# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for Advanced Queuing (#128): the queue/message classes, the
# enqueue encoder, the dequeue decoder (against a captured response), and the
# error extraction. RAW + object enqueue/dequeue (single + array) round-trips
# are covered live on 21c/23ai.

import unittest

from seerdb.client.aq import DeqOptions, EnqOptions, MessageProperties, Queue
from seerdb.client.connection import _aq_error_info, _decode_aq_deq, _decode_aq_enq
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _DECODE_SERVER_FIELD_VERSION,
    encode_aq_deq,
    encode_aq_enq,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    TNS_AQ_DEQ_REMOVE,
    TNS_FUNC_AQ_ENQ,
    TTI_FUN,
    TTI_RPA,
)


class _FakeConn:
    field_version = 16


class _FakeQueue:
    payload_type = None
    is_json = False
    _connection = _FakeConn()


class TestClasses(unittest.TestCase):
    def test_payload_toid(self):
        q = Queue(_FakeConn(), 'Q')  # RAW
        self.assertEqual(q.payload_toid, bytes(15) + bytes([0x17]))
        qj = Queue(_FakeConn(), 'Q', is_json=True)
        self.assertEqual(qj.payload_toid, bytes(15) + bytes([0x47]))

    def test_defaults(self):
        m = MessageProperties(payload=b'x')
        self.assertEqual((m.priority, m.delay, m.expiration), (0, 0, -1))
        self.assertEqual(DeqOptions().mode, TNS_AQ_DEQ_REMOVE)
        self.assertEqual(EnqOptions().visibility, 2)


class TestEncode(unittest.TestCase):
    def test_enq_header(self):
        q = Queue(_FakeConn(), 'MY_Q')
        out = encode_aq_enq(3, 16, q, MessageProperties(payload=b'hello'))
        self.assertEqual(out[0], TTI_FUN)
        self.assertEqual(out[1], TNS_FUNC_AQ_ENQ)  # 121
        self.assertIn(b'MY_Q', out)
        self.assertIn(b'hello', out)  # RAW payload (raw bytes)

    def test_json_payload_descriptor(self):
        # JSON enqueue (#150): the OSON image is wrapped in the AQ JSON
        # descriptor (fixed prefix + ub2 length + 22 zeros + length-prefixed
        # image), NOT a plain length-prefix. The OSON magic (ff 4a 5a) follows.
        from seerdb.common.tns import _AQ_JSON_DESCRIPTOR

        q = Queue(_FakeConn(), 'JQ', payload_type=None, is_json=True)
        out = encode_aq_enq(3, 16, q, MessageProperties(payload={'id': 7}))
        self.assertIn(_AQ_JSON_DESCRIPTOR, out)
        self.assertIn(bytes.fromhex('ff4a5a'), out)  # OSON magic


class TestTheQueueNameBefore12c(unittest.TestCase):
    # 11g reads the queue name in the data section as it stands; a length
    # byte in front made it read the payload a byte off, ORA-00600 [kpoaqeq:
    # payload] (#2697). Measured against JDBC thin 11.2 on 11g XE.
    def _before_the_name(self, out: bytes) -> int:
        at = out.index(b'PYO_AQ_RAW' + bytes(15) + b'\x17')
        return out[at - 1]

    def test_11g_writes_the_name_without_a_length(self):
        q = Queue(_FakeConn(), 'PYO_AQ_RAW')
        enq = encode_aq_enq(1, FIELD_VERSION_11_2, q, MessageProperties(payload=b'hi'))
        self.assertEqual(self._before_the_name(enq), 0)
        self.assertEqual(
            self._before_the_name(encode_aq_deq(1, FIELD_VERSION_11_2, q)), 0
        )

    def test_12c_keeps_the_length(self):
        q = Queue(_FakeConn(), 'PYO_AQ_RAW')
        enq = encode_aq_enq(1, FIELD_VERSION_12_1, q, MessageProperties(payload=b'hi'))
        self.assertEqual(self._before_the_name(enq), 10)
        self.assertEqual(
            self._before_the_name(encode_aq_deq(1, FIELD_VERSION_12_1, q)), 10
        )


class TestTheDequeueStringsBefore12c(unittest.TestCase):
    # 11g takes each string of the dequeue's data section without a length
    # byte: consumer, correlation and condition, as JDBC thin 11.2 writes them
    # (#2700).
    def _dequeue(self, version: int) -> bytes:
        q = Queue(_FakeConn(), 'PYO_AQ_RAW')
        q.deqoptions.consumer_name = 'SUB1'
        q.deqoptions.correlation = 'corr-1'
        q.deqoptions.condition = 'tab.priority = 5'
        return encode_aq_deq(1, version, q)

    def test_11g_writes_them_as_they_stand(self):
        out = self._dequeue(FIELD_VERSION_11_2)
        self.assertIn(
            b'PYO_AQ_RAWSUB1corr-1' + bytes(15) + b'\x17tab.priority = 5', out
        )

    def test_12c_keeps_their_lengths(self):
        out = self._dequeue(FIELD_VERSION_12_1)
        self.assertIn(b'\x04SUB1\x06corr-1', out)
        self.assertTrue(out.endswith(b'\x10tab.priority = 5'))


class TestArrayJsonGate(unittest.TestCase):
    # array enqueue/dequeue of JSON is gated (server-side ORA-00600 on these
    # editions); single enqone/deqone JSON works (#150).
    def test_enqmany_gated_for_json(self):
        from seerdb.common.exceptions import NotSupportedError

        q = Queue(_FakeConn(), 'JQ', payload_type=None, is_json=True)
        with self.assertRaises(NotSupportedError):
            q.enqmany([MessageProperties(payload={'a': 1})])
        with self.assertRaises(NotSupportedError):
            q.deqmany(5)


class TestDecode(unittest.TestCase):
    # A live RAW tpc dequeue response: RPA, num_bytes flag, message properties
    # (expiration -1, empty correlation), the date, the four extension keyword
    # pairs, recipients 0, then the RAW payload image and the 16-byte msgid.
    _CTX = bytes(32) + b'g1b1' + bytes(168 - 36)
    _DEQ = bytes.fromhex(
        '08 01 01 00 00 81 01 00 00 00 00 01 01 07 78 7e 06 12 18 06 17 00 '
        '01 04 16 00 00 01 40 00 00 01 41 00 00 01 42 00 00 01 45 00 00 00 '
        '00 00 00 00 00 00 00 01 0c 02 04 01 0c 00 00 00 08 68 65 6c 6c 6f '
        '2d 61 71 54 90 35 f5 ce dc 7a f1 e0 63 c0 00 a8 c0 7e 8f 09 01 02 '
        '02 5a 6f'.replace(' ', '')
    )

    def test_decode_deq(self):
        m = _decode_aq_deq(self._DEQ, _FakeQueue())
        self.assertEqual(m.payload, b'hello-aq')
        self.assertEqual(m.expiration, -1)
        self.assertEqual(m.msgid.hex(), '549035f5cedc7af1e063c000a8c07e8f')

    def test_decode_enq_msgid(self):
        # RPA + 16-byte msgid
        pkt = bytes([TTI_RPA]) + bytes(range(16)) + b'\x00'
        self.assertEqual(_decode_aq_enq(pkt), bytes(range(16)))

    def test_error_extraction(self):
        # The code and the whole message, prefix included, as every other error
        # carries them (#2474), from 23ai's reply to an enqueue on a queue that
        # doesn't exist, captured at field version 24 (the server's is 27).
        oer = bytes.fromhex(
            '04010102224e00025dca000000000300000000000000000000000007000000000000'
            '025dca00010300364f52412d32343031303a2051554555452050594f2e50594f5f4e'
            '4f5f535543485f515545554520646f6573206e6f742065786973740a1d'
        )
        tokens = (_DECODE_FIELD_VERSION.set(24), _DECODE_SERVER_FIELD_VERSION.set(27))
        try:
            self.assertEqual(
                _aq_error_info(oer),
                (24010, 'ORA-24010: QUEUE PYO.PYO_NO_SUCH_QUEUE does not exist'),
            )
        finally:
            _DECODE_FIELD_VERSION.reset(tokens[0])
            _DECODE_SERVER_FIELD_VERSION.reset(tokens[1])


if __name__ == '__main__':
    unittest.main()
