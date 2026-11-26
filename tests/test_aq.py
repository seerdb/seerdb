# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for Advanced Queuing (#128): the queue/message classes, the
# enqueue encoder, the dequeue decoder (against a captured response), and the
# error extraction. RAW + object enqueue/dequeue (single + array) round-trips
# are covered live on 21c/23ai.

import unittest

from seerdb.client.aq import DeqOptions, EnqOptions, MessageProperties, Queue
from seerdb.client.connection import (
    _aq_error_info,
    _decode_aq_array,
    _decode_aq_deq,
    _decode_aq_enq,
)
from seerdb.common.tns import (
    _AQ_ARRAY_CALL_FROM_THIN,
    _AQ_ARRAY_ENQ_HEAD_FROM_THIN,
    _AQ_ARRAY_ENQ_ITEM_FROM_THIN,
    _AQ_DEQ_FROM_THIN,
    _AQ_ENQ_FROM_THIN,
    _DECODE_FIELD_VERSION,
    _DECODE_SERVER_FIELD_VERSION,
    encode_aq_array,
    encode_aq_deq,
    encode_aq_enq,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_20_1,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1_EXT_1,
    TNS_AQ_ARRAY_DEQ,
    TNS_AQ_ARRAY_ENQ,
    TNS_AQ_DEQ_REMOVE,
    TNS_AQ_MSG_BUFFERED,
    TNS_FUNC_AQ_ENQ,
    TNS_KPD_AQ_BUFMSG,
    TTI_FUN,
    TTI_RPA,
    TTI_STA,
)


class _FakeConn:
    field_version = 16

    def _server_below_10_2(self):
        return False


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

    def test_a_json_payload_past_the_compact_form(self):
        # A string past 255 bytes, or more than 255 entries, takes OSON's wide
        # form: the enqueue has no text-cast fallback to go to (#2780).
        from seerdb.common.oson import decode_oson
        from seerdb.common.tns import _AQ_JSON_DESCRIPTOR, _THIN

        q = Queue(_FakeConn(), 'JQ', payload_type=None, is_json=True)
        for value in ({'k': 'x' * 300}, {f'k{i}': i for i in range(300)}):
            out = encode_aq_enq(3, 16, q, MessageProperties(payload=value))
            at = out.index(_AQ_JSON_DESCRIPTOR) + len(_AQ_JSON_DESCRIPTOR)
            length = int.from_bytes(out[at : at + 2], 'big')
            (image, rest) = _THIN.read_value(out[at + 2 + 22 :])
            self.assertEqual((len(image), rest), (length, b''))
            self.assertEqual(decode_oson(image), value)


class TestNinePointTwoOverThinOall8(unittest.TestCase):
    # A thin OALL8 session to 9.2 (#2805) enqueues and dequeues as JDBC thin
    # 11.2 (ojdbc6) does to 9.2.0.4: the properties without the enqueue
    # transaction id and the four fields after the extensions, and the enqueue
    # without the sender fields. The session runs at 10.2; the server is 9.2.

    @staticmethod
    def _capture(name):
        import os
        import sys

        sys.path.insert(0, os.path.dirname(__file__))
        from replay import load_capture

        return bytes(load_capture(name))

    def test_the_enqueue_is_jdbc_thin_11_2s(self):
        from seerdb.common.tns_consts import FIELD_VERSION_10_2

        theirs = self._capture('jdbc6_aq_enqueue_92.hexdump')
        q = Queue(_FakeConn(), 'PYO_AQ_J6')
        props = MessageProperties(payload=b'hello AQ')
        props.priority = 7
        props.expiration = 3600
        props.correlation = 'CORR1'
        ours = encode_aq_enq(theirs[2], FIELD_VERSION_10_2, q, props, True)
        # seerdb asks for the message id back, which JDBC does not: its
        # pointer and length after the payload's (`01 01 08`), where JDBC
        # writes two zeros.
        jdbc_slot = b'\x01\x01\x08\x00\x00'
        self.assertEqual(theirs.count(jdbc_slot), 1)
        self.assertEqual(ours, theirs.replace(jdbc_slot, b'\x01\x01\x08\x01\x01\x10'))

    def test_10_2_keeps_the_fields_9_2_drops(self):
        from seerdb.common.tns_consts import FIELD_VERSION_10_2

        q = Queue(_FakeConn(), 'PYO_AQ_J6')
        props = MessageProperties(payload=b'hello AQ')
        to_92 = encode_aq_enq(1, FIELD_VERSION_10_2, q, props, True)
        to_102 = encode_aq_enq(1, FIELD_VERSION_10_2, q, props)
        # One transaction id, four property fields and eight sender fields,
        # each a single zero byte here.
        self.assertEqual(len(to_102) - len(to_92), 13)

    def test_9_2s_dequeue_reply_reads_back(self):
        from seerdb.common.tns import decode_aq_deq_reply
        from seerdb.common.tns_consts import FIELD_VERSION_10_2

        reply = self._capture('jdbc6_aq_dequeue_reply_92.hexdump')
        msg = decode_aq_deq_reply(reply, FIELD_VERSION_10_2, False, True)
        self.assertEqual(
            (msg['priority'], msg['delay'], msg['expiration'], msg['correlation']),
            (7, 0, 3600, b'CORR1'),
        )
        self.assertEqual(msg['payload'], b'hello AQ')
        # 9.2's enqueue time is a longer value; its first 7 bytes are the
        # DATE (2026-11-26 14:36:50).
        self.assertEqual(msg['enq_time'][:7], bytes.fromhex('787e0b1a0f2533'))


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


class TestTheRequestsReadBack(unittest.TestCase):
    # Each request read back through its schema's decoder (#2773): the fields
    # the queue, the options and the properties gave, at the field versions
    # where the layout changes (11g's bare strings, 20.1's JSON flag, 21.1's
    # shard id).
    VERSIONS = (FIELD_VERSION_11_2, FIELD_VERSION_12_1, FIELD_VERSION_21_1)

    @staticmethod
    def _body(out: bytes, version: int) -> bytes:
        # Past the function header: its token number from 23ai.
        return out[4:] if version >= FIELD_VERSION_23_1_EXT_1 else out[3:]

    @staticmethod
    def _given(version: int) -> dict:
        return {
            'has_shard': version >= FIELD_VERSION_21_1,
            'has_json_flag': version >= FIELD_VERSION_20_1,
            'texts_bare': version < FIELD_VERSION_12_1,
            'texts_counted': version >= FIELD_VERSION_12_1,
        }

    def test_a_negative_priority(self):
        # Signed, as the expiration is: a negative priority raised (#2782).
        q = Queue(_FakeConn(), 'PYO_Q')
        out = encode_aq_enq(
            1, FIELD_VERSION_12_1, q, MessageProperties(payload=b'x', priority=-5)
        )
        given = self._given(FIELD_VERSION_12_1)
        (got, _) = _AQ_ENQ_FROM_THIN(self._body(out, FIELD_VERSION_12_1), given)
        self.assertEqual(got['priority'], -5)
        self.assertEqual(out[6:8], b'\x81\x05')  # after the queue name's ptr and length

    def test_an_enqueue(self):
        for version in self.VERSIONS:
            q = Queue(_FakeConn(), 'PYO_Q')
            q.enqoptions.delivery_mode = TNS_AQ_MSG_BUFFERED
            props = MessageProperties(
                payload=b'hello', correlation='corr', priority=3, recipients=['A']
            )
            out = encode_aq_enq(1, version, q, props)
            (got, rest) = _AQ_ENQ_FROM_THIN(
                self._body(out, version), self._given(version)
            )
            with self.subTest(version=version):
                self.assertEqual(rest, b'hello')
                self.assertEqual(got['queue_name'], b'PYO_Q')
                self.assertEqual((got['priority'], got['expiration']), (3, -1))
                self.assertEqual(got['correlation'], b'corr')
                self.assertEqual(got['recipients_length'], 3)
                self.assertEqual(got['raw_payload_length'], 5)
                self.assertEqual(got['enq_flags'], TNS_KPD_AQ_BUFMSG)
                self.assertEqual(got['payload_toid'], q.payload_toid)
                self.assertEqual(
                    [e['keyword'] for e in got['extensions']], [0x40, 0x41, 0x42, 0x45]
                )

    def test_a_dequeue(self):
        for version in self.VERSIONS:
            q = Queue(_FakeConn(), 'PYO_Q')
            o = q.deqoptions
            (o.consumer_name, o.condition, o.msgid) = (
                'SUB1',
                'tab.priority = 5',
                b'\x07',
            )
            out = encode_aq_deq(1, version, q)
            (got, rest) = _AQ_DEQ_FROM_THIN(
                self._body(out, version), self._given(version)
            )
            with self.subTest(version=version):
                self.assertEqual(rest, b'')
                self.assertEqual(got['consumer'], b'SUB1')
                self.assertEqual(got['condition'], b'tab.priority = 5')
                self.assertEqual(got['msgid'], b'\x07' + bytes(15))
                self.assertFalse(got['correlation_present'])
                self.assertEqual(
                    got.get('shard'), -1 if version >= FIELD_VERSION_21_1 else None
                )

    def test_an_array_dequeue(self):
        for version in self.VERSIONS:
            q = Queue(_FakeConn(), 'PYO_Q')
            q.deqoptions.condition = 'c'
            props = [MessageProperties() for _ in range(2)]
            out = encode_aq_array(1, version, q, TNS_AQ_ARRAY_DEQ, props, 2)
            given = {'has_shard': version >= FIELD_VERSION_21_1, 'is_enq': 0}
            (got, rest) = _AQ_ARRAY_CALL_FROM_THIN(self._body(out, version), given)
            with self.subTest(version=version):
                self.assertEqual(rest, b'')
                self.assertEqual(got['input_length'], 2)
                self.assertEqual(
                    [m['condition'] for m in got['messages']], [b'c', b'c']
                )
                self.assertEqual(got['messages'][0]['queue_name'], b'PYO_Q')

    def test_an_array_enqueue(self):
        for version in self.VERSIONS:
            q = Queue(_FakeConn(), 'PYO_Q')
            props = [
                MessageProperties(payload=b'p%d' % i, priority=i) for i in range(2)
            ]
            out = encode_aq_array(1, version, q, TNS_AQ_ARRAY_ENQ, props, 2)
            given = {'has_shard': version >= FIELD_VERSION_21_1, 'is_enq': 1}
            (call, rest) = _AQ_ARRAY_CALL_FROM_THIN(self._body(out, version), given)
            (head, rest) = _AQ_ARRAY_ENQ_HEAD_FROM_THIN(rest)
            rows = []
            for i in range(call['num_iters']):
                (row, rest) = _AQ_ARRAY_ENQ_ITEM_FROM_THIN(
                    rest, {'has_shard': given['has_shard'], 'has_raw_length': 1}
                )
                rows.append((row['priority'], bytes(rest[: row['raw_payload_length']])))
                rest = rest[row['raw_payload_length'] :]
            with self.subTest(version=version):
                self.assertEqual((call['num_iters'], call['messages']), (2, []))
                self.assertEqual(head['queue_name'], b'PYO_Q')
                self.assertEqual(rows, [(0, b'p0'), (1, b'p1')])
                self.assertEqual(rest, bytes([TTI_STA]))


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

    def _props(self, **extra) -> dict:
        values = {
            'priority': 2,
            'delay': 0,
            'expiration': -1,
            'correlation_length': 4,
            'correlation': b'corr',
            'num_attempts': 1,
            'exceptionq_length': 0,
            'state': 0,
            'has_enq_time': 0,
            'enq_txn_id_length': 0,
            'num_extensions': 1,
            'extensions_byte': 0x16,
            'extensions': [
                {'text_length': 0, 'binary_length': 1, 'binary': b'x', 'keyword': 0x40}
            ],
            'user_properties': 0,
            'csn': 0,
            'dsn': 0,
            'flags': 0,
            'has_shard': 1,
            'shard': 0,
            # 10.2's form: the transaction id and the four fields 9.2 lacks
            # (#2805).
            'has_txn_id': 1,
            'has_props_tail': 1,
        }
        values.update(extra)
        return values

    def _image(self, payload: bytes) -> bytes:
        from seerdb.common.tns import _AQ_PAYLOAD_IMAGE_THIN

        image = bytes(4) + payload
        return _AQ_PAYLOAD_IMAGE_THIN(
            {
                'toid_length': 0,
                'oid_length': 0,
                'snapshot_length': 0,
                'version': 1,
                'image_length': len(image),
                'flags': 0,
                'image': image,
            }
        )

    def test_decode_array_deq(self):
        # Two messages: one with its properties (and an extension) and a
        # payload, one with neither.
        from seerdb.common.tns import (
            _AQ_ARRAY_COUNT_THIN,
            _AQ_ARRAY_HEAD_THIN,
            _AQ_ARRAY_TAIL_THIN,
        )
        from seerdb.common.tns_consts import TNS_AQ_ARRAY_DEQ

        def tail(msgid: bytes) -> bytes:
            return _AQ_ARRAY_TAIL_THIN(
                {
                    'msgid_length': len(msgid),
                    'msgid': msgid,
                    'extensions_length': 0,
                    'ack': 0,
                }
            )

        first = self._props(has_props=1, props_byte=0, num_recipients=0, has_payload=1)
        second = {'has_props': 0, 'num_recipients': 0, 'has_payload': 0}
        reply = (
            _AQ_ARRAY_COUNT_THIN({'num_iters': 2})
            + _AQ_ARRAY_HEAD_THIN(first)
            + self._image(b'one')
            + tail(bytes(range(16)))
            + _AQ_ARRAY_HEAD_THIN(second)
            + tail(bytes(range(16, 32)))
        )
        (m1, m2) = _decode_aq_array(reply, _FakeQueue(), TNS_AQ_ARRAY_DEQ, [])
        self.assertEqual((m1.priority, m1.expiration, m1.correlation), (2, -1, 'corr'))
        self.assertEqual((m1.payload, m1.msgid), (b'one', bytes(range(16))))
        self.assertEqual(
            (m2.priority, m2.payload, m2.msgid), (0, None, bytes(range(16, 32)))
        )

    def test_decode_array_enq_msgids(self):
        # An array enqueue's ids come back concatenated, one per message sent.
        from seerdb.common.tns import (
            _AQ_ARRAY_COUNT_THIN,
            _AQ_ARRAY_HEAD_THIN,
            _AQ_ARRAY_TAIL_THIN,
        )
        from seerdb.common.tns_consts import TNS_AQ_ARRAY_ENQ

        ids = bytes(range(32))
        reply = (
            _AQ_ARRAY_COUNT_THIN({'num_iters': 1})
            + _AQ_ARRAY_HEAD_THIN(
                {'has_props': 0, 'num_recipients': 0, 'has_payload': 0}
            )
            + _AQ_ARRAY_TAIL_THIN(
                {
                    'msgid_length': len(ids),
                    'msgid': ids,
                    'extensions_length': 0,
                    'ack': 0,
                }
            )
        )
        sent = [MessageProperties(), MessageProperties()]
        self.assertIs(
            _decode_aq_array(reply, _FakeQueue(), TNS_AQ_ARRAY_ENQ, sent), sent
        )
        self.assertEqual([p.msgid for p in sent], [ids[:16], ids[16:]])

    def test_a_dequeue_with_no_message(self):
        self.assertIsNone(_decode_aq_deq(bytes([TTI_RPA, 0]), _FakeQueue()))

    def test_the_shard_id_is_21cs(self):
        # Behind the flags from 21c on; a 19c reply ends at them.
        from seerdb.common.tns import _AQ_MSG_PROPS_THIN, decode_aq_message_props
        from seerdb.common.tns_consts import (
            FIELD_VERSION_19_1_EXT_1,
            FIELD_VERSION_21_1,
        )

        with_shard = _AQ_MSG_PROPS_THIN(self._props(shard=7)) + b'\x09'
        (props, rest) = decode_aq_message_props(with_shard, FIELD_VERSION_21_1)
        self.assertEqual((props['shard'], rest), (7, b'\x09'))
        without = _AQ_MSG_PROPS_THIN(self._props(has_shard=0)) + b'\x09'
        (props, rest) = decode_aq_message_props(without, FIELD_VERSION_19_1_EXT_1)
        self.assertEqual(('shard' in props, rest), (False, b'\x09'))

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
