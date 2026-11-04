# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for DML RETURNING ... INTO (#120): the return-bind detection,
# the out-bind return-data decode, and the per-Var assignment.
#
# The wire bytes mirror what a live server sends (TTI_RXD carrying, per return
# bind, a ub4 row count then each row's length-prefixed value + an sb4
# truncation length), verified against 10g/11g/21c/23ai.

import unittest

from seerdb.client.connection import OracleConnect
from seerdb.client.cursor import _assign_return_binds
from seerdb.common.datatypes import Var
from seerdb.common.exceptions import DatabaseError, InterfaceError
from seerdb.common.sqltext import returning_bind_positions
from seerdb.common.tns import (
    FLUSH_OUT_BINDS,
    MAX_FLUSH_OUT_BINDS,
    decode_packet,
    decode_token_rxd,
    encode_dictionary_exec,
    set_decode_return_binds,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    TNS_DATA,
    TTI_FOB,
    TTI_STA,
    VERSION_11_2_0_2,
)


class TestReturningDetection(unittest.TestCase):
    def test_insert_returning_into(self):
        sql = 'INSERT INTO t VALUES (:1, :2) RETURNING id INTO :3'
        self.assertEqual(returning_bind_positions(sql, 3), frozenset({2}))

    def test_multiple_return_binds(self):
        sql = 'UPDATE t SET n=:1 WHERE id=:2 RETURNING id, n INTO :3, :4'
        self.assertEqual(returning_bind_positions(sql, 4), frozenset({2, 3}))

    def test_all_return_no_input(self):
        sql = "INSERT INTO t VALUES (1, 'x') RETURNING name INTO :1"
        self.assertEqual(returning_bind_positions(sql, 1), frozenset({0}))

    def test_not_returning(self):
        self.assertEqual(
            returning_bind_positions('INSERT INTO t VALUES (:1)', 1), frozenset()
        )
        # the INSERT's own INTO must not be mistaken for a RETURNING INTO
        self.assertEqual(
            returning_bind_positions('INSERT INTO t (a) VALUES (:1)', 1), frozenset()
        )

    def test_returning_in_string_literal_ignored(self):
        sql = "UPDATE t SET note = 'returning into x' WHERE id = :1"
        self.assertEqual(returning_bind_positions(sql, 1), frozenset())

    def test_returning_inside_a_plsql_block_is_not_a_wire_returning(self):
        # A RETURNING INTO inside a PL/SQL block is the block's own business:
        # the INTO target is an ordinary PL/SQL OUT bind and the block executes
        # like any other. Treated as a wire DML RETURNING, the client writes NO
        # value for that bind, so the server waits for bind bytes that never
        # arrive and neither side speaks again -- a HANG, not an error, ended
        # only by the client's 15s read timeout (#826).
        block = """
            declare
                t_id number;
            begin
                select nvl(count(*), 0) + 1 into t_id from t;
                insert into t (id) values (t_id)
                    returning id into :out_bind;
            end;
        """
        self.assertEqual(returning_bind_positions(block, 1), frozenset())

    def test_begin_block_with_returning_is_not_a_wire_returning(self):
        # The BEGIN form too, and with a leading comment -- is_plsql() strips
        # comments, so the guard must not be fooled into seeing plain DML.
        block = '-- go\nBEGIN insert into t (a) values (:1) returning id into :2; END;'
        self.assertEqual(returning_bind_positions(block, 2), frozenset())

    def test_plain_dml_returning_still_detected_when_wrapped_by_us(self):
        # The pre-10g path wraps a DML RETURNING in a block itself (#801) and
        # relies on the ORIGINAL statement still classifying as RETURNING -- the
        # positions are computed before the wrap. Guard that it does.
        from seerdb.common.sqltext import wrap_returning_in_block

        sql = 'INSERT INTO t VALUES (:1) RETURNING id INTO :2'
        self.assertEqual(returning_bind_positions(sql, 2), frozenset({1}))
        wrapped, _name = wrap_returning_in_block(sql)
        # ...and that the wrapped form is a block, so it takes the new path.
        self.assertEqual(returning_bind_positions(wrapped, 2), frozenset())


# A TTI_RXD (0x07) carrying return data for two binds: NUMBER 42 and VARCHAR
# 'hi', one row each, then a TTI_STA to end the response.
_RXD_TWO = (
    bytes([7])
    + bytes.fromhex('0101')
    + bytes.fromhex('02')
    + bytes.fromhex('c12b')
    + bytes.fromhex('00')
    + bytes.fromhex('0101')
    + bytes.fromhex('02')
    + b'hi'
    + bytes.fromhex('00')
    + bytes([TTI_STA])
)

# One NUMBER bind, two rows (multi-row DML RETURNING): 42 then 43.
# The same one-bind, one-row shape as _RXD_TWO's second bind, but with the
# trailing sb4 carrying 23 instead of 0: the server saying the value it just
# sent was cut down from 23 bytes to fit the client's variable (#1021).
_RXD_TRUNCATED = (
    bytes([7])
    + bytes.fromhex('0101')  # num_rows = 1
    + bytes.fromhex('02')
    + b'A '
    + bytes.fromhex('0117')  # sb4 actual length = 23
    + bytes([TTI_STA])
)


_RXD_MULTI = (
    bytes([7])
    + bytes.fromhex('0102')  # num_rows = 2
    + bytes.fromhex('02')
    + bytes.fromhex('c12b')
    + bytes.fromhex('00')
    + bytes.fromhex('02')
    + bytes.fromhex('c12c')
    + bytes.fromhex('00')
    + bytes([TTI_STA])
)


def _object_returning_rxd() -> bytes:
    """A RETURNING reply carrying one OBJECT value, built with the encoder.

    Hand-written hex would only prove the test matches itself; these are the
    bytes the Mirror's own object-column encoder produces, which is the framing
    a real server uses for a returned ADT (§21.2)."""
    from seerdb.common.dbobject import DbObject, DbObjectType
    from seerdb.common.tns import encode_object_column_value, encode_sb4
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR, TTI_RXD

    typ = DbObjectType(
        'PYO',
        'UDT_OBJECT',
        b'\x01' * 16,
        1,
        [{'name': 'STRINGVALUE', 'data_type': TNS_TYPE_VARCHAR}],
    )
    obj = DbObject('UDT_OBJECT', [('STRINGVALUE', 'returned')], dbtype=typ)
    return (
        bytes([TTI_RXD])
        + encode_sb4(1)  # one row for this bind
        + encode_object_column_value(obj)
        + encode_sb4(0)  # sb4 truncation length
        + bytes([TTI_STA])
    )


def _lob_returning_rxd(values: list[bytes | None]) -> bytes:
    """A RETURNING reply carrying CLOB values, built with the LOB COLUMN encoder.

    Deliberately not the Mirror's return-bind encoder: that one still writes a
    DALC for a LOB (the server half of #985). The column encoder is the framing
    a real server uses for a returned LOB -- verified on a live 23ai, where
    reading it as a DALC is exactly what desynced the reply."""
    from seerdb.common.tns import encode_lob_locator_thin, encode_sb4
    from seerdb.common.tns_consts import TTI_RXD

    out = bytes([TTI_RXD]) + encode_sb4(len(values))
    for index, value in enumerate(values):
        if value is None:
            out += b'\x00'  # a NULL LOB is the single byte, not a block
        else:
            out += encode_lob_locator_thin(
                len(value),
                with_metadata=True,
                locator=bytes([0x00, 0x26]) + bytes(36) + bytes([index]),
            )
        # The actual-length field: -1 for a NULL, 0 for a value that fitted.
        # A real 23ai sends -1 here, and writing 0 hid a bug the live matrix
        # caught instead -- a NULL LOB return was read as a truncation (#1021).
        # -1 is sign-magnitude on the wire (§12.1): the high bit of the
        # length byte is the sign, so 0x81 0x01 rather than encode_sb4.
        out += bytes([0x81, 0x01]) if value is None else encode_sb4(0)
    return out + bytes([TTI_STA])


class TestReturningDecode(unittest.TestCase):
    def tearDown(self):
        set_decode_return_binds(None)

    def _decode(self, data, positions):
        set_decode_return_binds(positions)
        (Done, Acc) = decode_token_rxd(data, (None, None, []))
        self.assertTrue(Done)
        return Acc[2][0]  # the return record

    def test_object_return_bind_reads_the_object_frame(self):
        # An OBJECT / collection return bind carries the object frame a column
        # uses, not a DALC. Read as a DALC the constructed 36-byte toid was
        # taken for a length, the reply desynced two bytes in, and the decoder
        # reported the toid's own `00 22 02 08` prefix as "no decoder for
        # response token 34" -- against a REAL 23ai, with no Mirror involved
        # (#826).
        from seerdb.common.dbobject import ObjectImage
        from seerdb.common.tns_consts import TNS_TYPE_ADT

        set_decode_return_binds([0], {0: TNS_TYPE_ADT})
        (Done, Acc) = decode_token_rxd(_object_returning_rxd(), (None, None, []))
        self.assertTrue(Done)
        rec = Acc[2][0]
        (value,) = rec['return_values'][0]
        self.assertIsInstance(value, ObjectImage)
        self.assertIn(b'returned', value.image)

    def test_lob_return_bind_reads_the_lob_block(self):
        # A CLOB / BLOB return bind carries the LOB block a fetched column uses
        # -- a ub4 block length, the locator's ub8 size and ub4 chunk size, then
        # the locator -- not a DALC. Read as a DALC the block length was taken
        # for the whole value and the rest left in the stream, where its next
        # byte decoded as a response token; the number came from the data, which
        # is what made it read like a decoder gap. Against a REAL 23ai, no
        # Mirror (#985).
        from seerdb.common.lob import LOB
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        set_decode_return_binds([0], {0: TNS_TYPE_CLOB})
        (Done, Acc) = decode_token_rxd(
            _lob_returning_rxd([b'first', b'second']), (None, None, [])
        )
        self.assertTrue(Done)
        (first, second) = Acc[2][0]['return_values'][0]
        # Two values, so the SECOND one is the half a desync loses: a reader
        # that mis-measured the first never reaches it intact.
        self.assertIsInstance(first, LOB)
        self.assertIsInstance(second, LOB)
        self.assertNotEqual(first.raw, second.raw)

    def test_a_null_lob_return_bind_is_a_single_byte(self):
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        set_decode_return_binds([0], {0: TNS_TYPE_CLOB})
        (Done, Acc) = decode_token_rxd(_lob_returning_rxd([None]), (None, None, []))
        self.assertTrue(Done)
        self.assertEqual(Acc[2][0]['return_values'][0], [None])

    def test_two_binds_single_row(self):
        rec = self._decode(_RXD_TWO, [0, 1])
        self.assertEqual(rec['return_positions'], [0, 1])
        self.assertEqual(rec['return_values'][0], [b'\xc1\x2b'])
        self.assertEqual(rec['return_values'][1], [b'hi'])

    def test_multi_row(self):
        rec = self._decode(_RXD_MULTI, [0])
        self.assertEqual(rec['return_values'][0], [b'\xc1\x2b', b'\xc1\x2c'])

    def test_a_truncated_value_is_reported_not_silently_returned(self):
        # A RETURNING value too big for its variable comes back cut down, and
        # the trailing sb4 -- otherwise 0 -- carries the untruncated length.
        # Discarding it turned a wrong answer into a plausible one: `var(str, 2)`
        # returned 'A ' and said nothing (#1021). Measured on a live 23ai.
        rec = self._decode(_RXD_TRUNCATED, [0])
        self.assertEqual(rec['return_values'][0], [b'A '])
        self.assertEqual(rec['return_lengths'][0], [23])
        bind = [Var(str)]
        with self.assertRaises(DatabaseError) as ctx:
            _assign_return_binds(bind, (None, None, None, None, [rec]))
        self.assertIn('DPY-4002', str(ctx.exception))
        self.assertIn('23', str(ctx.exception))

    def test_a_value_that_fitted_reports_nothing(self):
        # The companion: every value here carries a 0 length, so the same code
        # path must stay silent. A rule of "non-zero means truncated" is only
        # safe if what fits really does report 0.
        rec = self._decode(_RXD_TWO, [1, 2])
        self.assertEqual(rec['return_lengths'], [[0], [0]])
        bind = ['input', Var(int), Var(str)]
        _assign_return_binds(bind, (None, None, None, None, [rec]))
        self.assertEqual(bind[2].getvalue(), ['hi'])

    def test_a_length_equal_to_what_arrived_is_not_a_truncation(self):
        # Defensive: a server that echoed the true length for a value that DID
        # fit must not be read as a truncation report.
        rec = self._decode(_RXD_TRUNCATED, [0])
        rec['return_lengths'] = [[len(rec['return_values'][0][0])]]
        bind = [Var(str)]
        _assign_return_binds(bind, (None, None, None, None, [rec]))
        self.assertEqual(bind[0].getvalue(), ['A '])

    def test_a_null_return_is_not_a_truncation(self):
        # A NULL returned value carries -1 in the actual-length field, on every
        # type -- measured on a live 23ai with a NUMBER, a VARCHAR2, a RAW and a
        # CLOB. Read as "the untruncated length", it turned every NULL RETURNING
        # into a DPY-4002 (#1021); the live matrix caught it, the offline
        # fixture did not, because the fixture wrote 0.
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        set_decode_return_binds([0], {0: TNS_TYPE_CLOB})
        (Done, Acc) = decode_token_rxd(_lob_returning_rxd([None]), (None, None, []))
        self.assertTrue(Done)
        rec = Acc[2][0]
        self.assertEqual(rec['return_lengths'][0], [-1])
        bind = [Var(str)]
        _assign_return_binds(bind, (None, None, None, None, [rec]))
        self.assertEqual(bind[0].getvalue(), [None])

    def test_assign_decodes_by_var_type(self):
        rec = self._decode(_RXD_TWO, [1, 2])  # binds at positions 1 and 2
        result = (None, None, None, None, [rec])
        bind = ['input', Var(int), Var(str)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[1].getvalue(), [42])
        self.assertEqual(bind[2].getvalue(), ['hi'])


class TestReturningResponseLengths(unittest.TestCase):
    """What the Mirror writes in the trailing actual-length field (#1023).

    It used to write 0 for everything, so it could never tell a client that a
    value did not fit -- the client got half a string and called it an answer.
    Round-tripped through the client's own decoder + assignment, which is what
    reports the truncation.
    """

    def _assign(self, values, types, bind, max_sizes=None):
        # The Mirror's reply, decoded by the client's own packet decoder and
        # assigned to the Vars -- both halves of the round trip, since the
        # report is only produced at assignment.
        from seerdb.common.tns import encode_returning_response

        reply = encode_returning_response(1, [values], types, max_sizes=max_sizes)
        set_decode_return_binds(list(range(len(types))), dict(enumerate(types)))
        try:
            result = decode_packet(reply, (0, [], [], bind))
        finally:
            set_decode_return_binds(None)
        record = result[4][0]
        _assign_return_binds(bind, result)
        return record

    def test_a_value_longer_than_the_clients_buffer_is_cut_and_reported(self):
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

        bind = [Var(str)]
        with self.assertRaises(DatabaseError) as ctx:
            self._assign(
                [('a value far longer than two',)],
                [TNS_TYPE_VARCHAR],
                bind,
                max_sizes=[2],
            )
        self.assertIn('DPY-4002', str(ctx.exception))
        self.assertIn('27', str(ctx.exception))  # the untruncated length

    def test_a_value_that_fits_reports_zero(self):
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

        bind = [Var(str)]
        rec = self._assign([('hi',)], [TNS_TYPE_VARCHAR], bind, max_sizes=[100])
        self.assertEqual(rec['return_lengths'][0], [0])
        self.assertEqual(bind[0].getvalue(), ['hi'])

    def test_a_null_reports_minus_one(self):
        # What a real server sends, and it is not a length: read as one it turns
        # every NULL RETURNING into a truncation (#1021).
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

        bind = [Var(str)]
        rec = self._assign([(None,)], [TNS_TYPE_VARCHAR], bind, max_sizes=[100])
        self.assertEqual(rec['return_lengths'][0], [-1])
        self.assertEqual(bind[0].getvalue(), [None])

    def test_a_multibyte_value_is_cut_on_a_character_boundary(self):
        # A buffer that splits a multi-byte character would hand the client an
        # undecodable tail, so the cut lands on a boundary and the reported
        # length is still the whole value's.
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

        bind = [Var(str)]
        with self.assertRaises(DatabaseError):
            self._assign([('\u00e9' * 10,)], [TNS_TYPE_VARCHAR], bind, max_sizes=[5])
        self.assertEqual(bind[0].getvalue(), ['\u00e9\u00e9'])  # 4 of the 5 bytes

    def test_a_fixed_width_type_is_never_truncated(self):
        # A NUMBER's declared size is not a buffer the value can overflow, so
        # the size is ignored rather than cutting a number in half.
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER

        bind = [Var(int)]
        rec = self._assign([(42,)], [TNS_TYPE_NUMBER], bind, max_sizes=[1])
        self.assertEqual(rec['return_lengths'][0], [0])
        self.assertEqual(bind[0].getvalue(), [42])

    def test_without_sizes_nothing_is_truncated(self):
        # The sizes are optional: a caller that does not know them gets the
        # whole value and a 0, which is what every other encoder call does.
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

        bind = [Var(str)]
        rec = self._assign([('a long value',)], [TNS_TYPE_VARCHAR], bind)
        self.assertEqual(rec['return_lengths'][0], [0])
        self.assertEqual(bind[0].getvalue(), ['a long value'])


def _exec_bytes(bind, batch, return_binds):
    """The wire bytes of one array execute of a RETURNING statement."""
    return encode_dictionary_exec(
        {
            'seq': 3,
            'query': {
                'type': 'change',
                'auto': 0,
                'fetch': 0,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'insert into t (v) values (:1) returning id into :2',
                'bind': bind,
                'batch': batch,
                'def': [],
                'batcherrors': False,
                'arraydmlrowcounts': False,
                'return_binds': return_binds,
                'scrollable': False,
                'scroll': None,
            },
        }
    )


class TestArrayReturningEncode(unittest.TestCase):
    """An array execute must not send a value for a server-filled bind (#687).

    Every bind is described once in the type block, but a `RETURNING ... INTO`
    out-bind is filled by the server from the rows each iteration affected. Its
    value therefore belongs in no iteration's row data. Sending one shifted
    everything after it, and the server rejected the whole call as a malformed
    packet and dropped the connection.
    """

    def _cost_of_the_receiver(self, iterations):
        """How many more bytes the receiver adds over the same batch without it.

        The receiver is described once, so this is one descriptor's worth and
        must not depend on how many iterations there are. If it did, the
        receiver would be travelling in the row data.
        """
        receiver = Var(int)
        inputs = [[f'v{n}'] for n in range(iterations)]
        rows = [row + [receiver] for row in inputs]
        with_receiver = _exec_bytes(rows[0], rows[1:], frozenset({1}))
        without = _exec_bytes(inputs[0], inputs[1:], None)
        return len(with_receiver) - len(without)

    def test_return_bind_costs_the_same_at_any_batch_size(self):
        self.assertEqual(self._cost_of_the_receiver(2), self._cost_of_the_receiver(8))

    def test_return_bind_value_absent_from_every_iteration(self):
        receiver = Var(int)
        rows = [['a', receiver], ['bb', receiver], ['ccc', receiver]]
        encoded = _exec_bytes(rows[0], rows[1:], frozenset({1}))
        # Each iteration contributes exactly its own input value, and nothing
        # for the receiver.
        for value in (b'a', b'bb', b'ccc'):
            self.assertIn(value, encoded)
        self.assertEqual(encoded.count(b'ccc'), 1)

    def test_matches_the_same_batch_without_the_receiver(self):
        """The row data is byte-identical to a batch of the inputs alone.

        The two differ only in the type block, which describes the extra bind.
        Comparing the tail past the longest shared prefix isolates the row data,
        which is where the bug was.
        """
        receiver = Var(int)
        with_receiver = _exec_bytes(
            ['a', receiver], [['bb', receiver], ['ccc', receiver]], frozenset({1})
        )
        # A three-row batch of the inputs only, no RETURNING involved.
        inputs_only = _exec_bytes(['a'], [['bb'], ['ccc']], None)
        self.assertTrue(with_receiver.endswith(inputs_only[-len(b'ccc') - 8 :]))

    def test_without_return_binds_every_bind_still_travels(self):
        """A plain array execute is unchanged."""
        encoded = _exec_bytes(['a', 'x'], [['bb', 'y']], None)
        for value in (b'a', b'x', b'bb', b'y'):
            self.assertIn(value, encoded)


class TestArrayReturningAssign(unittest.TestCase):
    """Each iteration returns its own rows, and all of them must be kept."""

    def tearDown(self):
        set_decode_return_binds(None)

    def _record(self, values):
        return {'return_positions': [0], 'return_values': [values]}

    def test_per_iteration_values(self):
        result = (
            None,
            None,
            None,
            None,
            [self._record([b'\xc1\x02']), self._record([b'\xc1\x03'])],
        )
        bind = [Var(int)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[0].getvalue(0), [1])
        self.assertEqual(bind[0].getvalue(1), [2])
        # No argument keeps reading the first iteration, as before.
        self.assertEqual(bind[0].getvalue(), [1])

    def test_iteration_returning_several_rows(self):
        """An UPDATE can affect many rows in a single iteration."""
        result = (
            None,
            None,
            None,
            None,
            [self._record([b'\xc1\x02', b'\xc1\x03']), self._record([b'\xc1\x04'])],
        )
        bind = [Var(int)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[0].getvalue(0), [1, 2])
        self.assertEqual(bind[0].getvalue(1), [3])

    def test_single_iteration_keeps_the_flat_shape(self):
        """One execute has one iteration, so `pos` is ignored."""
        result = (None, None, None, None, [self._record([b'\xc1\x02'])])
        bind = [Var(int)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[0].getvalue(), [1])
        self.assertEqual(bind[0].getvalue(4), [1])


class TestFlushOutBindsRequest(unittest.TestCase):
    """The server asks before it answers, when a RETURNING statement fails (#697).

    Its whole reply is one byte -- the TTI_FOB token, nothing else -- and it then
    waits. The real error only arrives once the client has echoed the token back.
    Reading that packet as if it were a result abandoned the response mid-stream
    and left the connection unusable: the next statement on it came back
    ORA-03137, a protocol violation, because the server was still waiting.
    """

    def test_a_bare_fob_packet_decodes_to_the_marker(self):
        (Done, Marker) = decode_packet(bytes([TTI_FOB]), (None, None, []))
        self.assertIs(Done, False)
        self.assertEqual((Done, Marker), FLUSH_OUT_BINDS)

    def test_the_marker_is_not_mistaken_for_a_result(self):
        # It has to be distinguishable from anything a caller would keep, or the
        # request gets handed on as an answer -- which is how it surfaced, as
        # "unexpected wire response: (False, 'fob')".
        (Done, _Acc) = decode_packet(bytes([TTI_STA]), (None, None, []))
        self.assertNotEqual((Done, _Acc), FLUSH_OUT_BINDS)


class TestFlushOutBindsAcknowledged(unittest.TestCase):
    """The connection answers the request and reads on, rather than giving up."""

    class _Wire:
        """A connection stripped to what _handle_response touches."""

        field_version = FIELD_VERSION_11_2

        def __init__(self, packets):
            self._packets = list(packets)
            self.sent = []
            self._session_keywords = {}
            self._call_status = []

        def _absorb_session_keywords(self):
            pass

        def _next_data_packet(self, _a, _b):
            return (TNS_DATA, self._packets.pop(0)) if self._packets else False

        def send(self, _type, data):
            self.sent.append(data)

        def _server_field_version(self):
            return self.field_version

    def _read(self, packets):
        wire = self._Wire(packets)
        result = OracleConnect._handle_response(wire)
        return wire, result

    def test_the_token_is_echoed_back_and_the_answer_read(self):
        wire, result = self._read([bytes([TTI_FOB]), bytes([TTI_STA])])
        # Exactly the one byte the server sent, straight back.
        self.assertEqual(wire.sent, [bytes([TTI_FOB])])
        # And the response behind it is what the caller receives.
        self.assertIsNot(result, FLUSH_OUT_BINDS)

    def test_an_ordinary_response_sends_nothing(self):
        wire, _ = self._read([bytes([TTI_STA])])
        self.assertEqual(wire.sent, [])

    def test_a_server_that_never_stops_asking_ends_the_call(self):
        # A cap, not a fix for anything real: one request is what a server sends.
        # Without it a broken server would spin here forever.
        with self.assertRaises(InterfaceError):
            self._read([bytes([TTI_FOB])] * (MAX_FLUSH_OUT_BINDS + 1))


if __name__ == '__main__':
    unittest.main()


class TestReturningIsRefusedBelow10g(unittest.TestCase):
    """RETURNING ... INTO needs the 10g+ request form (#716).

    9i refuses the clause for this client type and 8i drops the connection on
    a failure, so the driver says so before any I/O. A connection whose version
    is not yet known is not refused.
    """

    def _check(self, version):
        import types

        from seerdb.client.cursor import _check_returning_support

        conn = (
            types.SimpleNamespace(field_version=version)
            if version
            else types.SimpleNamespace()
        )
        _check_returning_support(conn, frozenset({1}))

    def test_9i_is_refused(self):
        from seerdb.common.exceptions import NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        with self.assertRaises(NotSupportedError):
            self._check(FIELD_VERSION_9_2)

    def test_10g_and_later_are_not(self):
        from seerdb.common.tns_consts import FIELD_VERSION_10_2, FIELD_VERSION_11_2

        self._check(FIELD_VERSION_10_2)
        self._check(FIELD_VERSION_11_2)

    def test_an_unknown_version_is_not_refused(self):
        self._check(None)

    def test_a_statement_without_the_clause_is_never_refused(self):
        import types

        from seerdb.client.cursor import _check_returning_support
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        _check_returning_support(
            types.SimpleNamespace(field_version=FIELD_VERSION_9_2), frozenset()
        )


class TestPreTenReturningWrap(unittest.TestCase):
    """Pre-10g `DML ... RETURNING ... INTO` is served by rewriting it into an
    anonymous PL/SQL block, where the INTO targets are ordinary OUT binds (#801).
    """

    def test_wrap_shape(self):
        from seerdb.common.sqltext import wrap_returning_in_block

        SQL, Name = wrap_returning_in_block(
            'INSERT INTO t (id) VALUES (:1) RETURNING id INTO :2'
        )
        self.assertEqual(Name, 'seerdb_rowcount')
        self.assertEqual(
            SQL,
            'BEGIN INSERT INTO t (id) VALUES (:1) RETURNING id INTO :2; '
            ':seerdb_rowcount := SQL%ROWCOUNT; END;',
        )

    def test_trailing_semicolon_would_close_the_block_early(self):
        from seerdb.common.sqltext import wrap_returning_in_block

        SQL, _ = wrap_returning_in_block('DELETE FROM t RETURNING id INTO :1 ;  ')
        self.assertEqual(
            SQL,
            'BEGIN DELETE FROM t RETURNING id INTO :1; '
            ':seerdb_rowcount := SQL%ROWCOUNT; END;',
        )

    def test_rowcount_placeholder_avoids_colliding_with_a_user_bind(self):
        from seerdb.common.sqltext import wrap_returning_in_block

        _, Name = wrap_returning_in_block(
            'UPDATE t SET a = :seerdb_rowcount RETURNING id INTO :o'
        )
        self.assertEqual(Name, 'seerdb_rowcount_')

    def test_rowcount_is_lifted_and_the_record_becomes_a_return_record(self):
        from seerdb.client._conn_logic import returning_block_result

        # Two user binds, so the appended rowcount bind sits at position 2.
        Record = {
            'out_positions': [1, 2],
            'out_values': [bytes.fromhex('c107'), bytes.fromhex('c102')],
        }
        Result = (0, 0, 0, (None, None), [Record], None, None, [], None)
        Out = returning_block_result(Result, 2)
        self.assertEqual(Out[3][0], 1)  # SQL%ROWCOUNT, not the block's own count
        # Re-labelled as the record the native RETURNING path decodes, so the
        # value reaches the caller as a list exactly as it does on 10g+.
        self.assertEqual(Out[4][0]['return_positions'], [1])
        self.assertEqual(Out[4][0]['return_values'], [[bytes.fromhex('c107')]])
        self.assertNotIn('out_positions', Out[4][0])

    def test_zero_rows_is_an_empty_list_not_a_missing_value(self):
        from seerdb.client._conn_logic import returning_block_result

        # A statement that matched nothing: the RETURNING bind is unassigned.
        Record = {'out_positions': [1, 2], 'out_values': [None, bytes.fromhex('80')]}
        Result = (0, 0, 0, (None, None), [Record], None, None, [], None)
        Out = returning_block_result(Result, 2)
        self.assertEqual(Out[3][0], 0)
        # 10g+ reports [] for a RETURNING that matched no rows; match it.
        self.assertEqual(Out[4][0]['return_values'], [[]])

    def test_a_null_value_is_one_row_not_no_rows(self):
        from seerdb.client._conn_logic import returning_block_result

        # The row WAS affected and its returned value is NULL. Both arrive as an
        # empty OUT value, and collapsing them reported a NULL RETURNING as "no
        # rows returned" -- [] where 10g+ gives [None] (#1022). The appended
        # SQL%ROWCOUNT tells them apart: 1 here, 0 in the test above.
        Record = {'out_positions': [1, 2], 'out_values': [None, bytes.fromhex('c102')]}
        Result = (0, 0, 0, (None, None), [Record], None, None, [], None)
        Out = returning_block_result(Result, 2)
        self.assertEqual(Out[3][0], 1)
        self.assertEqual(Out[4][0]['return_values'], [[None]])

    def test_both_pre_10g_tiers_are_served(self):
        import types

        from seerdb.client.cursor import _check_returning_support
        from seerdb.client.dialect import Fv2Dialect, O8iDialect
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        Binds = frozenset({1})
        for Dialect in (Fv2Dialect(), O8iDialect(lambda: 0)):
            Conn = types.SimpleNamespace(
                field_version=FIELD_VERSION_9_2, _dialect=Dialect
            )
            _check_returning_support(Conn, Binds)  # served by the block rewrite

    def test_a_dialect_without_blocks_is_refused(self):
        import types

        from seerdb.client.cursor import _check_returning_support
        from seerdb.common.exceptions import NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        class NoBlocks:
            def capabilities(self):
                return frozenset({'dml'})

        Conn = types.SimpleNamespace(
            field_version=FIELD_VERSION_9_2, _dialect=NoBlocks()
        )
        with self.assertRaises(NotSupportedError):
            _check_returning_support(Conn, frozenset({1}))

    def test_a_quoted_bind_name_is_refused_below_10g(self):
        import types

        from seerdb.client.cursor import _check_returning_support
        from seerdb.client.dialect import Fv2Dialect
        from seerdb.common.exceptions import NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        Conn = types.SimpleNamespace(
            field_version=FIELD_VERSION_9_2, _dialect=Fv2Dialect()
        )
        # Plain names go through the rewrite.
        _check_returning_support(
            Conn, frozenset({1}), 'INSERT INTO t (a) VALUES (:a) RETURNING id INTO :o'
        )
        # A quoted one cannot: the server rejects it inside the block the rewrite
        # needs, so say that rather than surfacing a bare ORA-01006.
        with self.assertRaises(NotSupportedError):
            _check_returning_support(
                Conn,
                frozenset({1}),
                'INSERT INTO t (a) VALUES (:"desc") RETURNING id INTO :"out"',
            )

    def test_a_pre10_batch_runs_only_as_plain_dml_on_9i(self):
        # 9i runs a plain DML batch as array DML (#2245), batch errors included
        # (#2247). What it cannot run -- and any batch on 8i -- is refused, never
        # sent as its first row (#168).
        from seerdb.client._conn_logic import refuse_pre10_batch
        from seerdb.client.dialect import Fv2Dialect, O8iDialect
        from seerdb.common.exceptions import NotSupportedError

        refuse_pre10_batch(Fv2Dialect(), 'INSERT', None, False)
        refuse_pre10_batch(Fv2Dialect(), 'INSERT', None, True)
        for Dialect, Head, Returning, Errors, Says in (
            (O8iDialect(lambda: 0), 'INSERT', None, False, 'Oracle 8i'),
            (O8iDialect(lambda: 0), 'INSERT', None, True, 'Oracle 8i'),
            (Fv2Dialect(), 'INSERT', frozenset({1}), False, 'RETURNING'),
            (Fv2Dialect(), 'BEGIN', None, False, 'PL/SQL block'),
            (Fv2Dialect(), 'SELECT', None, False, 'query'),
        ):
            with self.assertRaisesRegex(NotSupportedError, Says):
                refuse_pre10_batch(Dialect, Head, Returning, Errors)

    def test_a_pre10_batch_with_errors_commits_its_good_rows(self):
        # Under autocommit a pre-10g DML's error means nothing to commit, but in
        # batcherrors mode ORA-24381 says the good rows went in (#2247).
        from seerdb.client._conn_logic import pre10_dml_applied

        Result = (0, 0, 0, (3, None), [], None, None, [], None)
        self.assertTrue(pre10_dml_applied(Result, False))
        Partial = (0, 24381, 0, (4, None), [], 'ORA-24381', None, [{}], None)
        self.assertTrue(pre10_dml_applied(Partial, True))
        self.assertFalse(pre10_dml_applied(Partial, False))
        Failed = (0, 1, 0, (2, None), [], 'ORA-00001', None, [], None)
        self.assertFalse(pre10_dml_applied(Failed, True))

    def test_bulk_collect_is_refused_below_10g(self):
        import types

        from seerdb.client.cursor import _check_returning_support
        from seerdb.client.dialect import Fv2Dialect
        from seerdb.common.exceptions import NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        Conn = types.SimpleNamespace(
            field_version=FIELD_VERSION_9_2, _dialect=Fv2Dialect()
        )
        with self.assertRaises(NotSupportedError):
            _check_returning_support(
                Conn,
                frozenset({0}),
                'UPDATE t SET a = 1 RETURNING id BULK COLLECT INTO :o',
            )

    def test_too_many_rows_is_explained_not_left_as_ora_01422(self):
        from seerdb.client._conn_logic import returning_block_error
        from seerdb.common.exceptions import DatabaseError, NotSupportedError

        Translated = returning_block_error(DatabaseError('ORA-01422', 1422))
        self.assertIsInstance(Translated, NotSupportedError)
        self.assertIn('more than one row', str(Translated))
        # Anything else is handed back untouched for the caller to raise.
        Other = DatabaseError('ORA-00001', 1)
        self.assertIs(returning_block_error(Other), Other)

    def test_the_array_dml_refusal_names_the_real_tier(self):
        from seerdb.client._conn_logic import _pre10_tier_name_for
        from seerdb.client.dialect import Fv2Dialect, O8iDialect

        # Both tiers are field version 2, so the version cannot tell them apart.
        self.assertEqual(_pre10_tier_name_for(Fv2Dialect()), '9i')
        self.assertEqual(_pre10_tier_name_for(O8iDialect(lambda: 0)), '8i')


class TestJsonReturnBind(unittest.TestCase):
    """A JSON return bind carries its OSON image, not a DALC (#826).

    A `RETURNING JsonCol INTO :b` reply frames the returned value the way such a
    column is framed in a row: the metadata header, then the image, then a
    locator to be discarded. Read as a plain DALC the locator stayed in the
    stream and became the next field, so the response desynced on the token
    after it (`no decoder for response token 2` against a live 23ai).
    """

    def tearDown(self):
        set_decode_return_binds(None)

    def test_decode_reads_the_image_and_drops_the_locator(self):
        from seerdb.common.oson import decode_oson, encode_oson
        from seerdb.common.tns import encode_prefetched_lob_value_thin, encode_sb4
        from seerdb.common.tns_consts import TNS_TYPE_JSON, TTI_RXD

        doc = {'a': 1, 'b': 'x'}
        image = encode_oson(doc, allow_wide=True)
        payload = (
            bytes([TTI_RXD])
            + encode_sb4(1)  # one affected row
            + encode_prefetched_lob_value_thin(image)
            + encode_sb4(0)  # sb4 truncation length
            + bytes([TTI_STA])  # the token that used to be misread
        )
        set_decode_return_binds([0], {0: TNS_TYPE_JSON})
        (Done, Acc) = decode_token_rxd(payload, (None, None, []))
        self.assertTrue(Done)
        (value,) = Acc[2][0]['return_values'][0]
        self.assertEqual(decode_oson(bytes(value)), doc)

    def test_a_position_with_no_type_still_reads_as_a_dalc(self):
        # Every other bind keeps the plain framing, so arming the types must not
        # change how an untyped position is read.
        rec = TestReturningDecode()._decode(_RXD_TWO, [0, 1])
        self.assertEqual(rec['return_values'][1], [b'hi'])

    def test_encode_frames_a_json_value_as_its_image(self):
        from seerdb.common.oson import encode_oson
        from seerdb.common.tns import (
            encode_prefetched_lob_value_thin,
            encode_returning_response,
        )
        from seerdb.common.tns_consts import TNS_TYPE_JSON

        doc = {'hello': 'world'}
        reply = encode_returning_response(1, [[(doc,)]], [TNS_TYPE_JSON])
        expected = encode_prefetched_lob_value_thin(encode_oson(doc, allow_wide=True))
        self.assertIn(expected, reply)

    def test_encode_keeps_a_null_json_value_bare(self):
        from seerdb.common.tns import encode_returning_response
        from seerdb.common.tns_consts import TNS_TYPE_JSON

        reply = encode_returning_response(1, [[(None,)]], [TNS_TYPE_JSON])
        self.assertIn(b'\x00', reply)
