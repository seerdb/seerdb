# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import asyncio
import socket
import threading
import time
import unittest
from unittest import mock

from seerdb.client.connection import (
    _FV2_MAX_RAW_BIND,
    _FV2_MAX_VARCHAR_BIND,
    _REDIRECT_CONNECT_ATTEMPTS,
    OracleConnect,
    _check_fv2_bind_sizes,
    _reject_cqn,
    _reject_sharding,
    _split_proxy_user,
)
from seerdb.common.exceptions import DatabaseError, NotSupportedError, OperationalError


class TestCqnRejected(unittest.TestCase):
    # A sync connection subscribes client-initiated only, as python-oracledb's
    # thin mode does (#2460); an asyncio connection has no subscriptions, as
    # python-oracledb's has none. Both refuse before anything is sent.
    def test_helper_raises(self):
        with self.assertRaises(NotSupportedError):
            _reject_cqn()

    def test_a_server_initiated_subscription_is_refused(self):
        from seerdb.common.exceptions import ProgrammingError

        c = OracleConnect(host='x', port=1, user='pyo', password='p')
        with self.assertRaises(NotSupportedError):
            c.subscribe(callback=lambda m: None)
        with self.assertRaises(ProgrammingError):
            c.unsubscribe(None)

    def test_async_subscribe_unsubscribe_reject(self):
        # Sync/async parity: regular (non-coroutine) methods that raise before
        # any await point.
        from seerdb.client.aconnection import AsyncOracleConnect

        a = AsyncOracleConnect(host='x', port=1, user='pyo', password='p')
        with self.assertRaises(NotSupportedError):
            a.subscribe(callback=lambda m: None)
        with self.assertRaises(NotSupportedError):
            a.unsubscribe()


class _FakeWriter:
    """Records writes and no-ops the asyncio.StreamWriter teardown calls that
    AsyncOracleConnect.close/disconnect drive, so an offline close() can run
    without a real socket."""

    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(bytes(data))

    async def drain(self):
        pass

    def can_write_eof(self):
        return False

    def close(self):
        pass

    async def wait_closed(self):
        pass


class TestAsyncCloseTeardown(unittest.TestCase):
    # Sync/async parity: OracleConnect.close() follows the §10 teardown — roll
    # back if autocommit is off, send TTI_LOGOFF and read its response, then a
    # final empty TNS_DATA packet with the EOF data flag so the server fully
    # releases the session (without it sessions linger and pile up over rapid
    # reconnects). The async close() must do the same.
    def _authenticated_conn(self, autocommit):
        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.common.tns_consts import CONN_STATE_AUTHENTICATED

        a = AsyncOracleConnect(
            host='x', port=1, user='pyo', password='p', autocommit=autocommit
        )
        a.conn_state = CONN_STATE_AUTHENTICATED
        a._writer = _FakeWriter()
        a._reader = object()
        # The logoff round-trip helpers do real socket I/O; stub them so the
        # teardown sequence runs offline over the fake writer.
        a.rollback = mock.AsyncMock()
        a._handle_response = mock.AsyncMock()
        return a

    def test_close_rolls_back_then_emits_eof_marker(self):
        # The marker is an empty DATA packet in the session's framing: 10
        # bytes, the data flags after the 8-byte header, as python-oracledb
        # 26.1 sends it to 23ai (`0000000a 06 00 0000 0040`). Packed by hand,
        # it was 8 bytes with the flags in the header checksum (#2558).
        for large, marker in (
            (False, '000a00000600000000' + '40'),
            (True, '0000000a0600000000' + '40'),
        ):
            with self.subTest(large=large):
                a = self._authenticated_conn(autocommit=False)
                a._large_packets = large
                writer = a._writer  # disconnect() nulls it during close()
                asyncio.run(a.close())
                a.rollback.assert_awaited_once()  # autocommit off -> roll back
                a._handle_response.assert_awaited_once()  # logoff is answered
                # the logoff is sent before the marker, which is the last write
                self.assertGreaterEqual(len(writer.writes), 2)
                self.assertEqual(writer.writes[-1].hex(), marker)

    def test_close_skips_rollback_when_autocommit(self):
        a = self._authenticated_conn(autocommit=True)
        asyncio.run(a.close())
        a.rollback.assert_not_awaited()
        a._handle_response.assert_awaited_once()

    def test_autocommit_defaults_to_off(self):
        # PEP 249 starts a connection with auto-commit off, and python-oracledb
        # does; seerdb defaulted it on until 3.0.0 (#1447). Sync and async alike.
        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.client.connection import OracleConnect

        for cls in (OracleConnect, AsyncOracleConnect):
            self.assertIs(
                cls(host='x', port=1, user='u', password='p').autocommit, False
            )
            self.assertIs(
                cls(
                    host='x', port=1, user='u', password='p', autocommit=True
                ).autocommit,
                True,
            )

    def test_close_noop_when_not_authenticated(self):
        # A connection that never authenticated must not send logoff/rollback.
        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.common.tns_consts import CONN_STATE_CONNECTED

        a = AsyncOracleConnect(host='x', port=1, user='pyo', password='p')
        a.conn_state = CONN_STATE_CONNECTED
        a._writer = _FakeWriter()
        a._reader = object()
        a.rollback = mock.AsyncMock()
        a._handle_response = mock.AsyncMock()
        writer = a._writer  # disconnect() nulls the attribute during close()

        asyncio.run(a.close())

        a.rollback.assert_not_awaited()
        a._handle_response.assert_not_awaited()
        self.assertEqual(writer.writes, [])


class TestSyncAsyncTeardownParity(unittest.TestCase):
    # Guard against sync/async drift in the I/O-interleaved teardown / txn
    # methods (close, commit, rollback). These interleave blocking recv vs
    # await, so they can't share a body and are hand-duplicated between
    # connection.py and aconnection.py — exactly the shape that produced the
    # close() parity gaps in #645/#646. Rather than re-test each method's
    # behavior on both sides, run the *real* sync and async bodies with their
    # I/O substeps instrumented and assert both issue the same ordered sequence
    # of logical steps. A step added to one side but not the other (or
    # reordered) makes the traces diverge and fails here.
    _STEP_METHODS = ('rollback', 'commit', 'send', '_handle_response', 'disconnect')

    def _marker(self):
        # The EOF packet in the legacy framing a fresh connection has (#2558).
        return bytes.fromhex('000a0000060000000040')

    def _instrument(self, conn, method, trace, is_async):
        # Replace every teardown substep except the method under test with a
        # recorder, so the traced body's real control flow drives the sequence.
        for name in self._STEP_METHODS:
            if name == method:
                continue
            if is_async:
                setattr(
                    conn,
                    name,
                    mock.AsyncMock(
                        side_effect=lambda *a, _n=name, **k: trace.append(_n)
                    ),
                )
            else:
                setattr(conn, name, lambda *a, _n=name, **k: trace.append(_n))

    def _sync_trace(self, method, autocommit):
        from seerdb.client.connection import OracleConnect
        from seerdb.common.tns_consts import CONN_STATE_AUTHENTICATED

        c = OracleConnect(
            host='x', port=1, user='pyo', password='p', autocommit=autocommit
        )
        c.conn_state = CONN_STATE_AUTHENTICATED
        trace: list[str] = []
        marker = self._marker()

        class _RecordingSock:
            def send(self, data):
                trace.append('eof_marker' if bytes(data) == marker else 'raw_write')
                return len(data)

        c.sock = _RecordingSock()
        self._instrument(c, method, trace, is_async=False)
        getattr(c, method)()
        return trace

    def _async_trace(self, method, autocommit):
        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.common.tns_consts import CONN_STATE_AUTHENTICATED

        a = AsyncOracleConnect(
            host='x', port=1, user='pyo', password='p', autocommit=autocommit
        )
        a.conn_state = CONN_STATE_AUTHENTICATED
        trace: list[str] = []
        marker = self._marker()

        class _RecordingWriter:
            def write(self, data):
                trace.append('eof_marker' if bytes(data) == marker else 'raw_write')

            async def drain(self):
                pass

        a._writer = _RecordingWriter()
        a._reader = object()
        self._instrument(a, method, trace, is_async=True)
        asyncio.run(getattr(a, method)())
        return trace

    def _assert_parity(self, method):
        for autocommit in (False, True):
            sync = self._sync_trace(method, autocommit)
            asyncr = self._async_trace(method, autocommit)
            self.assertEqual(
                sync,
                asyncr,
                f'{method}() sync vs async step sequence differs '
                f'(autocommit={autocommit}): {sync} != {asyncr}',
            )

    def test_close_step_parity(self):
        self._assert_parity('close')
        for autocommit in (False, True):
            self.assertIn('eof_marker', self._sync_trace('close', autocommit))

    def test_commit_step_parity(self):
        self._assert_parity('commit')

    def test_rollback_step_parity(self):
        self._assert_parity('rollback')


class TestProxyUser(unittest.TestCase):
    # Proxy authentication (#126): user "proxy[schema]" -> authenticate as
    # proxy, operate in schema. The wire side (PROXY_CLIENT_NAME auth pair) is
    # covered by the live tests on 10g/11g/21c/23ai.
    def test_split(self):
        self.assertEqual(_split_proxy_user('pyo[hr]'), ('pyo', 'hr'))
        self.assertEqual(_split_proxy_user('PROXY[TARGET]'), ('PROXY', 'TARGET'))

    def test_plain_user_unchanged(self):
        self.assertEqual(_split_proxy_user('pyo'), ('pyo', None))
        self.assertEqual(_split_proxy_user(''), ('', None))
        self.assertEqual(_split_proxy_user(None), (None, None))

    def test_only_trailing_brackets_after_name(self):
        # a leading bracket or a missing closing bracket is not a proxy form
        self.assertEqual(_split_proxy_user('[hr]'), ('[hr]', None))
        self.assertEqual(_split_proxy_user('pyo[hr'), ('pyo[hr', None))

    def test_connection_init_parses_user(self):
        c = OracleConnect(host='x', port=1, user='pyo[hr]', password='p')
        self.assertEqual(c.user, 'pyo')
        self.assertEqual(c.proxy_user, 'hr')
        env = c._make_dict(None)['env']
        self.assertEqual(env['user'], 'pyo')
        self.assertEqual(env['proxy_user'], 'hr')


class TestShardingRejected(unittest.TestCase):
    # Sharding keys (#164) route to a shard of a sharded database — an OCI-only
    # capability below the thin wire protocol. seerdb accepts the
    # oracledb-compatible parameters but rejects them with NotSupportedError
    # (before any socket work), so ported thin code gets the recognizable error
    # rather than a TypeError on an unexpected keyword.
    def test_helper_passes_through_when_absent(self):
        # None / absent must not raise (the default construction path).
        self.assertIsNone(_reject_sharding(None, None))

    def test_helper_rejects_each_key(self):
        with self.assertRaises(NotSupportedError):
            _reject_sharding(['CUST42'], None)
        with self.assertRaises(NotSupportedError):
            _reject_sharding(None, ['REGION1'])
        with self.assertRaises(NotSupportedError):
            _reject_sharding([42], ['REGION1'])

    def test_helper_rejects_falsey_but_present_key(self):
        # An empty list is still a request to shard — present, so rejected.
        with self.assertRaises(NotSupportedError):
            _reject_sharding([], None)

    def test_connection_init_rejects_sharding(self):
        # Raised at construction, before any host/port is touched.
        with self.assertRaises(NotSupportedError):
            OracleConnect(host='x', port=1, user='pyo', shardingkey=['CUST42'])
        with self.assertRaises(NotSupportedError):
            OracleConnect(host='x', port=1, user='pyo', supershardingkey=['R1'])

    def test_connection_init_without_sharding_ok(self):
        # The default (no sharding) construction path is unaffected.
        c = OracleConnect(host='x', port=1, user='pyo', password='p')
        self.assertEqual(c.host, 'x')

    def test_async_connection_init_rejects_sharding(self):
        # Sync/async parity: the async constructor rejects it the same way
        # (its __init__ is not a coroutine, so no loop is needed here).
        from seerdb.client.aconnection import AsyncOracleConnect

        with self.assertRaises(NotSupportedError):
            AsyncOracleConnect(host='x', port=1, user='pyo', shardingkey=['C'])
        # And the default path still constructs.
        a = AsyncOracleConnect(host='x', port=1, user='pyo', password='p')
        self.assertEqual(a.host, 'x')


class TestFv2BindSizeGate(unittest.TestCase):
    # 9i (fv2) caps a plain str / bytes bind at the SQL inline limits: 2000
    # bytes (RAW) / 4000 bytes (VARCHAR2). Past those, into a LOB column the 9i
    # server kills the connection or errors, as it does for ojdbc14 (#2260);
    # reject up front so the connection survives (#168/#169). A declared LONG
    # Var is not capped. Verified live on 9i; this guards the limits + boundary
    # offline.
    def test_bytes_within_cap_ok(self):
        _check_fv2_bind_sizes([b'x' * _FV2_MAX_RAW_BIND])  # exactly 2000

    def test_bytes_over_cap_raises(self):
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes([b'x' * (_FV2_MAX_RAW_BIND + 1)])

    def test_str_within_cap_ok(self):
        _check_fv2_bind_sizes(['x' * _FV2_MAX_VARCHAR_BIND])  # exactly 4000

    def test_str_over_cap_raises(self):
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes(['x' * (_FV2_MAX_VARCHAR_BIND + 1)])

    def test_the_refusal_names_both_routes(self):
        # A LONG column takes the value declared DB_TYPE_LONG; a LOB column
        # through its locator (#2260).
        with self.assertRaises(NotSupportedError) as raised:
            _check_fv2_bind_sizes(['x' * (_FV2_MAX_VARCHAR_BIND + 1)])
        self.assertIn('DB_TYPE_LONG', str(raised.exception))
        self.assertIn('locator', str(raised.exception))
        with self.assertRaises(NotSupportedError) as raised:
            _check_fv2_bind_sizes([b'x' * (_FV2_MAX_RAW_BIND + 1)])
        self.assertIn('DB_TYPE_LONG_RAW', str(raised.exception))

    def test_a_declared_long_var_is_not_capped(self):
        import seerdb.common.datatypes as dt

        v = dt.Var(dt.DB_TYPE_LONG, 50000)
        v.setvalue(0, 'q' * 50000)
        _check_fv2_bind_sizes([v])  # the server takes it inline

    def test_str_counts_utf8_bytes_not_chars(self):
        # A multibyte char string under 4000 chars can exceed 4000 utf-8 bytes.
        Value = 'é' * 2001  # 4002 utf-8 bytes
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes([Value])

    def test_dict_and_batch_values_checked(self):
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes({'b': b'x' * 2001})
        with self.assertRaises(NotSupportedError):
            _check_fv2_bind_sizes([1], Batch=[[b'x' * 2001]])

    def test_small_and_nonblob_binds_pass(self):
        _check_fv2_bind_sizes([1, 'small', b'raw', None, 3.14])
        _check_fv2_bind_sizes([])


def _reply_packet(body: bytes, last: bool) -> bytes:
    from seerdb.common.tns import encode_data_packet
    from seerdb.common.tns_consts import TNS_DATA_FLAGS_END_OF_RESPONSE

    return encode_data_packet(body, TNS_DATA_FLAGS_END_OF_RESPONSE if last else 0)


class TestReadsToTheEndOfAResponse(unittest.TestCase):
    # A reply arriving one packet per read -- as an encrypting server writes it
    # -- is read to the packet marked END_OF_RESPONSE, not cut where the bytes
    # read so far happen to end (#1845). A server that never marks its replies
    # keeps the old behaviour, so nothing waits for a mark that never comes.
    REPLY = [(b'one', False), (b'two', False), (b'three', True)]

    def _sync_recv(self, packets: list[tuple[bytes, bool]]) -> bytes:
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        con = OracleConnect()
        con.sock = ours

        def write_one_per_read():
            for body, last in packets:
                theirs.sendall(_reply_packet(body, last))
                time.sleep(0.05)

        threading.Thread(target=write_one_per_read, daemon=True).start()
        con._replies_marked = True  # an earlier reply carried the mark
        received = con.recv(b'', b'')
        assert received is not False
        return received[1]

    def test_a_marked_reply_is_read_to_its_last_packet(self):
        self.assertEqual(self._sync_recv(self.REPLY), b'onetwothree')

    def test_the_first_marked_reply_turns_reading_to_the_mark_on(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        con = OracleConnect()
        con.sock = ours
        theirs.sendall(_reply_packet(b'login', True))
        self.assertEqual(con.recv(b'', b''), (6, b'login'))
        self.assertTrue(con._replies_marked)

    def test_a_flush_out_binds_request_is_handed_on_unmarked(self):
        # A failing RETURNING makes the server send `07 00 13` -- a flush-out-binds
        # request, not marked END_OF_RESPONSE -- and wait for the client's answer;
        # reading on for the mark deadlocked the two (#697, #1845).
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        con = OracleConnect()
        con.sock = ours
        con._replies_marked = True
        theirs.sendall(_reply_packet(b'\x07\x00\x13', False))
        ours.settimeout(5)
        self.assertEqual(con.recv(b'', b''), (6, b'\x07\x00\x13'))

    def test_a_server_that_never_marks_is_read_as_before(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        con = OracleConnect()
        con.sock = ours
        theirs.sendall(_reply_packet(b'whole', False))
        self.assertEqual(con.recv(b'', b''), (6, b'whole'))

    def test_the_async_connection_reads_to_the_mark_too(self):
        from seerdb.client.aconnection import AsyncOracleConnect

        async def run() -> bytes:
            con = AsyncOracleConnect(host='x', port=1, user='u', password='p')
            reader = asyncio.StreamReader()
            con._reader = reader
            con._replies_marked = True

            async def write_one_per_read():
                for body, last in self.REPLY:
                    reader.feed_data(_reply_packet(body, last))
                    await asyncio.sleep(0.02)

            writer = asyncio.ensure_future(write_one_per_read())
            received = await con.recv(b'', b'')
            await writer
            assert received is not False
            return received[1]

        self.assertEqual(asyncio.run(run()), b'onetwothree')


class TestLobReplyAcrossPackets(unittest.TestCase):
    # A LOB READ reply spans packets, and a content chunk may straddle two: the
    # reader walks the bytes received so far and carries on, wherever a packet
    # ends (#1845). Slicing a straddling chunk short lost all but its first part.
    from seerdb.common.tns_consts import TNS_LONG_LENGTH_INDICATOR as _FE
    from seerdb.common.tns_consts import TTI_LOB as _LOB
    from seerdb.common.tns_consts import TTI_OER as _OER

    # The return parameters as 23ai sends them (#2540): TTI_RPA, the 40-byte
    # locator the READ declared, then the amount read, 4000 as <02><0f a0>.
    LOCATOR = bytes.fromhex(
        '00260000c2088000000265260000'
        '00ea000000010369000a00000000'
        '00021aab82f1000000010000'
    )
    RPA = bytes([0x08]) + LOCATOR + bytes([0x02, 0x0F, 0xA0])
    OER = bytes([_OER, 0x01, 0x01, 0x02, 0x38, 0x77, 0x00])
    # The same OER under implicit pooling: the call status is 0x4001.
    OER_POOLED = bytes([_OER, 0x02, 0x40, 0x01, 0x02, 0x38, 0x52, 0x00])

    def _walk(self, reply: bytes, split: int, ub4: bool) -> bytes:
        from seerdb.client.connection import _lob_reply_step

        out = bytearray()
        data, pos, chunked = b'', 0, False
        for packet in (reply[:split], reply[split:]):
            data = data[pos:] + packet
            pos, chunked, done = _lob_reply_step(
                data, 0, out, chunked, ub4, len(self.LOCATOR)
            )
            if done:
                return bytes(out)
        raise AssertionError('no OER reached')

    def test_ub4_chunks_split_anywhere(self):
        content = bytes(range(256)) * 3
        chunks = b''.join(
            bytes([2]) + len(part).to_bytes(2, 'big') + part
            for part in (content[:300], content[300:])
        )
        reply = bytes([self._LOB, self._FE]) + chunks + b'\x00' + self.RPA + self.OER
        for split in range(1, len(reply)):
            self.assertEqual(self._walk(reply, split, True), content, split)

    def test_ub1_chunks_and_a_plain_value_split_anywhere(self):
        content = b'abcdefghij' * 20
        chunked = bytes([self._LOB, self._FE, 100]) + content[:100]
        chunked += bytes([100]) + content[100:] + b'\x00'
        plain = bytes([self._LOB, 5]) + b'hello'
        for reply, want in (
            (chunked + self.RPA + self.OER, content),
            (plain + self.RPA + self.OER, b'hello'),
        ):
            for split in range(1, len(reply)):
                self.assertEqual(self._walk(reply, split, False), want, split)

    def test_a_two_byte_call_status_ends_the_reply(self):
        # Under implicit pooling the OER's call status is 0x4001, written in
        # two bytes; the reply ends there all the same (#2540).
        reply = bytes([self._LOB, 5]) + b'hello' + self.RPA + self.OER_POOLED
        for split in range(1, len(reply)):
            self.assertEqual(self._walk(reply, split, True), b'hello', split)

    def test_an_unknown_message_raises_rather_than_waits(self):
        from seerdb.common.exceptions import InterfaceError

        reply = bytes([self._LOB, 5]) + b'hello' + self.RPA + b'\x55' + self.OER
        with self.assertRaises(InterfaceError):
            self._walk(reply, len(reply), True)


class TestReplyContinuation(unittest.TestCase):
    # A reply decode that runs past the bytes read so far reads the reply's next
    # packet and decodes again from the rows it began with (#1845); a reply that
    # does not go on raises its Truncated rather than waiting for ever.
    def test_a_short_decode_reads_on_and_starts_over(self):
        from seerdb.common.exceptions import Truncated

        con = OracleConnect()
        rows: list = ['earlier row']
        seen = []

        def decode(packet, acc, *_versions):
            seen.append(packet)
            acc[2].append('partial')
            if packet == b'first':
                raise Truncated('row runs off the end')
            return ('done', list(acc[2]))

        with (
            mock.patch.object(con, '_next_data_packet', return_value=(6, b'first')),
            mock.patch.object(con, '_read_continuation', return_value=b'second'),
            mock.patch('seerdb.common.tns.decode_packet', decode),
        ):
            result = con._handle_response((None, None, rows))
        self.assertEqual(seen, [b'first', b'firstsecond'])
        self.assertEqual(result, ('done', ['earlier row', 'partial']))

    def test_a_reply_that_does_not_go_on_raises(self):
        from seerdb.client import connection as cm
        from seerdb.common.exceptions import Truncated

        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        con = OracleConnect()
        con.sock = ours
        with mock.patch.object(cm, '_CONTINUATION_SECONDS', 0.2):
            with self.assertRaises(Truncated):
                con._read_continuation(Truncated('row runs off the end'))
        self.assertIsNone(ours.gettimeout())


class TestConnection(unittest.TestCase):
    def test_empty_credentials_rejected(self):
        # Connecting with the default empty username/password must not silently
        # "succeed". The server rejects the logon with an auth-error OER, which
        # now surfaces as a DatabaseError (ORA-01017) instead of being swallowed
        # — and crucially no longer hangs the handshake. Needs a reachable
        # listener on localhost:1521; an unreachable one raises OSError instead.
        con = OracleConnect()
        with self.assertRaises((DatabaseError, OSError)):
            con.connect()

    def test_recv_times_out_on_silent_server(self):
        # The connection `timeout` (ms) must bound blocking socket reads: a
        # server that accepts the TCP connection but never replies (e.g. an XE
        # session held by the logon-storm throttle) used to wedge recv forever
        # because the timeout was never applied to the socket. It now raises an
        # OperationalError after roughly `timeout` ms instead of hanging.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        accepted = []

        def accept_and_hang():
            try:
                conn, _ = srv.accept()
                accepted.append(conn)  # hold it open; never reply
            except OSError:
                # Expected during teardown/races when the listening socket is
                # closed while this daemon thread is blocked in accept().
                pass

        threading.Thread(target=accept_and_hang, daemon=True).start()

        con = OracleConnect(
            host='127.0.0.1',
            port=srv.getsockname()[1],
            user='x',
            password='y',
            service_name='XE',
            timeout=1000,
        )
        start = time.monotonic()
        with self.assertRaises(OperationalError):
            con.connect()
        elapsed = time.monotonic() - start
        # Fired on the timeout, not after some unbounded wait.
        self.assertLess(elapsed, 10)
        self.assertGreaterEqual(elapsed, 0.5)
        for conn in accepted:
            conn.close()


class TestRedirectConnectRetry(unittest.TestCase):
    # #399: following a TNS_REDIRECT, the target dispatcher / dedicated-server
    # process may still be binding its port — a refused connect should be retried
    # briefly. An INITIAL refused connect must still fail fast.

    @staticmethod
    def _conn():
        return OracleConnect(
            host='127.0.0.1', port=1, user='x', password='y', service_name='XE'
        )

    def _fake_socket(self, refusals):
        # A socket whose connect() raises ConnectionRefusedError `refusals` times,
        # then succeeds. Tracks the attempt count.
        state = {'n': 0}

        class Fake:
            def settimeout(self, _t):
                pass

            def connect(self, _addr):
                state['n'] += 1
                if state['n'] <= refusals:
                    raise ConnectionRefusedError(111, 'Connection refused')

            def close(self):
                pass

        return Fake(), state

    def test_retries_on_refused_while_following_redirect(self):
        con = self._conn()
        con._redirects = 1  # we are following a redirect
        fake, state = self._fake_socket(refusals=3)
        with (
            mock.patch('seerdb.client.connection.socket.socket', return_value=fake),
            mock.patch('seerdb.client.connection.time.sleep'),
            mock.patch.object(con, 'send'),
        ):
            con._open_transport()  # must not raise
        self.assertEqual(state['n'], 4)  # 3 refusals + 1 success

    def test_initial_connect_does_not_retry(self):
        con = self._conn()
        con._redirects = 0  # initial connect
        fake, state = self._fake_socket(refusals=99)
        with (
            mock.patch('seerdb.client.connection.socket.socket', return_value=fake),
            mock.patch('seerdb.client.connection.time.sleep'),
            mock.patch.object(con, 'send'),
        ):
            with self.assertRaises(ConnectionRefusedError):
                con._open_transport()
        self.assertEqual(state['n'], 1)  # failed fast, no retry

    def test_gives_up_after_the_attempt_cap(self):
        con = self._conn()
        con._redirects = 1
        fake, state = self._fake_socket(refusals=999)  # never comes up
        with (
            mock.patch('seerdb.client.connection.socket.socket', return_value=fake),
            mock.patch('seerdb.client.connection.time.sleep'),
            mock.patch.object(con, 'send'),
        ):
            with self.assertRaises(ConnectionRefusedError):
                con._open_transport()
        self.assertEqual(state['n'], _REDIRECT_CONNECT_ATTEMPTS)
