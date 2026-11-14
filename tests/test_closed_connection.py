# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A connection that closes mid-call raises a DB-API error (#2656), offline.

A receive that found the connection closed raised a bare ``Exception``, which
a handler for ``seerdb.Error`` let through. It is now an ``OperationalError``,
worded as python-oracledb's DPY-4011; a packet no reply can be is an
``InternalError``.
"""

import asyncio
import unittest

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect
from seerdb.client.dialect import RECV, Oci11Dialect, Send
from seerdb.common.exceptions import Error, InternalError, OperationalError

# A TNS packet type no reply has (TNS_REFUSE).
_NOT_A_REPLY = 4


def _sync(received) -> OracleConnect:
    conn = object.__new__(OracleConnect)
    # The receive's answer, set on the instance (mypy won't let a method be assigned).
    setattr(conn, '_next_data_packet', lambda *_: received)
    return conn


def _async(received) -> AsyncOracleConnect:
    conn = object.__new__(AsyncOracleConnect)

    async def next_data_packet(*_):
        return received

    setattr(conn, '_next_data_packet', next_data_packet)
    return conn


class ReplyLoopTest(unittest.TestCase):
    def test_a_closed_connection_is_an_operational_error(self):
        with self.assertRaises(OperationalError) as raised:
            _sync(False)._handle_response()
        self.assertIsInstance(raised.exception, Error)
        self.assertEqual(
            str(raised.exception),
            'the database or network closed the connection during the call',
        )

    def test_a_packet_no_reply_can_be_is_an_internal_error(self):
        with self.assertRaisesRegex(InternalError, 'unexpected response type: 4'):
            _sync((_NOT_A_REPLY, b''))._handle_response()

    def test_the_async_loop_raises_the_same(self):
        # It raised InterfaceError for the closed connection.
        with self.assertRaisesRegex(
            OperationalError, 'closed the connection during the call'
        ):
            asyncio.run(_async(False)._handle_response())
        with self.assertRaises(InternalError):
            asyncio.run(_async((_NOT_A_REPLY, b''))._handle_response())


class DialectTest(unittest.TestCase):
    def test_a_dialect_call_cut_off_is_an_operational_error(self):
        gen = Oci11Dialect(lambda: 7).ping()
        self.assertIsInstance(next(gen), Send)
        self.assertIs(gen.send(None), RECV)
        with self.assertRaisesRegex(
            OperationalError,
            '^the database or network closed the connection during 11g ping$',
        ):
            gen.send(False)


if __name__ == '__main__':
    unittest.main()
