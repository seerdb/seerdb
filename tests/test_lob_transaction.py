# SPDX-FileCopyrightText: 2025 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""call_status is a flag word, not a "more rows" or "done" signal (#712).

It reads 1 with autocommit on and 2 while a transaction is open. Two readers
keyed on the value 1: the row drain fetched further rows only then, and the
LOB reader found the end of a LOB reply only by the bytes `04 01 01`. With
autocommit off, a SELECT of a LOB column of an uncommitted row therefore
returned no rows (the server defers such rows to a FETCH), and where the row
did arrive the LOB read waited forever for an end of call it had already
received.
"""

import unittest
from unittest.mock import AsyncMock, patch

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    TNS_DATA,
    TTI_LOB,
    TTI_OER,
    TTI_RPA,
)

ROW_FORMAT = ('dcb', [{'data_type': 2}])
IN_TRANSACTION = 2
END_OF_FETCH = 1403


def _deferred(cursor_id=7):
    """An execute reply for a LOB row in an open transaction: status 2, no
    end-of-fetch, a cursor, nothing inline."""
    return (IN_TRANSACTION, 0, cursor_id, ROW_FORMAT, [], None)


def _drained(rows, cursor_id=7):
    return (IN_TRANSACTION, END_OF_FETCH, cursor_id, ROW_FORMAT, rows, None)


# A LOB reply: the content, an RPA the reader skips, then the OER with
# call_status 2 -- the shape an open transaction produces.
_LOB_REPLY_IN_TRANSACTION = (
    bytes([TTI_LOB, 5])
    + b'hello'
    # the locator (3 bytes here) and the amount read, 5
    + bytes([TTI_RPA, 0, 1, 0, 1, 5])
    + bytes([TTI_OER, 1, IN_TRANSACTION, 2, 0x0D, 0xBA, 0, 0])
)


class TestTheDrainFetchesWhateverTheCallStatus(unittest.TestCase):
    def _conn(self):
        conn = OracleConnect()
        conn.field_version = FIELD_VERSION_11_2
        return conn

    def test_deferred_rows_are_fetched(self):
        batches = [_drained([[1, 'x']])]
        with patch.object(OracleConnect, 'fetch_more', lambda *a, **k: batches.pop(0)):
            result = self._conn()._drain_cursor(_deferred())
        self.assertEqual(result[4], [[1, 'x']])
        self.assertEqual(result[1], 0)  # the 1403 sentinel stays internal

    def test_inline_rows_at_end_of_fetch_need_no_fetch(self):
        def must_not_fetch(*a, **k):
            raise AssertionError('the drain fetched past the end of fetch')

        with patch.object(OracleConnect, 'fetch_more', must_not_fetch):
            result = self._conn()._drain_cursor(_drained([[1]]))
        self.assertEqual(result[4], [[1]])

    def test_an_empty_batch_ends_the_loop(self):
        # No 1403 and no rows: the loop must still stop, not spin.
        calls = []

        def empty(*a, **k):
            calls.append(1)
            if len(calls) > 3:
                raise AssertionError('the drain loop did not terminate')
            return _deferred()

        with patch.object(OracleConnect, 'fetch_more', empty):
            result = self._conn()._drain_cursor(_deferred())
        self.assertEqual(result[4], [])
        self.assertEqual(len(calls), 1)


class TestTheLobReaderFindsTheEndOfCallInATransaction(unittest.TestCase):
    def test_call_status_2_ends_the_reply(self):
        conn = OracleConnect()
        conn.field_version = FIELD_VERSION_11_2
        calls = []

        def one_packet(self, *a):
            calls.append(1)
            if len(calls) > 1:
                raise AssertionError('the reader kept waiting past the end of call')
            return (TNS_DATA, _LOB_REPLY_IN_TRANSACTION)

        with patch.object(OracleConnect, '_next_data_packet', one_packet):
            self.assertEqual(conn._read_lob_response(3), b'hello')


class TestTheAsyncTwins(unittest.IsolatedAsyncioTestCase):
    async def test_deferred_rows_are_fetched(self):
        conn = AsyncOracleConnect()
        conn.field_version = FIELD_VERSION_11_2
        with patch.object(
            AsyncOracleConnect,
            'fetch_more',
            AsyncMock(return_value=_drained([[1, 'x']])),
        ):
            result = await conn._drain_cursor(_deferred())
        self.assertEqual(result[4], [[1, 'x']])

    async def test_call_status_2_ends_the_reply(self):
        conn = AsyncOracleConnect()
        conn.field_version = FIELD_VERSION_11_2
        packets = AsyncMock(
            side_effect=[
                (TNS_DATA, _LOB_REPLY_IN_TRANSACTION),
                AssertionError('the reader kept waiting past the end of call'),
            ]
        )
        with patch.object(AsyncOracleConnect, '_next_data_packet', packets):
            self.assertEqual(await conn._read_lob_response(3), b'hello')
