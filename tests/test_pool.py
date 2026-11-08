# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The pool's acquire policy, sync and async, on stand-in connections."""

import asyncio
import threading
import unittest

import seerdb
from seerdb.client.apool import AsyncPool
from seerdb.client.pool import Pool
from seerdb.common.exceptions import InterfaceError


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql):
        self.conn.pings += 1
        if self.conn.dead:
            raise OSError('gone')

    def fetchone(self):
        return (1,)

    def close(self):
        pass


class FakeConn:
    def __init__(self):
        self.pings = 0
        self.dead = False
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True

    def _begin_request(self):
        pass

    def _end_request(self):
        pass


class FakePool(Pool):
    def _open_connection(self):
        return FakeConn()


class AsyncFakeCursor(FakeCursor):
    async def execute(self, sql):
        FakeCursor.execute(self, sql)

    async def fetchone(self):
        return (1,)

    async def close(self):
        pass


class AsyncFakeConn(FakeConn):
    def cursor(self):
        return AsyncFakeCursor(self)

    async def close(self):
        self.closed = True

    async def _end_request(self):
        pass


class AsyncFakePool(AsyncPool):
    async def _open_connection(self):
        return AsyncFakeConn()


def age(entry, seconds):
    entry.created_at -= seconds
    entry.released_at -= seconds


class TestGetmode(unittest.TestCase):
    def test_constants_match_python_oracledb(self):
        self.assertEqual(
            (
                seerdb.POOL_GETMODE_WAIT,
                seerdb.POOL_GETMODE_NOWAIT,
                seerdb.POOL_GETMODE_FORCEGET,
                seerdb.POOL_GETMODE_TIMEDWAIT,
            ),
            (0, 1, 2, 3),
        )

    def test_nowait_raises_at_once(self):
        pool = FakePool(min=1, max=1, getmode=seerdb.POOL_GETMODE_NOWAIT)
        with pool.acquire():
            with self.assertRaisesRegex(InterfaceError, 'no free connection'):
                pool.acquire()

    def test_timedwait_gives_up_after_wait_timeout(self):
        pool = FakePool(
            min=1, max=1, getmode=seerdb.POOL_GETMODE_TIMEDWAIT, wait_timeout=20
        )
        with pool.acquire():
            with self.assertRaisesRegex(InterfaceError, '20ms'):
                pool.acquire()

    def test_wait_ignores_timeout(self):
        pool = FakePool(min=1, max=1, timeout=0, getmode=seerdb.POOL_GETMODE_WAIT)
        guard = pool.acquire()
        got = []
        # A daemon: if this test fails, nothing releases the waiter.
        waiter = threading.Thread(
            target=lambda: got.append(pool.acquire()), daemon=True
        )
        waiter.start()
        waiter.join(0.1)
        self.assertTrue(waiter.is_alive())
        pool.release(guard._conn)
        waiter.join(5)
        self.assertEqual(len(got), 1)

    def test_no_getmode_keeps_timeout(self):
        pool = FakePool(min=1, max=1, timeout=0)
        with pool.acquire():
            with self.assertRaisesRegex(InterfaceError, 'timed out after 0s'):
                pool.acquire()

    def test_forceget_goes_past_max_and_closes_on_release(self):
        pool = FakePool(min=1, max=1, getmode=seerdb.POOL_GETMODE_FORCEGET)
        with pool.acquire():
            with pool.acquire() as extra:
                self.assertEqual(pool.opened, 2)
            self.assertTrue(extra.closed)
            self.assertEqual(pool.opened, 1)

    def test_invalid_arguments_are_refused(self):
        for kwargs in (
            {'getmode': 9},
            {'wait_timeout': -1},
            {'max_lifetime_session': -1},
            {'max_idle_session': -1},
        ):
            with self.subTest(kwargs), self.assertRaises(ValueError):
                FakePool(min=0, max=1, **kwargs)


class TestPing(unittest.TestCase):
    def acquired_after(self, idle, **kwargs):
        pool = FakePool(min=1, max=1, **kwargs)
        pool._free[0].released_at -= idle
        with pool.acquire() as conn:
            return conn.pings

    def test_ping_interval(self):
        self.assertEqual(self.acquired_after(0, ping_interval=10), 0)
        self.assertEqual(self.acquired_after(11, ping_interval=10), 1)
        self.assertEqual(self.acquired_after(0, ping_interval=0), 1)
        self.assertEqual(self.acquired_after(1000, ping_interval=-1), 0)

    def test_the_older_spelling_still_works(self):
        self.assertEqual(self.acquired_after(61), 1)
        self.assertEqual(self.acquired_after(5, idle_timeout=2), 1)
        self.assertEqual(self.acquired_after(1000, idle_timeout=None), 0)
        self.assertEqual(self.acquired_after(1000, health_check=False), 0)

    def test_ping_interval_excludes_the_older_spelling(self):
        for kwargs in ({'idle_timeout': 5}, {'health_check': False}):
            with self.subTest(kwargs), self.assertRaises(ValueError):
                FakePool(min=0, max=1, ping_interval=1, **kwargs)

    def test_dead_connection_is_replaced(self):
        pool = FakePool(min=1, max=1, ping_interval=0)
        pool._free[0].conn.dead = True
        first = pool._free[0].conn
        with pool.acquire() as conn:
            self.assertIsNot(conn, first)
            self.assertTrue(first.closed)
            self.assertEqual(pool.opened, 1)


class TestRetirement(unittest.TestCase):
    def test_lifetime_closes_on_acquire(self):
        pool = FakePool(min=1, max=1, max_lifetime_session=10)
        old = pool._free[0].conn
        age(pool._free[0], 11)
        with pool.acquire() as conn:
            self.assertIsNot(conn, old)
        self.assertTrue(old.closed)

    def test_lifetime_closes_on_release_not_during_use(self):
        pool = FakePool(min=1, max=1, max_lifetime_session=10)
        with pool.acquire() as conn:
            age(pool._in_use[id(conn)], 11)
            self.assertFalse(conn.closed)
        self.assertTrue(conn.closed)
        self.assertEqual(pool.opened, 0)

    def test_zero_lifetime_is_no_limit(self):
        pool = FakePool(min=1, max=1)
        old = pool._free[0].conn
        age(pool._free[0], 100000)
        pool._policy.ping_interval = -1
        with pool.acquire() as conn:
            self.assertIs(conn, old)

    def test_idle_closes_above_min_only(self):
        pool = FakePool(min=1, max=3, max_idle_session=10, ping_interval=-1)
        with pool.acquire():
            with pool.acquire():
                pass
        self.assertEqual(pool.opened, 2)
        for entry in pool._free:
            age(entry, 11)
        with pool.acquire():
            # One was idle too long and sat above `min`; the other is in use.
            self.assertEqual(pool.opened, 1)


class TestReconfigure(unittest.TestCase):
    def test_what_is_not_given_keeps_its_value(self):
        pool = FakePool(min=1, max=2, timeout=5, ping_interval=7)
        pool.reconfigure(getmode=seerdb.POOL_GETMODE_NOWAIT)
        policy = pool._policy
        self.assertEqual(policy.getmode, seerdb.POOL_GETMODE_NOWAIT)
        self.assertEqual((policy.min, policy.max), (1, 2))
        self.assertEqual((policy.timeout, policy.ping_interval), (5, 7))

    def test_timeout_none_is_a_value(self):
        pool = FakePool(min=0, max=1, timeout=5)
        pool.reconfigure(timeout=None)
        self.assertIsNone(pool._policy.timeout)

    def test_a_disabled_ping_stays_disabled(self):
        pool = FakePool(min=0, max=1, health_check=False)
        pool.reconfigure(max=2)
        self.assertEqual(pool._policy.ping_interval, -1)

    def test_a_bad_value_changes_nothing(self):
        pool = FakePool(min=1, max=2)
        before = pool._policy
        for kwargs in (
            {'max': 3, 'wait_timeout': -1},
            {'max': 0},
            {'min': 3},
            {'getmode': 9},
        ):
            with self.subTest(kwargs), self.assertRaises(ValueError):
                pool.reconfigure(**kwargs)
            self.assertIs(pool._policy, before)
            self.assertEqual(pool.opened, 1)

    def test_growing_min_opens_now(self):
        pool = FakePool(min=1, max=4)
        pool.reconfigure(min=3)
        self.assertEqual(pool.opened, 3)
        self.assertEqual(pool.busy, 0)

    def test_shrinking_max_closes_free_now_and_busy_on_release(self):
        pool = FakePool(min=0, max=3, ping_interval=-1)
        first, second, third = pool.acquire(), pool.acquire(), pool.acquire()
        pool.release(third._conn)
        pool.reconfigure(max=1)
        self.assertTrue(third._conn.closed)
        self.assertEqual(pool.opened, 2)
        pool.release(first._conn)
        self.assertTrue(first._conn.closed)
        pool.release(second._conn)
        self.assertFalse(second._conn.closed)
        self.assertEqual(pool.opened, 1)

    def test_a_larger_max_wakes_a_waiter(self):
        pool = FakePool(min=1, max=1, getmode=seerdb.POOL_GETMODE_WAIT)
        held = pool.acquire()
        got = []
        # A daemon: if this test fails, nothing releases the waiter.
        waiter = threading.Thread(
            target=lambda: got.append(pool.acquire()), daemon=True
        )
        waiter.start()
        waiter.join(0.1)
        self.assertTrue(waiter.is_alive())
        pool.reconfigure(max=2)
        waiter.join(5)
        self.assertEqual(len(got), 1)
        self.assertIsNot(got[0]._conn, held._conn)

    def test_a_closed_pool_is_refused(self):
        pool = FakePool(min=0, max=1)
        pool.close()
        with self.assertRaisesRegex(InterfaceError, 'closed'):
            pool.reconfigure(max=2)


class TestLock(unittest.TestCase):
    def test_a_slow_open_does_not_block_a_release(self):
        opening, proceed = threading.Event(), threading.Event()

        class SlowPool(FakePool):
            def _open_connection(self):
                opening.set()
                proceed.wait(5)
                return FakeConn()

        pool = SlowPool(min=0, max=2)
        proceed.set()
        held = pool.acquire()
        proceed.clear()
        opening.clear()
        slow = threading.Thread(target=pool.acquire)
        slow.start()
        self.assertTrue(opening.wait(5))
        released = threading.Thread(target=pool.release, args=(held._conn,))
        released.start()
        released.join(2)
        blocked = released.is_alive()
        proceed.set()
        slow.join(5)
        released.join(5)
        self.assertFalse(blocked)

    def test_a_failed_open_gives_its_slot_back(self):
        class FailingPool(FakePool):
            fail = True

            def _open_connection(self):
                if self.fail:
                    raise OSError('refused')
                return FakeConn()

        pool = FailingPool(min=0, max=1, timeout=0)
        with self.assertRaises(OSError):
            pool.acquire()
        pool.fail = False
        with pool.acquire():
            self.assertEqual(pool.busy, 1)

    def test_an_open_finishing_after_close_is_closed(self):
        opened = []

        class ClosingPool(FakePool):
            def _open_connection(self):
                conn = FakeConn()
                opened.append(conn)
                self.close()
                return conn

        pool = ClosingPool(min=0, max=1)
        with self.assertRaisesRegex(InterfaceError, 'closed'):
            pool.acquire()
        self.assertTrue(opened[0].closed)


class TestAsync(unittest.IsolatedAsyncioTestCase):
    async def full(self, **kwargs):
        pool = AsyncFakePool(min=1, max=1, **kwargs)
        await pool.prewarm()
        return pool

    async def test_nowait_raises_at_once(self):
        pool = await self.full(getmode=seerdb.POOL_GETMODE_NOWAIT)
        async with pool.acquire():
            with self.assertRaisesRegex(InterfaceError, 'no free connection'):
                await pool._acquire_one()

    async def test_timedwait_gives_up(self):
        pool = await self.full(getmode=seerdb.POOL_GETMODE_TIMEDWAIT, wait_timeout=20)
        async with pool.acquire():
            with self.assertRaisesRegex(InterfaceError, '20ms'):
                await pool._acquire_one()

    async def test_forceget_goes_past_max_and_closes_on_release(self):
        pool = await self.full(getmode=seerdb.POOL_GETMODE_FORCEGET)
        async with pool.acquire():
            async with pool.acquire() as extra:
                self.assertEqual(pool.opened, 2)
            self.assertTrue(extra.closed)
            self.assertEqual(pool.opened, 1)

    async def test_ping_interval(self):
        pool = await self.full(ping_interval=0)
        async with pool.acquire() as conn:
            self.assertEqual(conn.pings, 1)

    async def test_lifetime_closes_on_acquire(self):
        pool = await self.full(max_lifetime_session=10)
        old = pool._free[0].conn
        age(pool._free[0], 11)
        async with pool.acquire() as conn:
            self.assertIsNot(conn, old)
        self.assertTrue(old.closed)

    async def test_idle_closes_above_min_only(self):
        pool = AsyncFakePool(min=1, max=3, max_idle_session=10, ping_interval=-1)
        await pool.prewarm()
        async with pool.acquire():
            async with pool.acquire():
                pass
        for entry in pool._free:
            age(entry, 11)
        async with pool.acquire():
            self.assertEqual(pool.opened, 1)

    async def test_reconfigure_grows_and_shrinks(self):
        pool = AsyncFakePool(min=1, max=4, ping_interval=-1)
        await pool.prewarm()
        await pool.reconfigure(min=3)
        self.assertEqual(pool.opened, 3)
        await pool.reconfigure(min=1, max=2)
        self.assertEqual(pool.opened, 2)

    async def test_reconfigure_before_the_first_acquire(self):
        pool = AsyncFakePool(min=1, max=4)
        await pool.reconfigure(min=2)
        self.assertEqual(pool.opened, 0)
        await pool.prewarm()
        self.assertEqual(pool.opened, 2)

    async def test_a_larger_max_wakes_a_waiter(self):
        pool = await self.full(getmode=seerdb.POOL_GETMODE_WAIT)
        held = await pool._acquire_one()
        waiter = asyncio.create_task(pool._acquire_one())
        await asyncio.sleep(0.05)
        self.assertFalse(waiter.done())
        await pool.reconfigure(max=2)
        self.assertIsNot(await asyncio.wait_for(waiter, 5), held)

    async def test_reconfigure_refuses_a_bad_value(self):
        pool = await self.full()
        before = pool._policy
        with self.assertRaises(ValueError):
            await pool.reconfigure(max=3, wait_timeout=-1)
        self.assertIs(pool._policy, before)

    async def test_a_slow_open_does_not_block_a_release(self):
        opening, proceed = asyncio.Event(), asyncio.Event()

        class SlowPool(AsyncFakePool):
            async def _open_connection(self):
                opening.set()
                await proceed.wait()
                return AsyncFakeConn()

        pool = SlowPool(min=0, max=2)
        proceed.set()
        await pool.prewarm()
        held = await pool._acquire_one()
        proceed.clear()
        opening.clear()
        slow = asyncio.create_task(pool._acquire_one())
        await asyncio.wait_for(opening.wait(), 5)
        await asyncio.wait_for(pool.release(held), 2)
        proceed.set()
        await asyncio.wait_for(slow, 5)


if __name__ == '__main__':
    unittest.main()
