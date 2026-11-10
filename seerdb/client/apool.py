# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async connection pool.

Async-native counterpart to `seerdb.client.pool.Pool`. Same shape — pre-warm
to `min`, grow lazily to `max`, optional health-check on idle reacquire
— but the synchronisation primitives are `asyncio.Lock` and
`asyncio.Condition` so concurrent coroutines wait on a free entry
without blocking the event loop.

Usage:

    pool = await seerdb.create_pool_async(
        host=..., user=..., password=..., service_name=...,
        min=2, max=10,
    )
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM dual")
    await pool.close()
"""

import asyncio
import inspect
import time
from collections import deque
from typing import Any, Callable

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.pool import (
    _KEEP,
    _PoolEntry,
    _PoolPolicy,
    apply_drcp_pool_defaults,
    check_session_callback,
    drcp_pool_class,
    forget_pool,
)
from seerdb.common.exceptions import InterfaceError


class _AsyncPooledConnectionGuard:
    """Async context manager returned by `AsyncPool.acquire()`.
    Releases on `__aexit__` even if the user's block raised."""

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: 'AsyncPool', conn: AsyncOracleConnect):
        self._pool = pool
        self._conn = conn

    async def __aenter__(self) -> AsyncOracleConnect:
        return self._conn

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._pool.release(self._conn)


class AsyncPool:
    """Async-native pool of `AsyncOracleConnect` instances.

    Construction does NOT pre-warm — there's no event loop at
    `__init__` time and we want the pool to be usable from
    synchronous helper code that calls `AsyncPool(...)` and only
    later enters the loop. Instead, the first batch of `min`
    connections is opened lazily on the first `acquire()`.

    Use `create_pool_async()` (module-level helper) to pre-warm
    explicitly in an async context.
    """

    def __init__(
        self,
        min: int = 1,
        max: int = 4,
        increment: int = 1,
        timeout: float | None = 30.0,
        idle_timeout: float | None = 60.0,
        health_check: bool = True,
        getmode: int | None = None,
        wait_timeout: int = 0,
        ping_interval: float | None = None,
        max_lifetime_session: float = 0,
        max_idle_session: float = 0,
        session_callback: Callable[..., Any] | None = None,
        **connect_kwargs,
    ):
        self._policy = _PoolPolicy(
            min,
            max,
            increment,
            timeout,
            idle_timeout,
            health_check,
            getmode,
            wait_timeout,
            ping_interval,
            max_lifetime_session,
            max_idle_session,
        )
        self._session_callback = check_session_callback(session_callback)
        self._connect_kwargs = connect_kwargs
        # The connection class this pool's DRCP sessions share (#2006).
        self._drcp_class = drcp_pool_class()

        # asyncio.Condition wraps an asyncio.Lock; same usage as the
        # sync Pool but everything is await-based. Created lazily so
        # the pool can be constructed outside an event loop.
        self._lock: asyncio.Lock | None = None
        self._available: asyncio.Condition | None = None
        self._free: deque[_PoolEntry] = deque()
        self._in_use: dict[int, _PoolEntry] = {}
        self._opening = 0
        self._closed = False
        self._prewarmed = False

    # ----- public API -----

    async def prewarm(self) -> None:
        """Open `min` connections up front. Idempotent. Normally called
        for you by the first `acquire()`; `create_pool_async()` calls
        it eagerly so the construction call awaits the opens."""
        cond = self._ensure_sync_primitives()
        async with cond:
            if self._prewarmed or self._closed:
                return
            self._prewarmed = True
            for _ in range(self._policy.min):
                Conn = await self._open_connection()
                self._free.append(_PoolEntry(Conn))

    def acquire(self) -> '_AcquireContext':
        """Return an async context manager that yields a free
        connection (or opens a fresh one, up to `max`). Use as:

            async with pool.acquire() as conn:
                ...
        """
        return _AcquireContext(self)

    async def release(self, conn: AsyncOracleConnect) -> None:
        """Return a connection to the pool. Idempotent; releasing a
        connection not produced by this pool raises InterfaceError."""
        cond = self._ensure_sync_primitives()
        Retired: list[AsyncOracleConnect] = []
        async with cond:
            Entry = self._in_use.pop(id(conn), None)
            if Entry is None:
                raise InterfaceError('connection was not acquired from this pool')
            if self._closed:
                Retired.append(conn)
            else:
                # End the pooled logical request (#464): flush REQUEST_END if
                # open; a failure means the connection is dead, so discard it.
                try:
                    await conn._end_request()
                except Exception:
                    Retired.append(conn)
                else:
                    Now = time.monotonic()
                    if self._policy.past_lifetime(Entry, Now) or (
                        self._held() >= self._policy.max
                    ):
                        Retired.append(conn)
                    else:
                        Entry.released_at = Now
                        self._free.append(Entry)
                    Retired.extend(self._retire_idle(Now))
                cond.notify()
        await self._discard_all(Retired)

    async def reconfigure(
        self,
        min: int | None = None,
        max: int | None = None,
        increment: int | None = None,
        getmode: int | None = None,
        timeout: Any = _KEEP,
        wait_timeout: int | None = None,
        ping_interval: float | None = None,
        max_lifetime_session: float | None = None,
        max_idle_session: float | None = None,
    ) -> None:
        """Change the pool's settings while it is in use. What isn't given
        keeps its value; `timeout=None` means wait forever, as at creation.
        Every value is checked before any takes effect. Above a smaller `max`,
        free connections close now and busy ones on release; below a larger
        `min`, connections open now. An `acquire()` already waiting keeps the
        deadline it started with."""
        Changes: dict[str, Any] = {
            Name: Value
            for Name, Value in (
                ('min', min),
                ('max', max),
                ('increment', increment),
                ('getmode', getmode),
                ('wait_timeout', wait_timeout),
                ('ping_interval', ping_interval),
                ('max_lifetime_session', max_lifetime_session),
                ('max_idle_session', max_idle_session),
            )
            if Value is not None
        }
        if timeout is not _KEEP:
            Changes['timeout'] = timeout
        Policy = self._policy.replaced(**Changes)
        cond = self._ensure_sync_primitives()
        async with cond:
            if self._closed:
                raise InterfaceError('pool is closed')
            self._policy = Policy
            Retired = self._retire_above_max()
            cond.notify_all()
        await self._discard_all(Retired)
        # Before the first acquire the pool holds nothing yet, and `prewarm()`
        # opens the new `min` itself.
        if self._prewarmed:
            await self._grow_to_min()

    async def close(self) -> None:
        """Close every free connection and mark the pool closed.
        Connections still checked out get closed when their caller
        releases them."""
        forget_pool(self)
        cond = self._ensure_sync_primitives()
        async with cond:
            self._closed = True
            while self._free:
                Entry = self._free.popleft()
                try:
                    await Entry.conn.close()
                except Exception:
                    # Best-effort: keep draining the rest even if one
                    # connection refuses to close.
                    pass
            cond.notify_all()

    @property
    def opened(self) -> int:
        return len(self._free) + len(self._in_use)

    @property
    def busy(self) -> int:
        return len(self._in_use)

    # ----- internals -----

    def _ensure_sync_primitives(self) -> asyncio.Condition:
        if self._available is None:
            self._lock = asyncio.Lock()
            self._available = asyncio.Condition(self._lock)
        return self._available

    def _held(self) -> int:
        """Connections held or being opened."""
        return len(self._free) + len(self._in_use) + self._opening

    def _retire_idle(self, now: float) -> list[AsyncOracleConnect]:
        """Free connections past `max_idle_session`, down to `min`, for the
        caller to close outside the lock. The oldest release is first, so the
        scan stops at the first one still in time."""
        Retired: list[AsyncOracleConnect] = []
        while (
            self._free
            and self._held() > self._policy.min
            and self._policy.past_idle(self._free[0], now)
        ):
            Retired.append(self._free.popleft().conn)
        return Retired

    def _retire_above_max(self) -> list[AsyncOracleConnect]:
        """Free connections over `max`, oldest release first, for the caller
        to close outside the lock."""
        Retired: list[AsyncOracleConnect] = []
        while self._free and self._held() > self._policy.max:
            Retired.append(self._free.popleft().conn)
        return Retired

    async def _grow_to_min(self) -> None:
        """Open connections until the pool holds `min`."""
        cond = self._ensure_sync_primitives()
        while True:
            async with cond:
                if self._closed or self._held() >= self._policy.min:
                    return
                self._opening += 1
            try:
                Conn = await self._open_connection()
            except BaseException:
                async with cond:
                    self._opening -= 1
                    cond.notify()
                raise
            async with cond:
                self._opening -= 1
                Closed = self._closed
                if not Closed:
                    self._free.append(_PoolEntry(Conn))
                    cond.notify()
            if Closed:
                await self._discard_dead(Conn)
                return

    async def _acquire_one(self) -> AsyncOracleConnect:
        """The body of acquire(), refactored so the
        `_AcquireContext` can drive it explicitly."""
        if not self._prewarmed:
            await self.prewarm()
        Deadline = self._policy.deadline(time.monotonic())
        while True:
            Entry, Reserved, Retired = await self._claim(Deadline)
            await self._discard_all(Retired)
            if Reserved:
                Conn = await self._open_reserved()
            elif Entry is not None and await self._alive(Entry):
                Conn = Entry.conn
            else:
                continue
            Conn._begin_request()  # request boundary (#464)
            await self._run_session_callback(Conn)
            return Conn

    async def _run_session_callback(self, Conn: AsyncOracleConnect) -> None:
        """Run the session callback the first time `Conn` is handed out, as
        python-oracledb does, with no tag requested; awaited when it returns an
        awaitable. If it raises, the connection goes back and the next caller
        to get it runs the callback again."""
        Callback = self._session_callback
        if Callback is None:
            return
        Entry = self._in_use.get(id(Conn))
        if Entry is None or not Entry.needs_callback:
            return
        try:
            Result = Callback(Conn, None)
            if inspect.isawaitable(Result):
                await Result
        except BaseException:
            await self.release(Conn)
            raise
        Entry.needs_callback = False

    async def _claim(
        self, deadline: float | None
    ) -> tuple[_PoolEntry | None, bool, list[AsyncOracleConnect]]:
        """Under the lock, take a free connection or reserve a slot to open
        one, waiting as `getmode` says. Returns the entry, whether a slot was
        reserved, and the connections to close once the lock is let go."""
        cond = self._ensure_sync_primitives()
        async with cond:
            while True:
                if self._closed:
                    raise InterfaceError('pool is closed')
                Policy = self._policy  # `reconfigure()` may change it mid-wait
                Now = time.monotonic()
                Retired = self._retire_idle(Now)
                while self._free:
                    Entry = self._free.popleft()
                    if Policy.past_lifetime(Entry, Now):
                        Retired.append(Entry.conn)
                        continue
                    self._in_use[id(Entry.conn)] = Entry
                    return Entry, False, Retired
                Busy = len(self._in_use) + self._opening
                if Policy.may_open(Busy):
                    self._opening += 1
                    return None, True, Retired
                if Retired:
                    return None, False, Retired  # close them, then look again
                if deadline is None:
                    await cond.wait()
                else:
                    Remaining = deadline - time.monotonic()
                    if Remaining <= 0:
                        raise Policy.exhausted(Busy)
                    try:
                        await asyncio.wait_for(cond.wait(), timeout=Remaining)
                    except asyncio.TimeoutError:
                        raise Policy.exhausted(
                            len(self._in_use) + self._opening
                        ) from None

    async def _open_reserved(self) -> AsyncOracleConnect:
        """Open a connection into the slot `_claim` reserved."""
        cond = self._ensure_sync_primitives()
        try:
            Conn = await self._open_connection()
        except BaseException:
            async with cond:
                self._opening -= 1
                cond.notify()
            raise
        async with cond:
            self._opening -= 1
            Closed = self._closed
            if not Closed:
                self._in_use[id(Conn)] = _PoolEntry(Conn)
        if Closed:
            await self._discard_dead(Conn)
            raise InterfaceError('pool is closed')
        return Conn

    async def _alive(self, entry: _PoolEntry) -> bool:
        """Ping a claimed entry if it is due one. A dead connection gives its
        slot back."""
        if not self._policy.needs_ping(entry, time.monotonic()):
            return True
        try:
            Alive = await self._ping(entry.conn)
        except BaseException:
            await self._forget(entry.conn)
            raise
        if not Alive:
            await self._forget(entry.conn)
            await self._discard_dead(entry.conn)
        return Alive

    async def _forget(self, conn: AsyncOracleConnect) -> None:
        cond = self._ensure_sync_primitives()
        async with cond:
            self._in_use.pop(id(conn), None)
            cond.notify()

    async def _open_connection(self) -> AsyncOracleConnect:
        Conn = AsyncOracleConnect(**self._connect_kwargs)
        apply_drcp_pool_defaults(Conn, self._drcp_class)
        await Conn.connect()
        return Conn

    async def _ping(self, conn: AsyncOracleConnect) -> bool:
        try:
            Cur = conn.cursor()
            try:
                await Cur.execute('SELECT 1 FROM DUAL')
                await Cur.fetchone()
            finally:
                try:
                    await Cur.close()
                except Exception:
                    # Best-effort: the ping already has its result; a failed
                    # cursor close must not mask it.
                    pass
            return True
        except Exception:
            return False

    async def _discard_dead(self, conn: AsyncOracleConnect) -> None:
        try:
            await conn.close()
        except Exception:
            # The connection is already known to be dead; closing it is
            # purely best-effort cleanup.
            pass

    async def _discard_all(self, conns: list[AsyncOracleConnect]) -> None:
        for Conn in conns:
            await self._discard_dead(Conn)


class AsyncPooledConnection:
    """A connection `seerdb.connect_async(pool_alias=...)` took from a named
    pool: the connection to use, and `close()`, or leaving an `async with`
    block, hands it back to the pool."""

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: AsyncPool, conn: AsyncOracleConnect):
        object.__setattr__(self, '_pool', pool)
        object.__setattr__(self, '_conn', conn)

    def _connection(self) -> AsyncOracleConnect:
        Conn = object.__getattribute__(self, '_conn')
        if Conn is None:
            raise InterfaceError('connection was returned to its pool')
        return Conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._connection(), name, value)

    async def close(self) -> None:
        Conn = object.__getattribute__(self, '_conn')
        if Conn is not None:
            object.__setattr__(self, '_conn', None)
            await object.__getattribute__(self, '_pool').release(Conn)

    async def __aenter__(self) -> 'AsyncPooledConnection':
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()


class _AcquireContext:
    """Glue between `pool.acquire()` and the async-with statement.

    Resolves the connection in `__aenter__` (so the user awaits the
    acquire there) and hands it back to the pool in `__aexit__`.
    Returning a plain coroutine from `acquire()` would also work but
    forces `async with await pool.acquire():` — the extra `await`
    is ugly and easy to forget.
    """

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: AsyncPool):
        self._pool = pool
        self._conn: AsyncOracleConnect | None = None

    async def __aenter__(self) -> AsyncOracleConnect:
        self._conn = await self._pool._acquire_one()
        return self._conn

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._conn is not None:
            await self._pool.release(self._conn)
            self._conn = None
