# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Connection pool.

`seerdb.connect()` does a full TNS / O5LOGON handshake every time, which
takes a few hundred ms even against a local XE. Long-running applications
that frequently acquire short-lived connections (one per request, etc.)
end up spending more time handshaking than running queries.

A pool keeps a small set of authenticated `OracleConnect` instances
warm. Acquire pulls a free one from the pool (or opens a fresh one,
up to `max`); release returns it. Each acquisition optionally verifies
the connection is still alive with a cheap round-trip first.

Usage:

    pool = seerdb.create_pool(host=..., user=..., password=...,
                              service_name=..., min=2, max=10)
    with pool.acquire() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM dual")
    pool.close()
"""

import base64
import secrets
import threading
import time
from collections import deque
from typing import Any, Callable

from seerdb.client._conn_logic import _ConnectionLogic
from seerdb.client.connection import OracleConnect
from seerdb.common.exceptions import InterfaceError, ProgrammingError
from seerdb.common.tns_consts import PURITY_DEFAULT, PURITY_SELF

# What `acquire()` does when every connection is busy and the pool is at `max`,
# numbered as in python-oracledb so its constants compare equal.
POOL_GETMODE_WAIT = 0  # wait for one, however long
POOL_GETMODE_NOWAIT = 1  # raise at once
POOL_GETMODE_FORCEGET = 2  # open one past `max`, closed again on release
POOL_GETMODE_TIMEDWAIT = 3  # wait up to `wait_timeout` milliseconds

_GETMODES = (
    POOL_GETMODE_WAIT,
    POOL_GETMODE_NOWAIT,
    POOL_GETMODE_FORCEGET,
    POOL_GETMODE_TIMEDWAIT,
)
_DEFAULT_IDLE_TIMEOUT = 60.0
# `reconfigure(timeout=...)` left out: None already means wait forever.
_KEEP: Any = object()


class _PoolEntry:
    """One pooled connection, with when it was opened and last released, and
    whether the pool's session callback has yet to succeed on it."""

    __slots__ = ('conn', 'created_at', 'released_at', 'needs_callback')

    def __init__(self, conn: Any):
        self.conn = conn
        self.created_at = self.released_at = time.monotonic()
        self.needs_callback = True


def check_session_callback(callback: Any) -> Any:
    """A pool's session callback: a callable, or None for none. python-oracledb
    takes a PL/SQL procedure's name here too, for DRCP's tags; seerdb has
    no tags."""
    if callback is not None and not callable(callback):
        raise TypeError(
            'session_callback must be a callable taking the connection and the '
            f'requested tag, not {type(callback).__name__}'
        )
    return callback


class _PoolPolicy:
    """A pool's settings and what follows from them, shared by `Pool` and
    `AsyncPool`. Nothing here touches a connection or a lock."""

    def __init__(
        self,
        min: int,
        max: int,
        increment: int,
        timeout: float | None,
        idle_timeout: float | None,
        health_check: bool,
        getmode: int | None,
        wait_timeout: int,
        ping_interval: float | None,
        max_lifetime_session: float,
        max_idle_session: float,
    ):
        if min < 0 or max <= 0 or min > max:
            raise ValueError(
                f'invalid pool sizes: min={min}, max={max} '
                f'(need 0 <= min <= max and max > 0)'
            )
        if increment <= 0:
            raise ValueError(f'increment must be positive, got {increment}')
        if getmode is not None and getmode not in _GETMODES:
            raise ValueError(f'invalid getmode: {getmode}')
        for Name, Value in (
            ('wait_timeout', wait_timeout),
            ('max_lifetime_session', max_lifetime_session),
            ('max_idle_session', max_idle_session),
        ):
            if Value < 0:
                raise ValueError(f'{Name} must not be negative, got {Value}')
        if ping_interval is None:
            # `idle_timeout` and `health_check`, the older spelling.
            Off = idle_timeout is None or not health_check
            ping_interval = -1 if Off else idle_timeout
        elif idle_timeout != _DEFAULT_IDLE_TIMEOUT or not health_check:
            raise ValueError(
                'ping_interval replaces idle_timeout and health_check: '
                'give one or the other'
            )
        self.min = min
        self.max = max
        self.increment = increment
        self.timeout = timeout
        self.getmode = getmode
        self.wait_timeout = wait_timeout
        self.ping_interval: float = ping_interval  # type: ignore[assignment]
        self.max_lifetime_session = max_lifetime_session
        self.max_idle_session = max_idle_session

    def replaced(self, **changes: Any) -> '_PoolPolicy':
        """A copy with `changes` applied, validated as a new pool's would be."""
        Values: dict[str, Any] = {
            'min': self.min,
            'max': self.max,
            'increment': self.increment,
            'timeout': self.timeout,
            'getmode': self.getmode,
            'wait_timeout': self.wait_timeout,
            'ping_interval': self.ping_interval,
            'max_lifetime_session': self.max_lifetime_session,
            'max_idle_session': self.max_idle_session,
        }
        Values.update(changes)
        return _PoolPolicy(
            idle_timeout=_DEFAULT_IDLE_TIMEOUT, health_check=True, **Values
        )

    def deadline(self, now: float) -> float | None:
        """When an acquire on a full pool gives up; None waits forever."""
        if self.getmode is None:
            return None if self.timeout is None else now + self.timeout
        if self.getmode == POOL_GETMODE_WAIT:
            return None
        if self.getmode == POOL_GETMODE_TIMEDWAIT:
            return now + self.wait_timeout / 1000
        return now

    def may_open(self, busy: int) -> bool:
        return busy < self.max or self.getmode == POOL_GETMODE_FORCEGET

    def exhausted(self, busy: int) -> InterfaceError:
        State = f'(in_use={busy}, max={self.max})'
        if self.getmode == POOL_GETMODE_NOWAIT:
            return InterfaceError(f'pool has no free connection {State}')
        if self.getmode == POOL_GETMODE_TIMEDWAIT:
            return InterfaceError(
                f'pool acquire timed out after {self.wait_timeout}ms {State}'
            )
        return InterfaceError(f'pool acquire timed out after {self.timeout}s {State}')

    def needs_ping(self, entry: _PoolEntry, now: float) -> bool:
        return self.ping_interval >= 0 and (
            now - entry.released_at >= self.ping_interval
        )

    def past_lifetime(self, entry: _PoolEntry, now: float) -> bool:
        Limit = self.max_lifetime_session
        return Limit > 0 and now - entry.created_at >= Limit

    def past_idle(self, entry: _PoolEntry, now: float) -> bool:
        Limit = self.max_idle_session
        return Limit > 0 and now - entry.released_at >= Limit


class PooledConnection:
    """A connection taken from a pool, by `Pool.acquire()` or by
    `seerdb.connect(pool_alias=...)`.

    It is the connection to use, and `close()`, `Pool.release()`, or leaving a
    `with` block hands it back to the pool rather than closing it, as
    python-oracledb's pooled connection does (#2555). Leaving the block
    releases it whether or not the block raised; a connection left in a bad
    state is caught by the next acquire's health check."""

    __slots__ = ('_pool', '_conn')

    def __init__(self, pool: 'Pool', conn: OracleConnect):
        object.__setattr__(self, '_pool', pool)
        object.__setattr__(self, '_conn', conn)

    def _connection(self) -> OracleConnect:
        Conn = object.__getattribute__(self, '_conn')
        if Conn is None:
            raise InterfaceError('connection was returned to its pool')
        return Conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._connection(), name, value)

    def close(self) -> None:
        Conn = object.__getattribute__(self, '_conn')
        if Conn is not None:
            object.__setattr__(self, '_conn', None)
            object.__getattribute__(self, '_pool').release(Conn)

    def __enter__(self) -> 'PooledConnection':
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# The pools created with a `pool_alias`, by it (#2459). A name is taken while
# its pool is being made, so two at once cannot both have it.
_NAMED_POOLS: dict[str, Any] = {}
_NAMED_LOCK = threading.Lock()
_BEING_MADE = object()


def take_pool_alias(alias: Any) -> None:
    """Reserve `alias` for a pool being made: a str, not taken yet."""
    if not isinstance(alias, str):
        raise TypeError('pool_alias must be a string')
    with _NAMED_LOCK:
        if alias in _NAMED_POOLS:
            raise ProgrammingError(
                f'a connection pool with alias "{alias}" already exists'
            )
        _NAMED_POOLS[alias] = _BEING_MADE


def settle_pool_alias(alias: str, pool: Any) -> None:
    """Name the pool made under `alias`, or free the name when it was not
    made (`pool` None)."""
    with _NAMED_LOCK:
        if pool is None:
            _NAMED_POOLS.pop(alias, None)
        else:
            _NAMED_POOLS[alias] = pool


def forget_pool(pool: Any) -> None:
    """Free the names a closed pool had."""
    with _NAMED_LOCK:
        for Alias in [A for (A, P) in _NAMED_POOLS.items() if P is pool]:
            del _NAMED_POOLS[Alias]


def get_pool(alias: str) -> Any:
    """The open pool created with `pool_alias=alias`, or None."""
    Pool_ = _NAMED_POOLS.get(alias)
    return None if Pool_ is _BEING_MADE else Pool_


def named_pool(alias: str, kind: type) -> Any:
    """The pool `seerdb.connect(pool_alias=alias)` takes a connection from."""
    Pool_ = get_pool(alias)
    if Pool_ is None:
        raise ProgrammingError(f'a connection pool with alias "{alias}" does not exist')
    if not isinstance(Pool_, kind):
        raise ProgrammingError(
            f'the connection pool with alias "{alias}" is not a {kind.__name__}'
        )
    return Pool_


def drcp_pool_class() -> str:
    """A connection class for one DRCP pool: a prefix and the base64 of 16
    random bytes, the shape python-oracledb gives its own pools (`DPY:` and 24
    characters, new for each pool, measured) under seerdb's prefix, so the
    server's DRCP statistics name the driver that made it (#2006)."""
    return 'SEERDB:' + base64.b64encode(secrets.token_bytes(16)).decode('ascii')


def apply_drcp_pool_defaults(conn: _ConnectionLogic, cclass: str) -> None:
    """What a pool sets on a connection that asks for a pooled server (#2006):
    the pool's own class when the connection names none, and purity SELF when
    it is left at the default -- as python-oracledb's pools do, where a
    standalone pooled connection sends NEW and no class. Applied after the
    connection reads its dsn, so `:pooled` there counts too."""
    if conn.server_type != 'pooled':
        return
    if not conn.cclass:
        conn.cclass = cclass
    if conn.purity == PURITY_DEFAULT:
        conn.purity = PURITY_SELF


class Pool:
    """Thread-safe pool of authenticated `OracleConnect` instances.

    Construction is lazy: only `min` connections are opened up front;
    the rest are created on demand and capped at `max`. What `acquire()`
    does at `max` follows `getmode`; left out, it blocks up to `timeout`
    seconds until another caller releases.
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

        # `_free` holds available entries, oldest release first; `_in_use` the
        # checked-out ones by id(conn). `_opening` counts the slots reserved
        # for connections being opened, which happens outside the lock.
        self._lock = threading.Lock()
        self._available = threading.Condition(self._lock)
        self._free: deque[_PoolEntry] = deque()
        self._in_use: dict[int, _PoolEntry] = {}
        self._opening = 0
        self._closed = False

        # Pre-warm to `min`. Failures here surface immediately rather than
        # later when the caller acquires.
        for _ in range(self._policy.min):
            self._free.append(_PoolEntry(self._open_connection()))

    # ----- public API -----

    def acquire(self) -> PooledConnection:
        """Get a connection from the pool: the connection itself, which
        `close()`, `release()` or leaving a `with` block hands back."""
        Deadline = self._policy.deadline(time.monotonic())
        while True:
            Entry, Reserved, Retired = self._claim(Deadline)
            self._discard_all(Retired)
            if Reserved:
                Conn = self._open_reserved()
            elif Entry is not None and self._alive(Entry):
                Conn = Entry.conn
            else:
                continue
            Conn._begin_request()  # request boundary (#464)
            self._run_session_callback(Conn)
            return PooledConnection(self, Conn)

    def release(self, conn: 'OracleConnect | PooledConnection') -> None:
        """Return a connection to the pool. Idempotent on already-released
        connections (a misbehaving caller releasing twice doesn't break
        accounting). Connections not produced by this pool are rejected."""
        if isinstance(conn, PooledConnection):
            if object.__getattribute__(conn, '_pool') is not self:
                raise InterfaceError('connection was not acquired from this pool')
            conn.close()
            return
        Retired: list[OracleConnect] = []
        with self._available:
            Entry = self._in_use.pop(id(conn), None)
            if Entry is None:
                raise InterfaceError('connection was not acquired from this pool')
            if self._closed:
                # Pool closed while held -- just close this one ourselves.
                Retired.append(conn)
            else:
                # End the pooled logical request (#464): flush REQUEST_END if
                # one is open. A failure here means the connection is dead --
                # discard it rather than return a broken connection.
                try:
                    conn._end_request()
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
                self._available.notify()
        self._discard_all(Retired)

    def reconfigure(
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
        with self._available:
            if self._closed:
                raise InterfaceError('pool is closed')
            self._policy = Policy
            Retired = self._retire_above_max()
            self._available.notify_all()
        self._discard_all(Retired)
        self._grow_to_min()

    def close(self) -> None:
        """Close all connections (free + in-use). Subsequent `acquire`
        calls raise InterfaceError."""
        forget_pool(self)
        with self._available:
            self._closed = True
            # Free entries close immediately; in-use entries will close
            # when their caller releases them.
            while self._free:
                Entry = self._free.popleft()
                try:
                    Entry.conn.close()
                except Exception:
                    # Best-effort: keep draining the rest even if one
                    # connection refuses to close.
                    pass
            self._available.notify_all()

    @property
    def opened(self) -> int:
        """Connections currently held by the pool (free + in-use)."""
        with self._lock:
            return len(self._free) + len(self._in_use)

    @property
    def busy(self) -> int:
        """Connections currently checked out."""
        with self._lock:
            return len(self._in_use)

    # ----- internals -----

    def _held(self) -> int:
        """Connections held or being opened; the caller holds the lock."""
        return len(self._free) + len(self._in_use) + self._opening

    def _retire_idle(self, now: float) -> list[OracleConnect]:
        """Free connections past `max_idle_session`, down to `min`. The oldest
        release is first, so the scan stops at the first one still in time.
        The caller holds the lock, and closes what this returns outside it."""
        Retired: list[OracleConnect] = []
        while (
            self._free
            and self._held() > self._policy.min
            and self._policy.past_idle(self._free[0], now)
        ):
            Retired.append(self._free.popleft().conn)
        return Retired

    def _retire_above_max(self) -> list[OracleConnect]:
        """Free connections over `max`, oldest release first; the caller holds
        the lock, and closes what this returns outside it."""
        Retired: list[OracleConnect] = []
        while self._free and self._held() > self._policy.max:
            Retired.append(self._free.popleft().conn)
        return Retired

    def _grow_to_min(self) -> None:
        """Open connections until the pool holds `min`."""
        while True:
            with self._available:
                if self._closed or self._held() >= self._policy.min:
                    return
                self._opening += 1
            try:
                Conn = self._open_connection()
            except BaseException:
                with self._available:
                    self._opening -= 1
                    self._available.notify()
                raise
            with self._available:
                self._opening -= 1
                Closed = self._closed
                if not Closed:
                    self._free.append(_PoolEntry(Conn))
                    self._available.notify()
            if Closed:
                self._discard_dead(Conn)
                return

    def _run_session_callback(self, Conn: OracleConnect) -> None:
        """Run the session callback the first time `Conn` is handed out, as
        python-oracledb does, with no tag requested. If it raises, the
        connection goes back and the next caller to get it runs it again."""
        Callback = self._session_callback
        if Callback is None:
            return
        with self._lock:
            Entry = self._in_use.get(id(Conn))
        if Entry is None or not Entry.needs_callback:
            return
        try:
            Callback(Conn, None)
        except BaseException:
            self.release(Conn)
            raise
        Entry.needs_callback = False

    def _claim(
        self, deadline: float | None
    ) -> tuple[_PoolEntry | None, bool, list[OracleConnect]]:
        """Under the lock, take a free connection or reserve a slot to open
        one, waiting as `getmode` says. Returns the entry, whether a slot was
        reserved, and the connections to close once the lock is let go."""
        with self._available:
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
                    self._available.wait()
                else:
                    Remaining = deadline - time.monotonic()
                    if Remaining <= 0:
                        raise Policy.exhausted(Busy)
                    self._available.wait(Remaining)

    def _open_reserved(self) -> OracleConnect:
        """Open a connection into the slot `_claim` reserved."""
        try:
            Conn = self._open_connection()
        except BaseException:
            with self._available:
                self._opening -= 1
                self._available.notify()
            raise
        with self._available:
            self._opening -= 1
            Closed = self._closed
            if not Closed:
                self._in_use[id(Conn)] = _PoolEntry(Conn)
        if Closed:
            self._discard_dead(Conn)
            raise InterfaceError('pool is closed')
        return Conn

    def _alive(self, entry: _PoolEntry) -> bool:
        """Ping a claimed entry if it is due one. A dead connection gives its
        slot back."""
        if not self._policy.needs_ping(entry, time.monotonic()):
            return True
        try:
            Alive = self._ping(entry.conn)
        except BaseException:
            self._forget(entry.conn)
            raise
        if not Alive:
            self._forget(entry.conn)
            self._discard_dead(entry.conn)
        return Alive

    def _forget(self, conn: OracleConnect) -> None:
        with self._available:
            self._in_use.pop(id(conn), None)
            self._available.notify()

    def _open_connection(self) -> OracleConnect:
        Conn = OracleConnect(**self._connect_kwargs)
        apply_drcp_pool_defaults(Conn, self._drcp_class)
        Conn.connect()
        return Conn

    def _ping(self, conn: OracleConnect) -> bool:
        # `SELECT 1 FROM DUAL` is the cheapest round-trip that confirms
        # the session is still good — any kind of broken socket or
        # killed-session state shows up here.
        try:
            Cur = conn.cursor()
            try:
                Cur.execute('SELECT 1 FROM DUAL')
                Cur.fetchone()
            finally:
                try:
                    Cur.close()
                except Exception:
                    # Best-effort: the ping already has its result; a failed
                    # cursor close must not mask it.
                    pass
            return True
        except Exception:
            return False

    def _discard_dead(self, conn: OracleConnect) -> None:
        try:
            conn.close()
        except Exception:
            # The connection is already known to be dead; closing it is
            # purely best-effort cleanup.
            pass

    def _discard_all(self, conns: list[OracleConnect]) -> None:
        for Conn in conns:
            self._discard_dead(Conn)
