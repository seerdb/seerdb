# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Non-I/O cursor logic shared by the sync and async cursors (#553).

`Cursor` (sync) and `AsyncCursor` (async) duplicate a body of methods whose
logic contains no ``await`` and touches no socket — the DB-API accessor
properties, bind-variable / batch-error helpers, and the buffered (client-side)
scroll bookkeeping. `_CursorLogic` holds that shared logic; both concrete cursor
classes inherit it, so a single definition serves both and the sync/async parity
holds by construction. The genuinely I/O-bound methods (execute, fetch*, the
server-side scroll path, close, iteration) stay per-class.

The shared ``__init__`` establishes the cursor state the concrete I/O methods
read and write.
"""

from __future__ import annotations

from seerdb.client.defaults import defaults
from seerdb.client.typehandlers import build_fetch_plan
from seerdb.common.datatypes import Var
from seerdb.common.exceptions import (
    NotSupportedError,
    ProgrammingError,
    from_ora_code,
)
from seerdb.common.exceptions import (
    Warning as DbWarning,
)
from seerdb.common.sqltext import bind_placeholders, is_plsql


def _declared_bind(declared: object, value: object) -> Var:
    # One bind whose type was declared rather than deduced. An integer declares a
    # string of that size, which is what PEP 249's "size" means and what
    # python-oracledb does with one; anything else is a type as `var()` takes it.
    if isinstance(declared, int) and not isinstance(declared, bool):
        variable = Var(str, declared)
    else:
        variable = Var(declared)
    if value is not None:
        variable.setvalue(0, value)
    return variable


def _bound_like(template: Var, value: object) -> Var:
    # A further row's bind through the variable an input type handler returned
    # for the first: the same type, size and inconverter (#2458).
    variable = Var(
        template._pytype or template.dbtype,
        template.size,
        inconverter=template.inconverter,
    )
    variable.setvalue(0, value)
    return variable


def _touched_rowid(rowid: str | None, rowcount: object) -> str | None:
    """The ``lastrowid`` a DML / DDL reply reports (#1078).

    A statement that affected no rows touched no row, so it has no rowid,
    whatever the status token carries. The token can echo an earlier row: after
    a SELECT on the same cursor, 23ai's reply to a DELETE that matched nothing
    carried the rowid of the row the SELECT had fetched. python-oracledb reports
    None there, and its suite asserts it (test_4321).
    """
    if isinstance(rowcount, int) and rowcount == 0:
        return None
    return rowid


class _CursorLogic:
    """Shared non-I/O logic for `Cursor` / `AsyncCursor` (#553)."""

    # The default number of rows fetchmany() returns and a scrollable cursor
    # refills per batch — 100, matching oracledb (oracledb.defaults.arraysize). A
    # bare fetchmany() then returns up to 100 rows as it does under oracledb, not 1.
    # (The wire prefetch for a normal cursor is the connection's `fetch`, separate
    # from this.)
    arraysize: int = 100
    # Rows the server prefetches on a scrollable open (oracledb's prefetchrows
    # default). Kept small so the open does not drain the cursor to EOF, which
    # would break the subsequent scroll re-execute (#181).
    prefetchrows: int = 2

    def __init__(self, connection, scrollable: bool = False):
        self._connection = connection
        self._description: list[tuple] | None = None
        self._annotations: list[dict | None] | None = None
        self._rows: list[list] = []
        self._row_index: int = 0
        self._rowcount: int = -1
        self._closed: bool = False
        self._lastrowid: str | None = None
        # The bind directions the last PL/SQL execute's IOV reported, one per
        # bind (16 OUT, 32 IN, 48 IN OUT), or None when the last statement was
        # not a block. The wire carries no direction on the way IN, so this is
        # the only place a caller can learn what the server decided -- which the
        # Mirror's passthrough forwards so its own client is told the truth
        # rather than "everything is OUT" (#1064).
        self._bind_directions: list[int] | None = None
        self._rowfactory = None
        # The warning the last execute reported, or None (#993). A condition the
        # server raises alongside a call that SUCCEEDED -- a PL/SQL object
        # created with compilation errors -- so it is an attribute, never
        # raised. Present from construction: a caller may read it before any
        # execute has run.
        self.warning: DbWarning | None = None
        # Scrollable cursor. With scrollable=True a SELECT is fetched lazily from
        # a kept-open server cursor: scroll() repositions server-side and
        # fetchone/many pull batches on demand (#181). With scrollable=False the
        # whole result set is buffered on execute and scroll() is a local
        # reposition (#161) — kept for backwards compatibility.
        self._scrollable = bool(scrollable)
        # Server-side scroll state (only used when scrollable and a SELECT is
        # open). _scroll_active gates the lazy path; the buffer window spans
        # absolute rows [_scroll_buf_min, _scroll_buf_max), and _scroll_consumed
        # is the absolute row number of the last row returned (oracledb's
        # rowcount), used to compute relative-scroll targets.
        self._scroll_active: bool = False
        self._scroll_cursor_id: int = 0
        self._scroll_rowformat: list | None = None
        self._scroll_buf_min: int = 0
        self._scroll_buf_max: int = 0
        self._scroll_consumed: int = 0
        self._scroll_eof: bool = False
        # Pending implicit result sets (#121): (row_format, cursor_id) queue
        # left by a DBMS_SQL.RETURN_RESULT block, consumed via nextset().
        self._implicit_results: list = []
        # Bind types declared by setinputsizes for the next execute (#696), as
        # (positional, by name). Cleared once that execute has used them.
        self._inputsizes: tuple[tuple, dict] = ((), {})
        # seerdb.defaults, read as the cursor is opened (#2458).
        self.arraysize = defaults.arraysize
        self.prefetchrows = defaults.prefetchrows
        # The type handlers (#2458); None defers to the connection's.
        self.outputtypehandler = None
        self.inputtypehandler = None
        # Set while a block's executemany runs its rows one by one (#2479), whose
        # binds the handler has already seen as one batch.
        self._binds_handled = False
        # The per-column plan the handler and fetch_decimals made for the
        # current result set, applied as each row is fetched; None when no
        # column needs one. fetch_decimals as the last execute had it.
        self._fetch_plan: list | None = None
        self._fetch_decimals: bool = defaults.fetch_decimals

    def _handled_binds(
        self, Bind: list, Batch: list | None
    ) -> tuple[list, list | None]:
        """Bind and Batch with the input type handler applied (#2458).

        The handler, the cursor's else the connection's, is called once per bind
        position that isn't already a Var -- one the caller made, or one
        setinputsizes declared -- with the first row's value and the number of
        rows, as python-oracledb calls it. A Var it returns binds that position
        in every row: each row's value goes through its inconverter and must
        then fit its type."""
        if self._binds_handled:
            # A block's executemany already ran the handler over its batch.
            return Bind, Batch
        Handler = self.inputtypehandler
        if Handler is None:
            Handler = getattr(self._connection, 'inputtypehandler', None)
        if Handler is None or not Bind:
            return Bind, Batch
        Rows = [Bind] + list(Batch or [])
        Out = [list(Row) for Row in Rows]
        for Index, Value in enumerate(Bind):
            if isinstance(Value, Var):
                continue
            Template = Handler(self, Value, len(Rows))
            if Template is None:
                continue
            if not isinstance(Template, Var):
                raise ProgrammingError(
                    'an input type handler must return None or a variable from '
                    f'cursor.var(), not {type(Template).__name__}'
                )
            Template.setvalue(0, Value)
            Out[0][Index] = Template
            for Row in Out[1:]:
                if Index < len(Row) and not isinstance(Row[Index], Var):
                    Row[Index] = _bound_like(Template, Row[Index])
        return Out[0], (Out[1:] if Batch else Batch)

    def _plan_fetch(self) -> None:
        # Called wherever a new result set is described (#2458). A handler that
        # raises, or a conversion that is refused, leaves no result set behind:
        # the statement failed as far as the caller is concerned.
        if self._description is None:
            self._fetch_plan = None
            return
        try:
            self._fetch_plan = build_fetch_plan(
                self, self._description, self._fetch_decimals
            )
        except BaseException:
            self._fetch_plan = None
            self._description = None
            self._annotations = None
            self._rows = []
            raise

    def _fetch_decimals_for(self, fetch_decimals: bool | None) -> None:
        # An execute's fetch_decimals, else seerdb.defaults'.
        self._fetch_decimals = (
            defaults.fetch_decimals if fetch_decimals is None else bool(fetch_decimals)
        )

    @property
    def scrollable(self) -> bool:
        """Whether this cursor was opened scrollable (#161). seerdb's
        result-set buffer makes scroll() available on any cursor, so this is
        primarily for oracledb API compatibility."""
        return self._scrollable

    @scrollable.setter
    def scrollable(self, value: bool) -> None:
        self._scrollable = bool(value)

    @property
    def description(self) -> list[tuple] | None:
        return self._description

    @property
    def bind_directions(self) -> list[int] | None:
        """The bind directions the last PL/SQL block's reply reported (#1064).

        One per bind -- 16 OUT, 32 IN, 48 IN OUT -- or None when the last
        statement was not a block, or carried no binds. A server reports these
        only on the way back, so nothing else in the API can tell an IN bind
        from an OUT one."""
        return self._bind_directions

    @property
    def annotations(self) -> list[dict | None] | None:
        """Per-column SQL annotations (23ai) for the last SELECT, aligned with
        `description`: a list with one entry per column — a `{name: value}` dict
        for an annotated column (value is '' for a name-only annotation) or
        `None` for a column with no annotations. `None` overall when the last
        statement produced no result set or the server is pre-23ai."""
        return self._annotations

    @property
    def rowcount(self) -> int:
        # For a lazy server-side scrollable cursor, rowcount tracks the number of
        # rows consumed so far (the absolute position of the last row returned),
        # matching oracledb; otherwise it is the buffered result-set size / DML
        # affected-row count.
        if self._scroll_active:
            return self._scroll_consumed
        return self._rowcount

    @property
    def connection(self):
        return self._connection

    @property
    def rowfactory(self):
        """Optional callable applied to each fetched row. It is called with the
        row's column values as positional arguments (oracledb semantics), e.g.
        `cur.rowfactory = lambda *a: dict(zip([c[0] for c in cur.description], a))`.
        None (the default) yields plain tuples."""
        return self._rowfactory

    @rowfactory.setter
    def rowfactory(self, value) -> None:
        self._rowfactory = value

    @property
    def lastrowid(self):
        """ROWID (string) of the last row an INSERT / UPDATE / DELETE touched,
        or None when the last statement produced no rowid (SELECT, DDL, or a
        multi-row/zero-row change). PEP 249 optional attribute."""
        return self._lastrowid

    def var(
        self,
        typ,
        size=None,
        arraysize: int = 1,
        inconverter=None,
        outconverter=None,
        typename: str | None = None,
        encoding_errors: str | None = None,
        bypass_decode: bool = False,
        convert_nulls: bool = False,
    ) -> Var:
        """Create a bind variable that can receive an OUT / IN OUT value.

        `typ` is a Python type (`int`, `str`, `bytes`, `datetime`, ...) or an
        `seerdb` type constant (`seerdb.NUMBER`, `seerdb.STRING`,
        `seerdb.DB_TYPE_*`). Pass the returned `Var` in a `callproc` /
        `execute` parameter list and read the result with `getvalue()`, or
        return it from an `outputtypehandler` to say what a fetched column
        becomes (#2458).

        The rest are python-oracledb's: `arraysize` (reported as
        `num_elements`), `inconverter` (applied to a value set on it),
        `outconverter` (applied to each value fetched into it, and to NULL too
        with `convert_nulls`). `typename`, `encoding_errors` and
        `bypass_decode` are refused, not ignored, since seerdb doesn't act on
        them.
        """
        if typename is not None:
            raise NotSupportedError(
                'var(typename=...) is not supported; pass the type from '
                'connection.gettype() as typ'
            )
        if encoding_errors is not None or bypass_decode:
            raise NotSupportedError(
                'var(encoding_errors=..., bypass_decode=...) is not supported'
            )
        V = Var(
            typ,
            size,
            num_elements=max(int(arraysize), 1),
            inconverter=inconverter,
            outconverter=outconverter,
            convert_nulls=convert_nulls,
        )
        return V

    def getbatcherrors(self) -> list:
        """Errors collected by the most recent ``executemany(batcherrors=True)``.

        Returns a list of ``DatabaseError`` objects, one per failed row, each
        carrying ``.offset`` (the 0-based row index in the batch), ``.code``
        (the ORA number) and the message. Empty if the last statement had no
        batch errors. oracledb-compatible.
        """
        Out = []
        for E in getattr(self, '_batcherrors', []):
            Code = E.get('code')
            Exc = from_ora_code(Code)(E.get('message') or f'ORA-{Code:05d}', code=Code)
            Exc.offset = E.get('offset')
            Out.append(Exc)
        return Out

    def getarraydmlrowcounts(self) -> list:
        """Per-iteration row counts from the most recent
        ``executemany(arraydmlrowcounts=True)``.

        Returns a list of ints, one per row in the batch, giving how many rows
        that iteration affected (e.g. an UPDATE matching 3 rows yields 3).
        Empty if the last statement didn't request row counts. Requires a 12.1+
        server. oracledb-compatible.
        """
        return list(getattr(self, '_arraydmlrowcounts', []))

    def _init_scroll_window(
        self, cursor_id: int, colmeta: list, server_rowcount, batch_len: int, eof: bool
    ) -> None:
        # Arm the lazy server-side scroll path after a scrollable open.
        self._scroll_active = True
        self._scroll_cursor_id = cursor_id
        self._scroll_rowformat = colmeta
        self._scroll_set_window(server_rowcount, batch_len)
        self._scroll_eof = eof

    def _scroll_set_window(self, server_rowcount, batch_len: int) -> None:
        # Place the buffer window from the server's cumulative rowcount (the
        # absolute 1-based row number of the last row in the batch) and the batch
        # size, mirroring oracledb's _post_process_scroll. _scroll_consumed is
        # the absolute position of the last row already returned to the caller.
        if batch_len <= 0:
            self._scroll_buf_min = self._scroll_buf_max = 0
            self._scroll_consumed = 0
            self._row_index = 0
            return
        Srv = server_rowcount if isinstance(server_rowcount, int) else batch_len
        self._scroll_buf_min = Srv - batch_len + 1
        self._scroll_buf_max = self._scroll_buf_min + batch_len
        self._scroll_consumed = self._scroll_buf_min - 1
        self._row_index = 0

    def _scroll_buffered(self, value: int, mode: str) -> None:
        # #161 fallback: the whole result set is in self._rows, so scroll() is a
        # local index move. Used for non-scrollable cursors.
        Count = len(self._rows)
        if mode == 'relative':
            Target = self._row_index + value
        elif mode == 'absolute':
            Target = value
        elif mode == 'first':
            Target = 1
        elif mode == 'last':
            Target = Count
        else:
            raise ProgrammingError(f'invalid scroll mode: {mode!r}')
        if Target < 1 or Target > Count:
            raise IndexError('scroll operation would leave the result set')
        self._row_index = Target - 1

    def setinputsizes(self, *args, **kwargs) -> None:
        """Declare the type of one or more binds for the next execute.

        A bind's type is normally read off the value, which works until the
        value cannot say what it is: a `None` carries no type, the server infers
        CHAR, and comparing that to a DATE or a NUMBER column is refused with
        ORA-00932. Declaring the type here is the way to say what the value
        cannot (#696).

        Positional arguments name the placeholders in order, one each, with
        `None` to leave one alone; keyword arguments name them by bind name.
        Each is a type as `var()` takes it — a Python type or an `seerdb.*`
        constant — or an integer, which sizes a string bind. Matches
        python-oracledb.

        The declaration applies to the next `execute` or `executemany` and is
        forgotten afterwards, as PEP 249 specifies. Calling it with no arguments
        discards a pending one.
        """
        self._inputsizes = (tuple(args), dict(kwargs))

    def _typed_binds(self, SQL: str, Bind: list) -> list:
        # Apply a pending setinputsizes to a resolved bind list, by wrapping each
        # declared position in a Var of that type. A Var's OAC announces its
        # declared type rather than guessing from the value, which is the whole
        # point; its row data is the value itself, so an ordinary IN bind still
        # sends exactly what it did before (#696).
        (positional, named) = self._inputsizes
        if not positional and not named:
            return Bind
        wanted: dict[int, object] = {}
        for index, declared in enumerate(positional):
            if declared is not None and index < len(Bind):
                wanted[index] = declared
        if named:
            # Placeholder names in the order the values were resolved into, so a
            # name maps to the same position the value took.
            names = [
                name for name, _quoted in bind_placeholders(SQL, dedupe=is_plsql(SQL))
            ]
            for index, name in enumerate(names):
                declared = named.get(name) or named.get(name.lower())
                if declared is not None and index < len(Bind):
                    wanted[index] = declared
        if not wanted:
            return Bind
        Out = list(Bind)
        for index, declared in wanted.items():
            value = Out[index]
            if isinstance(value, Var):
                continue  # already carries its own declared type
            Out[index] = _declared_bind(declared, value)
        return Out

    def setoutputsize(self, size, column=None) -> None:
        pass
