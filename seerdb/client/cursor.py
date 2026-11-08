# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import re
from typing import Any

from seerdb.client._conn_logic import temp_lobs_available
from seerdb.client._cursor_logic import _CursorLogic, _touched_rowid
from seerdb.client.typehandlers import apply_fetch_plan, lob_columns
from seerdb.common.datatypes import (
    _DATE_TNS_TYPES,
    _NUMBER_TNS_TYPES,
    DB_TYPE_OBJECT,
    DB_TYPE_XMLTYPE,
    BfileBind,
    RefCursorBind,
    TempLob,
    Var,
    dbtype_for_oracle_type,
)
from seerdb.common.exceptions import (
    DatabaseError,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
    compilation_warning,
    from_ora_code,
)
from seerdb.common.sqltext import (
    bind_placeholders,
    canonical_bind_key,
    is_plsql,
    returning_bind_positions,
    strip_non_bind_text,
)
from seerdb.common.tns import _object_bind_type, is_prefixed_locator
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    FIELD_VERSION_10_2,
    FIELD_VERSION_12_1,
    ORA_ARRAY_DML_ERRORS,
    ORA_NO_DATA_FOUND,
    TNS_FETCH_ORIENTATION_ABSOLUTE,
    TNS_FETCH_ORIENTATION_CURRENT,
    TNS_FETCH_ORIENTATION_FIRST,
    TNS_FETCH_ORIENTATION_LAST,
    TNS_FETCH_ORIENTATION_RELATIVE,
    TNS_OER_WARN_COMPILATION_ERROR,
    TNS_TYPE_ADT,
    TNS_TYPE_BFILE,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_JSON,
    TNS_TYPE_RAW,
    TNS_TYPE_RID,
    TNS_TYPE_UROWID,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
    UTF8_CHARSET,
    VECTOR_FLAG_FLEXIBLE_DIM,
)
from seerdb.common.vector import is_vector_bind

# `RETURNING col BULK COLLECT INTO :x` -- the bulk form of the clause.
_BULK_COLLECT_RE = re.compile(r'\bBULK\s+COLLECT\b', re.I)


class cursor(RefCursorBind):
    # Sentinel passed as a bind value to indicate a REFCURSOR slot. Consumed by
    # the encoder in seerdb.common.tns (encode_token_oac / encode_token_rxd),
    # which detects it via the RefCursorBind base so common never imports the
    # client. Kept lowercase for backwards-compatibility with existing call sites.
    id: int = 0


class Cursor(_CursorLogic):
    # PEP 249 DB-API 2.0 cursor. Wraps OracleConnect.execute and presents the
    # standard fetchone/fetchmany/fetchall surface. Backwards-compatibility
    # note: the raw 5-tuple result format produced by OracleConnect.execute
    # is still available for callers that prefer it.

    # Rows the server prefetches on a scrollable open (oracledb's prefetchrows
    # default). Kept small so the open does not drain the cursor to EOF, which
    # would break the subsequent scroll re-execute (#181).
    def _check_open(self) -> None:
        if self._closed:
            raise InterfaceError('cursor is closed')
        if self._connection is None or self._connection.sock is None:
            raise InterfaceError('connection is closed')

    def close(self) -> None:
        self._release_scroll_cursor()
        self._closed = True
        self._description = None
        self._annotations = None
        self._rows = []
        self._row_index = 0

    def _release_scroll_cursor(self) -> None:
        # Queue the kept-open server-side scrollable cursor for close (#181). It
        # was deliberately not drained or queued on the open, so it lingers until
        # the cursor is closed or re-executed; reuse the #191 close-piggyback
        # queue so it rides the next call rather than a dedicated round trip.
        if self._scroll_active and self._scroll_cursor_id:
            Conn = self._connection
            if Conn is not None and getattr(Conn, 'sock', None) is not None:
                try:
                    Conn._close_cursor_later(self._scroll_cursor_id)
                except Exception:
                    # Best-effort cleanup: queueing the cursor for close is an
                    # optimisation, not correctness — if the connection is mid
                    # teardown the server frees it on session end anyway.
                    pass
        self._scroll_active = False
        self._scroll_cursor_id = 0

    def execute(
        self, operation: str, parameters=None, *, fetch_decimals: bool | None = None
    ) -> 'Cursor':
        self._check_open()
        self._fetch_decimals_for(fetch_decimals)
        # Re-executing frees any cursor left open by a prior scrollable SELECT.
        self._release_scroll_cursor()
        Bind = _bind_temp_lobs(
            _resolve_parameters(operation, parameters), self._connection
        )
        Bind = self._resolve_cursor_binds(Bind)
        Bind = self._promote_large_lob_binds(operation, Bind)
        Bind = _with_object_bind_lobs(
            Bind,
            [
                [self._connection.createlob(T, C) for T, C in Pending]
                for Pending in _object_bind_lob_values(Bind)
            ],
        )
        return self._run(operation, Bind)

    def parse(self, operation: str) -> None:
        """Parse ``operation`` on the server without running it (#1018).

        The statement is validated — syntax, object names, bind-variable names —
        and nothing else happens: no rows change, no query runs. A statement
        that will not parse raises the server's error, which is the point of the
        call. A query also comes back described, so ``description`` is populated
        for a SELECT and cleared for anything else.

        This is python-oracledb's ``Cursor.parse``, an extension to DB-API 2.0.
        Not available on the pre-10g tiers, whose request dialects have no
        parse-without-execute shape.
        """
        self._check_open()
        self._release_scroll_cursor()
        Result = self._connection.execute(operation, ParseOnly=True)
        self._apply_result([], Result)

    def _resolve_cursor_binds(self, Bind: list) -> list:
        """Turn an open ``Cursor`` bind into the REF CURSOR sentinel (#1047).

        `cursor.execute(plsql, rcursor=other_cursor)` hands a PL/SQL block a
        cursor the server already has, declared there as a plain
        ``sys_refcursor`` IN parameter; the block fetches from it, and may close
        it. python-oracledb takes the cursor object itself, so this does too.

        What travels is the server-side cursor **id**, so the cursor has to
        still be open on the server with its rows unread. A cursor whose rows
        this driver already drained is closed as far as the block is concerned,
        and the server says so — ``ORA-01007``, a reference to a variable not in
        the SELECT — so it is refused here with a reason instead.
        """
        if not Bind:
            return Bind
        Out: list = []
        for Value in Bind:
            if not isinstance(Value, Cursor):
                Out.append(Value)
                continue
            CursorId = Value._scroll_cursor_id if Value._scroll_active else 0
            if not CursorId:
                raise NotSupportedError(
                    'binding a cursor as a REF CURSOR parameter needs one that '
                    'is still open on the server with its rows unread; open it '
                    'with connection.cursor(scrollable=True) so the driver '
                    'leaves it open rather than draining it'
                )
            Sentinel = cursor()
            Sentinel.id = CursorId
            Out.append(Sentinel)
        return Out

    def _promote_large_lob_binds(self, operation: str, Bind: list) -> list:
        # Large CLOB / BLOB into a PL/SQL locator param (#91): a str / bytes
        # bind over the 32767-byte PL/SQL VARCHAR2 / RAW limit can't go through
        # the streamed path (ORA-01460). Stream it into a server temp LOB and
        # bind the locator instead. Only for PL/SQL blocks (plain DML keeps the
        # streamed-LONG path) and only where a temp LOB can be made: 12c+, and a
        # pooled 11g session in the native form (#2466); 11g's converted form
        # rejects CREATE_TEMP.
        Conn = self._connection
        if not temp_lobs_available(Conn) or not is_plsql(operation) or not Bind:
            return Bind
        Promoted = []
        for Value in Bind:
            if isinstance(Value, str) and len(Value.encode('utf-8')) > 32767:
                Locator = Conn.create_temp_lob()
                Conn.write_temp_lob(Locator, Value)
                Promoted.append(TempLob(Locator, False))
            elif isinstance(Value, (bytes, bytearray)) and len(Value) > 32767:
                Locator = Conn.create_temp_lob(is_blob=True)
                Conn.write_temp_lob(Locator, bytes(Value), is_blob=True)
                Promoted.append(TempLob(Locator, True))
            else:
                Promoted.append(Value)
        return Promoted

    def _promote_lob_var_binds(self, Bind: list) -> list:
        # A CLOB / BLOB bound through a Var (cursor.var / setinputsizes) has no
        # inline wire form -- its value rides as a temp-LOB locator, the way
        # python-oracledb's createlob does (#902). Promote each such Var's
        # non-NULL value to a server temp LOB and bind that; a NULL Var (a pure
        # OUT, or a NULL IN bind) keeps its typed form, which now carries the LOB
        # bind OAC. 12c+ only, and a pooled 11g session (#2466): 11g's converted form
        # has no CREATE_TEMP, so an 11g Var(CLOB) there keeps its
        # prior behaviour.
        Conn = self._connection
        if not temp_lobs_available(Conn) or not Bind:
            return Bind
        Out: list = []
        for V in Bind:
            if (
                isinstance(V, Var)
                and not V.is_array
                and V.dbtype.tns_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB)
                and V._value is not None
            ):
                IsBlob = V.dbtype.tns_type == TNS_TYPE_BLOB
                Locator = Conn.create_temp_lob(is_blob=IsBlob)
                Payload = (
                    bytes(V._value)
                    if isinstance(V._value, (bytes, bytearray))
                    else str(V._value)
                )
                # An empty value writes nothing -- an empty temp LOB is a
                # non-NULL, zero-length LOB (#903).
                if Payload:
                    Conn.write_temp_lob(Locator, Payload, is_blob=IsBlob)
                # Carry the Var on the marker: the bind list is what the IOV
                # decoder types the response against, and what the OUT value is
                # assigned back through, so replacing the Var outright left an
                # IN OUT LOB bind with neither (#978).
                Out.append(TempLob(Locator, IsBlob, V))
            else:
                Out.append(V)
        return Out

    def _run(
        self,
        operation: str,
        Bind: list,
        Batch: list | None = None,
        BatchErrors: bool = False,
        ArrayDmlRowCounts: bool = False,
    ) -> 'Cursor':
        # A pending setinputsizes types the binds it names before anything else
        # looks at them, and is spent by this execute (#696).
        Bind = self._typed_binds(operation, Bind)
        if Batch:
            Batch = [self._typed_binds(operation, Row) for Row in Batch]
        # Then the input type handler, for each bind still untyped (#2458).
        (Bind, Batch) = self._handled_binds(Bind, Batch)
        # A declared CLOB / BLOB value goes as a temporary LOB, every row of an
        # executemany too, as python-oracledb makes one for each (#902).
        Bind = self._promote_lob_var_binds(Bind)
        if Batch:
            Batch = [self._promote_lob_var_binds(Row) for Row in Batch]
        self._inputsizes = ((), {})
        _check_object_bind_support(self._connection, Bind, Batch)
        Kw: dict[str, Any] = {
            'Bind': Bind,
            'Batch': Batch,
            'BatchErrors': BatchErrors,
            'ArrayDmlRowCounts': ArrayDmlRowCounts,
        }
        ReturnBinds = returning_bind_positions(operation, len(Bind or []))
        _check_returning_support(self._connection, ReturnBinds, operation)
        if ReturnBinds:  # DML RETURNING ... INTO (#120)
            Kw['ReturnBinds'] = ReturnBinds
        # Server-side scrollable open (#181): mark the cursor scrollable and cap
        # the open's prefetch to prefetchrows so it stays mid-stream. Gated to
        # 10g+ (the OALL8 path); 9i (fv2) speaks the TTI_ALL7 dialect and falls
        # back to the buffered scroll (#161).
        if self._scrollable and self._connection.field_version >= FIELD_VERSION_10_2:
            Kw['scrollable'] = True
            # 0 is a real answer, not a missing one: it opens the cursor and
            # reads NOTHING, which is what binding it into a PL/SQL block needs
            # (the block fetches from row one) and what python-oracledb's
            # prefetchrows=0 means. Clamping it to 1 silently consumed a row,
            # so the block resumed one row late (#1048).
            Kw['Prefetch'] = max(int(self.prefetchrows), 0)
        Result = self._connection.execute(operation, **Kw)
        return self._apply_result(Bind, Result, BatchErrors=BatchErrors)

    def _apply_result(self, Bind: list, Result, BatchErrors: bool = False) -> 'Cursor':
        # Interpret a decoded execute Result tuple into this cursor's rows /
        # rowcount / description / OUT binds. Split out of _run (#158) so the
        # request pipelining path can reuse the exact post-processing on a
        # response it read out-of-band, without re-sending the request.
        # Wire result tuple from decode_token_oer:
        #   (call_status, oracle_error_code, cursor_id, (rowcount, col_meta),
        #    rows, message_or_none, last_rowid, batch_errors, row_counts,
        #    error_offset)
        # The trailing slots were added incrementally; tolerate a shorter shape
        # so a stale build doesn't crash here.
        try:
            OraCode = Result[1]
            RetFormat = Result[3]
            Rows = Result[4]
            Message = Result[5] if len(Result) > 5 else None
            LastRowid = Result[6] if len(Result) > 6 else None
            ErrorOffset = Result[9] if len(Result) > 9 else None
            WarnFlags = Result[10] if len(Result) > 10 else 0
        except (TypeError, IndexError, ValueError) as exc:
            raise DatabaseError(f'unexpected wire response: {Result!r}') from exc

        # `cursor.warning` (#993): a CREATE that produced a PL/SQL object with
        # compilation errors SUCCEEDS -- the object exists, invalid -- and says
        # so only with bit 0x20 of the OER's warn byte. Set here and cleared by
        # the next execute that does not raise it, so a DROP of the same object
        # clears it.
        self.warning = (
            compilation_warning()
            if WarnFlags & TNS_OER_WARN_COMPILATION_ERROR
            else None
        )

        # Array-DML batch errors (#18): each entry is {offset, code, message}.
        self._batcherrors = list(Result[7]) if len(Result) > 7 else []
        # Array-DML per-iteration row counts (#18): list of ints, one per row.
        self._arraydmlrowcounts = (
            list(Result[8]) if len(Result) > 8 and Result[8] else []
        )

        # The column metadata of a result set, if this reply carries one. Read
        # before the error gate below, which needs it to tell an end-of-fetch
        # ORA-01403 from a real one.
        ServerRowCount = None
        ColMeta = None
        if isinstance(RetFormat, tuple) and len(RetFormat) >= 2:
            ServerRowCount = RetFormat[0]
            if isinstance(RetFormat[1], list):
                ColMeta = RetFormat[1]

        # ORA-24381 ("error(s) in array DML") is the summary code the server
        # returns when batcherrors collected per-row failures — not a fatal
        # error. Surface them through getbatcherrors() instead of raising.
        #
        # ORA-01403 is the end-of-fetch sentinel ONLY for a statement that
        # fetches. A `SELECT ... INTO` inside a PL/SQL block that matches no row
        # raises it as a real error, and masking it there turned every such
        # block into a silent success handing back NULL -- the caller's OUT
        # variable simply stayed None (#1039). A query's execute reply carries
        # the column metadata, so its presence is what tells the two apart:
        # nothing can be at the end of a fetch that never had rows to fetch.
        NonFatal: tuple[int, ...] = (0,)
        if ColMeta:
            NonFatal += (ORA_NO_DATA_FOUND,)
        if BatchErrors:
            NonFatal += (ORA_ARRAY_DML_ERRORS,)
        if OraCode not in NonFatal:
            # An executemany whose batch aborts part-way really DID apply the
            # rows before the failing one, and the server reports how many in
            # the same OER field a success reports its own count. Setting it
            # before the raise is what lets a caller read cursor.rowcount in the
            # except block and know what to retry -- it used to read the -1 the
            # cursor was constructed with, or a count left over from an earlier
            # statement, neither of which says anything (#998).
            if isinstance(RetFormat, tuple) and isinstance(RetFormat[0], int):
                self._rowcount = RetFormat[0]
            Detail = Message or f'ORA-{OraCode:05d}'
            Exc = from_ora_code(OraCode)(Detail, code=OraCode)
            # oracledb parity: the 0-based character offset of the error in the
            # statement text, for a parse/bind error (0 when the server reports none).
            Exc.offset = ErrorOffset
            raise Exc

        # PL/SQL OUT / IN OUT binds: write returned values back into any Var
        # objects the caller passed. REF CURSOR OUT binds are fetched here.
        self._bind_directions = _iov_directions(Result)
        for Variable, Marker in _assign_out_binds(Bind, Result, self._connection):
            # 9i's REF CURSOR arrives with its rows already read (#2246).
            Rows = Marker.get('rows')
            if Rows is None:
                Rows = self._connection.fetch_all_rows(
                    Marker['cursor_id'], Marker['row_format']
                )
            Variable._value = _build_refcursor_cursor(self._connection, Rows, Marker)
        _resolve_out_bind_lobs(self._connection, Bind)

        # DML RETURNING ... INTO: write the returned value list onto each Var.
        _assign_return_binds(Bind, Result, self._connection)
        _resolve_return_bind_lobs(self._connection, Bind)

        # Implicit result sets (#121): queue any DBMS_SQL.RETURN_RESULT cursors
        # for nextset() to fetch on demand.
        self._implicit_results = _extract_implicit_results(Result)

        if ColMeta:
            # A result set (SELECT): no "last modified row", so lastrowid is
            # cleared even though the server echoes the last fetched row's rowid
            # in the OER.
            self._lastrowid = None
            self._description = [_column_description(C) for C in ColMeta]
            self._annotations = [_col_annotations(C) for C in ColMeta]
            self._plan_fetch()
            self._rows = [
                _resolve_nested_cursors(
                    self._connection,
                    _resolve_objects(
                        self._connection, _resolve_lobs(self._connection, row)
                    ),
                )
                for row in (Rows or [])
            ]
            # For SELECT, the OER's success-iters value is the per-call fetch
            # count, not the total result set size; len(rows) is the answer
            # callers expect from cursor.rowcount.
            self._rowcount = len(self._rows)
            if (
                self._scrollable
                and self._connection.field_version >= FIELD_VERSION_10_2
            ):
                # Server-side scrollable open (#181): the cursor stays open and
                # this Result holds only the first prefetched batch. Record the
                # window so scroll()/fetchone can reposition + pull more lazily.
                # Gated to 10g+ to match _run; on 9i the open drained and scroll
                # stays buffered (#161).
                CursorId = (
                    Result[2] if len(Result) > 2 and isinstance(Result[2], int) else 0
                )
                self._init_scroll_window(
                    CursorId,
                    ColMeta,
                    ServerRowCount,
                    len(self._rows),
                    OraCode == ORA_NO_DATA_FOUND,
                )
        else:
            # DDL / DML / non-result-set statement. OER carries the affected
            # row count in its success-iters field; surface it, along with the
            # touched-row rowid (None for DDL / zero-row changes).
            self._lastrowid = _touched_rowid(LastRowid, ServerRowCount)
            self._description = None
            self._annotations = None
            self._fetch_plan = None
            self._rows = []
            self._rowcount = ServerRowCount if isinstance(ServerRowCount, int) else -1

        self._row_index = 0
        return self

    def arrayvar(self, typ, value_or_numelements, size=None) -> Var:
        """Create a bulk-array bind for a PL/SQL associative array (index-by
        table) parameter (#122, oracledb-compatible).

        `typ` is the element type. The second argument is either a list of
        initial element values or an int giving the maximum number of elements.
        Pass the returned `Var` for an IN / OUT / IN OUT array argument and read
        the result list with `getvalue()`.
        """
        if isinstance(value_or_numelements, int):
            num = value_or_numelements
            values = []
        else:
            values = list(value_or_numelements)
            num = len(values)
        var = Var(typ, size, is_array=True, num_elements=max(num, 1))
        var._value = values
        var.has_value = bool(values)
        return var

    def callproc(self, name: str, parameters=None) -> list:
        """Call a stored procedure. `parameters` is a positional list of plain
        values (IN) and `Var` objects (OUT / IN OUT). Returns the parameter
        list with each `Var` replaced by its returned value (PEP 249 / oracledb
        compatible).
        """
        self._check_open()
        Params = list(parameters) if parameters else []
        Placeholders = ', '.join(f':{I + 1}' for I in range(len(Params)))
        self.execute(f'BEGIN {name}({Placeholders}); END;', Params)
        return [P.getvalue() if isinstance(P, Var) else P for P in Params]

    def callfunc(self, name: str, return_type, parameters=None):
        """Call a stored function and return its value. `return_type` is a
        Python type or `seerdb` type constant (as for `var`); `parameters`
        are the function's arguments (plain values for IN, `Var` for OUT /
        IN OUT). PEP 249 / oracledb compatible.
        """
        self._check_open()
        Ret = Var(return_type)
        Params = list(parameters) if parameters else []
        # :1 is the return value; arguments are :2, :3, ...
        Args = ', '.join(f':{I + 2}' for I in range(len(Params)))
        self.execute(f'BEGIN :1 := {name}({Args}); END;', [Ret] + Params)
        return Ret.getvalue()

    def executemany(
        self,
        operation: str,
        seq_of_parameters,
        batcherrors: bool = False,
        arraydmlrowcounts: bool = False,
    ) -> 'Cursor':
        # Array DML: bind every row's values and execute them in a single
        # server round trip (one parse, `len(rows)` iterations) rather than
        # one execute() per row. Column types are taken from the first row.
        #
        # With `batcherrors=True` a per-row error (e.g. a unique-constraint
        # violation) no longer aborts the batch: the good rows are applied and
        # the failures are collected, retrievable via `getbatcherrors()`
        # (oracledb-compatible). #18.
        #
        # With `arraydmlrowcounts=True` the server returns the number of rows
        # each iteration affected, retrievable via `getarraydmlrowcounts()`.
        # A 12c+ feature; raises on an 11g server (oracledb-compatible). #18.
        self._check_open()
        if arraydmlrowcounts and self._connection.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError('arraydmlrowcounts requires an Oracle 12.1+ server')
        self._batcherrors = []
        self._arraydmlrowcounts = []
        Rows = [
            _bind_temp_lobs(_resolve_parameters(operation, P), self._connection)
            for P in seq_of_parameters
        ]
        if not Rows:
            self._description = None
            self._rows = []
            self._rowcount = 0
            self._row_index = 0
            return self
        if len(Rows) > 1 and is_plsql(operation):
            return self._executemany_block(operation, Rows)
        return self._run(
            operation,
            Rows[0],
            Batch=Rows[1:],
            BatchErrors=batcherrors,
            ArrayDmlRowCounts=arraydmlrowcounts,
        )

    def _executemany_block(self, operation: str, Rows: list) -> 'Cursor':
        # A PL/SQL block's rows, one execute each (#2479). Sent as one array
        # execute on a freshly parsed cursor, the server refuses them --
        # ORA-03146 on 23ai and the session killed after it, the connection
        # dropped on 11g -- since nothing has told it the binds' directions yet.
        # python-oracledb runs the first row alone and the rest as one array
        # re-execute; one execute per row is the same result in more round
        # trips. A pending setinputsizes types every row, and an error carries
        # its row's index as `offset`, as python-oracledb reports it.
        Sizes = self._inputsizes
        # The input type handler sees the whole batch once, as it would for an
        # array execute, so each row arrives already bound through its Var.
        Typed = [self._typed_binds(operation, Row) for Row in Rows]
        (First, Rest) = self._handled_binds(Typed[0], Typed[1:])
        Rows = [First] + list(Rest or [])
        self._binds_handled = True
        try:
            for Offset, Row in enumerate(Rows):
                self._inputsizes = Sizes
                try:
                    self._run(operation, Row)
                except DatabaseError as Exc:
                    self._inputsizes = ((), {})
                    Exc.offset = Offset
                    raise
        finally:
            self._binds_handled = False
        return self

    # --- Server-side scroll window helpers (#181) ---

    def _scroll_refill(self) -> None:
        # Continue a drained scroll buffer with the next batch. oracledb fetches
        # every batch as a positioned scroll re-execute (orient CURRENT at the
        # next absolute row), NOT a plain TTI_FETCH — mixing in a TTI_FETCH
        # desyncs the server's scroll reference and corrupts a later RELATIVE
        # scroll. So continue with CURRENT at consumed + 1 (#181).
        Conn = self._connection
        Size = max(int(self.arraysize), 1)
        Prev = self._rows[-1] if self._rows else None
        Rows, Eof, ServerRowCount = Conn.scroll_fetch(
            self._scroll_cursor_id,
            TNS_FETCH_ORIENTATION_CURRENT,
            self._scroll_consumed + 1,
            self._scroll_rowformat,
            Fetch=Size,
            PrevRow=Prev,
        )
        Batch = [_resolve_objects(Conn, _resolve_lobs(Conn, R)) for R in Rows]
        self._rows = Batch
        # _scroll_set_window resets the window to empty when Batch is empty
        # (off the end), so a later scroll() can't buffer-hit a stale window.
        self._scroll_set_window(ServerRowCount, len(Batch))
        self._scroll_eof = Eof or not Batch

    def fetchone(self) -> tuple | None:
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        if self._row_index >= len(self._rows):
            # Lazy server-side scrollable cursor: pull the next batch on demand.
            if self._scroll_active and not self._scroll_eof:
                self._scroll_refill()
            if self._row_index >= len(self._rows):
                return None
        Row = self._rows[self._row_index]
        self._row_index += 1
        if self._scroll_active:
            self._scroll_consumed = self._scroll_buf_min + self._row_index - 1
        if self._fetch_plan is not None:
            # The output type handler's conversions (#2458), before the
            # rowfactory sees the row, as python-oracledb applies them.
            from seerdb.common.lob import LOB

            Row = list(Row)
            for I in lob_columns(self._fetch_plan):
                if isinstance(Row[I], LOB):
                    Row[I] = Row[I].read()
            Row = apply_fetch_plan(self._fetch_plan, Row)
        if self._rowfactory is not None:
            return self._rowfactory(*Row)
        return tuple(Row)

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        if size is None:
            size = self.arraysize
        Out = []
        for _ in range(max(size, 0)):
            Row = self.fetchone()
            if Row is None:
                break
            Out.append(Row)
        return Out

    def fetchall(self) -> list[tuple]:
        Out = []
        while True:
            Row = self.fetchone()
            if Row is None:
                break
            Out.append(Row)
        return Out

    def fetch_df_all(self):
        """Fetch all remaining rows of the result set as a single
        ``pyarrow.Table`` (column-major), for fast hand-off to pandas / Polars /
        pyarrow (#162, oracledb-compatible). Consumes the rows like fetchall."""
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        from seerdb.client.dataframe import build_table

        Rows = self._rows[self._row_index :]
        self._row_index = len(self._rows)
        return build_table(Rows, self._description)

    def fetch_df_batches(self, size: int | None = None):
        """Yield the result set as ``pyarrow.Table`` batches of ``size`` rows
        (default ``arraysize``), for streaming large results into a DataFrame
        without materialising every row at once (#162)."""
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        from seerdb.client.dataframe import build_table

        if size is None:
            size = self.arraysize
        size = max(int(size), 1)
        while self._row_index < len(self._rows):
            Rows = self._rows[self._row_index : self._row_index + size]
            self._row_index += len(Rows)
            yield build_table(Rows, self._description)

    def nextset(self) -> bool | None:
        """Advance to the next implicit result set (#121, PEP 249).

        A PL/SQL block that calls ``DBMS_SQL.RETURN_RESULT`` returns one or more
        result sets; each ``nextset()`` makes the next one current (its rows
        become fetchable and ``description`` reflects it) and returns ``True``.
        Returns ``None`` when there are no more sets. 12c+.
        """
        self._check_open()
        if not self._implicit_results:
            return None
        RowFormat, CursorId = self._implicit_results.pop(0)
        Rows = self._connection.fetch_all_rows(CursorId, RowFormat)
        self._description = [_column_description(C) for C in RowFormat]
        self._annotations = [_col_annotations(C) for C in RowFormat]
        self._plan_fetch()
        self._rows = [
            _resolve_nested_cursors(
                self._connection,
                _resolve_objects(
                    self._connection, _resolve_lobs(self._connection, Row)
                ),
            )
            for Row in (Rows or [])
        ]
        self._rowcount = len(self._rows)
        self._row_index = 0
        return True

    def scroll(self, value: int = 0, mode: str = 'relative') -> None:
        """Scroll the result-set cursor to a new position (PEP 249 / oracledb
        semantics). `mode` is one of:

        - ``"relative"`` (default): move ``value`` rows from the current
          position (``value`` may be negative).
        - ``"absolute"``: move to the 1-based row number ``value``.
        - ``"first"`` / ``"last"``: move to the first / last row.

        After the call the next ``fetchone()`` returns the row at the new
        position. A target *before* the first row always raises ``IndexError``.

        A target *past the last row* deliberately differs by cursor kind:

        - a **buffered** cursor (``scrollable=False``, and the 9i fallback)
          raises ``IndexError`` — the PEP 249 / oracledb behaviour;
        - a **server-side scrollable** cursor (``scrollable=True``, 10g+) leaves
          the cursor positioned past the end: the next ``fetchone()`` returns
          ``None`` and a later in-range scroll repositions back into the result
          set — like ``file.seek()`` past EOF. This is the better fit for a
          positionable cursor: a ``relative`` scroll into an unknown position
          returns ``None`` rather than forcing a try/except (see README
          §Compatibility).

        With ``scrollable=True`` the reposition happens server-side and rows are
        fetched lazily (#181); otherwise the whole result set is already
        buffered and the reposition is local (#161).
        """
        self._check_open()
        if self._description is None:
            raise InterfaceError('no result set; call execute() with a SELECT first')
        if self._scroll_active:
            return self._scroll_server(value, mode)
        return self._scroll_buffered(value, mode)

    def _scroll_server(self, value: int, mode: str) -> None:
        # #181 server-side scroll: map the mode to a fetch orientation + desired
        # 1-based row, satisfy it from the current buffer when possible, else
        # re-execute the open cursor at the new position (oracledb's
        # _create_scroll_message / _post_process_scroll).
        if mode == 'relative':
            Orientation = TNS_FETCH_ORIENTATION_RELATIVE
            Desired = self._scroll_consumed + value
        elif mode == 'absolute':
            Orientation = TNS_FETCH_ORIENTATION_ABSOLUTE
            Desired = value
        elif mode == 'first':
            Orientation = TNS_FETCH_ORIENTATION_FIRST
            Desired = 1
        elif mode == 'last':
            Orientation = TNS_FETCH_ORIENTATION_LAST
            Desired = 0
        else:
            raise ProgrammingError(f'invalid scroll mode: {mode!r}')
        # A target before the first row leaves the result set (PEP 249); raise
        # locally rather than sending an invalid position to the server.
        if mode in ('relative', 'absolute') and Desired < 1:
            raise IndexError('scroll operation would leave the result set')
        # Buffer hit: the target row is already in the current window — just move
        # the index, no server round trip.
        if mode != 'last' and self._scroll_buf_min <= Desired < self._scroll_buf_max:
            self._row_index = Desired - self._scroll_buf_min
            self._scroll_consumed = Desired - 1
            return
        Conn = self._connection
        Size = max(int(self.arraysize), 1)
        Prev = self._rows[-1] if self._rows else None
        Rows, Eof, ServerRowCount = Conn.scroll_fetch(
            self._scroll_cursor_id,
            Orientation,
            Desired,
            self._scroll_rowformat,
            Fetch=Size,
            PrevRow=Prev,
        )
        Batch = [_resolve_objects(Conn, _resolve_lobs(Conn, R)) for R in Rows]
        if not Batch:
            # Scrolled off the end (oracledb resets the window; the next
            # fetchone returns None).
            self._rows = []
            self._scroll_buf_min = self._scroll_buf_max = 0
            self._scroll_consumed = 0
            self._row_index = 0
            self._scroll_eof = True
            return
        self._rows = Batch
        self._scroll_set_window(ServerRowCount, len(Batch))
        self._scroll_eof = Eof

    def __iter__(self):
        return self

    def __next__(self):
        Row = self.fetchone()
        if Row is None:
            raise StopIteration
        return Row

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def _object_with_lobs(Obj, Connection):
    # A decoded object's LOB attributes are the locators its image carried; make
    # each a LOB on the connection, as a fetched LOB column is -- what the
    # reference client hands back for one (#1260). Anything else passes through.
    from seerdb.common.dbobject import lob_attribute_csfrm, map_object_lobs
    from seerdb.common.lob import LOB

    def Make(Attr, Value):
        if not isinstance(Value, (bytes, bytearray)):
            return Value
        return LOB(
            Attr['data_type'],
            bytes(Value),
            connection=Connection,
            csfrm=lob_attribute_csfrm(Attr),
        )

    return map_object_lobs(Obj, Make)


def _object_bind_lob_values(Bind) -> list[list[tuple[object, object]]]:
    # For each bind, the (LOB type, content) of every LOB attribute of a bound
    # object that holds a str or bytes rather than a LOB, in image order. A
    # server takes nothing but a locator there, so the reference client makes a
    # temporary LOB of each and binds that (captured against 23ai, #1260); the
    # caller does the making, which the async cursor has to await.
    from seerdb.common.datatypes import DB_TYPE_BLOB, DB_TYPE_CLOB, DB_TYPE_NCLOB
    from seerdb.common.dbobject import DbObject, lob_attribute_csfrm, map_object_lobs

    Out: list[list[tuple[object, object]]] = []
    for Value in Bind if isinstance(Bind, list) else []:
        Pending: list[tuple[object, object]] = []

        def Collect(Attr, Content, Pending=Pending):
            if isinstance(Content, (str, bytes, bytearray)):
                if Attr['data_type'] == TNS_TYPE_BLOB:
                    Type = DB_TYPE_BLOB
                elif lob_attribute_csfrm(Attr) == 2:
                    Type = DB_TYPE_NCLOB
                else:
                    Type = DB_TYPE_CLOB
                Pending.append((Type, Content))
            return Content

        if isinstance(Value, DbObject):
            map_object_lobs(Value, Collect)
        Out.append(Pending)
    return Out


def _with_object_bind_lobs(Bind: list, Lobs: list[list]) -> list:
    # The binds with each object that had str / bytes LOB attributes replaced by
    # a copy holding the LOBs made for them, in the order
    # _object_bind_lob_values listed them. The caller's own object is left as it
    # was set.
    from seerdb.common.dbobject import map_object_lobs

    if not isinstance(Bind, list) or not any(Lobs):
        return Bind
    Out = []
    for Value, Made in zip(Bind, Lobs):
        if Made:
            Next = iter(Made)

            def Put(_Attr: dict, Content: object, Next=Next) -> object:
                if isinstance(Content, (str, bytes, bytearray)):
                    return next(Next)
                return Content

            Value = map_object_lobs(Value, Put)
        Out.append(Value)
    return Out


def _object_from_out_image(image, objtype, Connection=None):
    # Build a DbObject of `objtype` from an object OUT bind's ObjectImage (#888).
    # The image decodes against the type's own layout: named attributes for an
    # object, the single element type for a VARRAY / nested table. None (a NULL
    # object OUT) stays None.
    if image is None:
        return None
    from seerdb.common.dbobject import (
        DbObject,
        decode_collection_keyed,
        decode_object_image,
    )

    if getattr(objtype, 'is_collection', False):
        (elements, keys) = decode_collection_keyed(image.image, objtype.element)
        return _object_with_lobs(
            DbObject(objtype.full_name, elements=elements, dbtype=objtype, keys=keys),
            Connection,
        )
    attrs = decode_object_image(image.image, objtype.attrs)
    return _object_with_lobs(
        DbObject(objtype.full_name, attrs, dbtype=objtype), Connection
    )


def _update_object_in_place(Target, Image, Connection=None) -> None:
    # Write an object OUT bind's returned image into the DbObject the CALLER
    # passed, rather than onto a Var (#1029). `cursor.callproc(name, (3, obj))`
    # hands the object over directly and then reads `obj` back -- the object is
    # the caller's handle on the result, exactly as in python-oracledb, so a new
    # DbObject built beside it would leave the caller looking at an empty one.
    Decoded = _object_from_out_image(
        Image, object.__getattribute__(Target, '_dbtype'), Connection
    )
    if Decoded is None:
        # A NULL object OUT: clear the values the caller's object was built
        # with, which are the INPUT half of an IN OUT bind and would otherwise
        # read as a successful no-op. The object keeps its SHAPE -- a record
        # still has its attribute names, all NULL -- because its type did not
        # change, only its contents.
        if Target.is_collection:
            object.__getattribute__(Target, '_elements')[:] = []
            object.__setattr__(Target, '_keys', None)
        else:
            Attrs = object.__getattribute__(Target, '_attrs')
            for Name in object.__getattribute__(Target, '_order'):
                Attrs[Name] = None
        return
    if Target.is_collection:
        object.__getattribute__(Target, '_elements')[:] = list(Decoded)
        # The keys travel with the values: an associative array OUT bind is the
        # one place the caller's object learns keys it did not have, and leaving
        # _keys behind would pair the new values with the old array's keys
        # (#1053).
        object.__setattr__(Target, '_keys', object.__getattribute__(Decoded, '_keys'))
        return
    Attrs = object.__getattribute__(Target, '_attrs')
    for Name in object.__getattribute__(Decoded, '_order'):
        Attrs[Name] = object.__getattribute__(Decoded, '_attrs')[Name]


def _iov_directions(Result) -> list[int] | None:
    # The directions the IOV carried, if this reply was a PL/SQL block's (#1064).
    if not isinstance(Result, tuple) or len(Result) < 5:
        return None
    Rows = Result[4]
    if not Rows or not isinstance(Rows[0], dict):
        return None
    directions = Rows[0].get('directions')
    return list(directions) if directions else None


def _assign_out_binds(Bind, Result, Connection=None) -> list:
    # After a PL/SQL execute, the IOV decoder leaves an {'out_positions',
    # 'out_values', ...} record as the single "row". Decode each scalar OUT
    # value by its Var's declared type and store it on the Var. REF CURSOR OUT
    # values arrive as a marker dict ({'_refcursor', 'cursor_id',
    # 'row_format'}); they need a server fetch to materialise, which differs
    # between the sync and async cursors, so collect and return them as
    # (Var, marker) pairs for the caller to finish.
    if not isinstance(Bind, list) or not isinstance(Result, tuple) or len(Result) < 5:
        return []
    Rows = Result[4]
    if not Rows or not isinstance(Rows[0], dict) or 'out_positions' not in Rows[0]:
        return []
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value

    Record = Rows[0]
    RefCursors = []
    for Pos, Value in zip(Record['out_positions'], Record['out_values']):
        if Pos >= len(Bind):
            continue
        if _object_bind_type(Bind[Pos]) is not None and not isinstance(Bind[Pos], Var):
            # An object passed straight to callproc / execute, with no Var to
            # hold the result -- the caller's own object is where it goes.
            _update_object_in_place(Bind[Pos], Value, Connection)
            continue
        Variable = _bind_var(Bind[Pos])
        if Variable is None:
            continue
        # The Var's charset form has to travel with the type: national (csfrm 2)
        # data arrives as AL16UTF16, and _string_charset keys on exactly this.
        # Without it every NVARCHAR OUT bind -- scalar and array alike -- came
        # back as its raw UTF-16BE bytes read one per character (#991).
        Column = {
            # A ROWID / UROWID Var is bound as a VARCHAR, so its value comes back
            # as that VARCHAR's text, which is the rowid a client uses (#1397).
            'data_type': TNS_TYPE_VARCHAR
            if Variable.dbtype.tns_type in (TNS_TYPE_RID, TNS_TYPE_UROWID)
            else Variable.dbtype.tns_type,
            'charset': UTF8_CHARSET,
            'csfrm': getattr(Variable.dbtype, 'csfrm', 1),
        }
        if isinstance(Value, dict) and Value.get('_refcursor'):
            RefCursors.append((Variable, Value))
            continue
        # The Var now holds a value, so bound again it is an input: 8i decides on
        # this flag, and sent a Var an OUT bind had filled as NULL (#1505).
        Variable.has_value = True
        if isinstance(Value, dict) and Value.get('_array'):
            # Associative-array OUT (#122): decode each element by the Var's
            # type into a Python list.
            Variable._value = [
                decode_value(Column, V if V else None) for V in Value['values']
            ]
        elif isinstance(Value, LOB):
            # A LOB-class OUT value arrives already built by the IOV reader
            # (#978); the connection is attached, and `fetch_lobs` honoured, by
            # the caller's _resolve_out_bind_lobs -- which the async cursor does
            # with an awaited read.
            Variable._value = Value
        elif Variable.dbtype.tns_type == TNS_TYPE_ADT:
            # Object / collection OUT (#888): the IOV decoder handed back an
            # ObjectImage (or None); build a DbObject of the Var's type from it,
            # decoding the image against the type's own attribute / element
            # layout (which the Var's DbObjectType already carries).
            Variable._value = _object_from_out_image(Value, Variable.dbtype, Connection)
        else:
            Variable._value = decode_value(Column, Value if Value else None)
    return RefCursors


def _decode_returned_image(TnsType: int, Raw) -> object:
    # The binary image a JSON / VECTOR return bind carries, decoded to a Python
    # value. An empty / missing image is a NULL returned value (#826).
    if not Raw:
        return None
    if TnsType == TNS_TYPE_JSON:
        from seerdb.common.oson import decode_oson

        return decode_oson(bytes(Raw))
    from seerdb.common.vector import decode_vector

    return decode_vector(bytes(Raw))


def _decode_returned_object(Typ: object, Image: object, Connection=None) -> object:
    # The object image an ADT return bind carries, walked into a DbObject with
    # the layout the Var was declared with. A returning Var is created from the
    # type itself (`cursor.var(conn.gettype(...))`), and `_resolve_dbtype` keeps
    # that DbObjectType as the Var's dbtype, so the layout is already in hand --
    # unlike a fetched COLUMN, which has to look the type up from the describe
    # (#826).
    from seerdb.common.dbobject import (
        DbObject,
        DbObjectType,
        ObjectImage,
        decode_collection_keyed,
        decode_object_image,
    )

    if not isinstance(Image, ObjectImage) or not Image.image:
        return None
    if not isinstance(Typ, DbObjectType):
        # A Var declared with a plain DB_TYPE_OBJECT carries no layout, so the
        # image cannot be walked; hand back the placeholder rather than guess.
        return Image
    Charset = Image.charset or AL32UTF8_CHARSET
    Name = Typ.name or Image.type_name
    if Typ.is_collection:
        (Elements, Keys) = decode_collection_keyed(
            Image.image, Typ.element or {}, Charset
        )
        return _object_with_lobs(
            DbObject(Name, elements=Elements, dbtype=Typ, keys=Keys), Connection
        )
    Attrs = decode_object_image(Image.image, Typ.attrs or [], Charset)
    return _object_with_lobs(DbObject(Name, Attrs, dbtype=Typ), Connection)


def _assign_return_binds(Bind, Result, Connection=None) -> None:
    # DML RETURNING ... INTO (#120): the response decoder left one
    # {'return_positions', 'return_values'} record per execute iteration, where
    # return_values[i] is the list of raw values for that bind (one per row the
    # iteration affected). Decode each by its Var's declared type and store the
    # list on the Var (getvalue() returns it, matching python-oracledb).
    #
    # An array execute produces several such records, one per iteration, and
    # they all have to be kept: the values a later iteration returned are not in
    # the first record, and reading only that one silently reported a single
    # returned key for a batch of any size (#687). They go on the Var as its
    # per-iteration values, selected by getvalue(pos); getvalue() with no
    # argument still reads the first iteration, so a single execute is unchanged.
    if not isinstance(Bind, list) or not isinstance(Result, tuple) or len(Result) < 5:
        return
    Rows = Result[4]
    Records = [R for R in Rows or () if isinstance(R, dict) and 'return_positions' in R]
    if not Records:
        return
    from seerdb.common.tns import _PREFETCHED_IMAGE_TYPES
    from seerdb.common.types import decode_value

    PerBind: dict = {}
    Truncated: list = []
    for Record in Records:
        Lengths = Record.get('return_lengths') or []
        for Index, (Pos, Values) in enumerate(
            zip(Record['return_positions'], Record['return_values'])
        ):
            if Pos >= len(Bind) or not isinstance(Bind[Pos], Var):
                continue
            Truncated += _truncated_returns(
                Values, Lengths[Index] if Index < len(Lengths) else []
            )
            Variable = Bind[Pos]
            TnsType = Variable.dbtype.tns_type
            if TnsType in _PREFETCHED_IMAGE_TYPES:
                # A JSON / VECTOR bind's returned value arrives as its binary
                # image, the same one such a column carries in a row, so it is
                # decoded rather than run through the scalar type decoder (#826).
                PerBind.setdefault(Pos, []).append(
                    [_decode_returned_image(TnsType, V) for V in Values]
                )
                continue
            if TnsType == TNS_TYPE_ADT:
                # An OBJECT / collection bind's returned value is an object
                # image, decoded with the type the Var was declared with (#826).
                PerBind.setdefault(Pos, []).append(
                    [
                        _decode_returned_object(Variable.dbtype, V, Connection)
                        for V in Values
                    ]
                )
                continue
            if TnsType in _LOB_RETURN_TYPES:
                # A CLOB / BLOB bind's returned value is already a LOB built by
                # the reader (#985); the connection is attached, and fetch_lobs
                # honoured, by _resolve_return_bind_lobs.
                PerBind.setdefault(Pos, []).append(list(Values))
                continue
            # Same rule as the OUT-bind path: a national return bind's value
            # arrives as AL16UTF16, and the charset form is what says so (#991).
            Column = {
                'data_type': TnsType,
                'charset': UTF8_CHARSET,
                'csfrm': getattr(Variable.dbtype, 'csfrm', 1),
            }
            PerBind.setdefault(Pos, []).append(
                [decode_value(Column, V if V else None) for V in Values]
            )
    for Pos, Iterations in PerBind.items():
        Variable = Bind[Pos]
        Variable._value = Iterations[0]
        Variable._iteration_values = Iterations if len(Iterations) > 1 else None
        Variable.has_value = True
    if Truncated:
        # Reported only now, with every Var assigned: the values that did fit
        # are correct and worth keeping, and the statement really ran -- the
        # DML is committed or pending on the server either way, exactly as it
        # is for python-oracledb, which raises the same DPY-4002 here (#1021).
        Got, Wanted = Truncated[0]
        raise DatabaseError(
            f'DPY-4002: column truncated to {Got} characters. Untruncated was {Wanted}'
        )


def _truncated_returns(Values, Lengths) -> list:
    # The (received, actual) pairs among a return bind's values the server
    # marked truncated (#1021). The trailing sb4 is the value's actual length,
    # and only ONE of its shapes is a report: a positive length longer than
    # what arrived. 0 is "it fitted" and -1 is "this value is NULL" -- measured
    # on a live 23ai, where a NULL return of any type sends -1, LOB or not.
    # Reading -1 as a report made `RETURNING ClobCol` into a NULL variable
    # raise instead of returning None.
    #
    # Only a value that arrived as bytes can be compared, which is the whole
    # set that truncates this way: a LOB, object or JSON / VECTOR return bind
    # carries its own framing and its length field says nothing about a buffer.
    Out = []
    for Value, Actual in zip(Values, Lengths):
        if not isinstance(Value, (bytes, bytearray)):
            continue
        if Actual > len(Value):
            Out.append((len(Value), Actual))
    return Out


def _extract_implicit_results(Result) -> list:
    # Pull the {'implicit_results': [...]} record the response decoder leaves in
    # the rows for a DBMS_SQL.RETURN_RESULT block (#121). Returns a list of
    # (row_format, cursor_id) pairs (empty if none), in server order.
    if not isinstance(Result, tuple) or len(Result) < 5:
        return []
    Rows = Result[4]
    if not Rows:
        return []
    for Row in Rows:
        if isinstance(Row, dict) and 'implicit_results' in Row:
            return [(R['row_format'], R['cursor_id']) for R in Row['implicit_results']]
    return []


def _build_refcursor_cursor(Connection, Rows, Marker) -> 'Cursor':
    # Wrap an already-fetched REF CURSOR result set in a Cursor.
    Nested = Cursor(Connection)
    Nested._description = [_column_description(C) for C in Marker['row_format']]
    Nested._annotations = [_col_annotations(C) for C in Marker['row_format']]
    # The connection's output type handler applies to it, as it applies to any
    # cursor without one of its own (#2458).
    Nested._plan_fetch()
    # Recursive: a nested cursor may itself select a CURSOR(...) column, so its
    # rows get the same resolution the outer ones did (#826).
    Nested._rows = [
        _resolve_nested_cursors(
            Connection, _resolve_objects(Connection, _resolve_lobs(Connection, Row))
        )
        for Row in Rows
    ]
    Nested._rowcount = len(Nested._rows)
    Nested._row_index = 0
    return Nested


def _resolve_nested_cursors(Connection, Row: list) -> list:
    # Turn a nested-cursor cell -- `select ..., CURSOR(select ...) from ...` --
    # into a fetchable Cursor (#826). The row decoder leaves the same marker a
    # REF CURSOR OUT bind does: a cursor id plus the row format the server
    # described inline, so the rows are fetched here and wrapped the same way.
    Out = list(Row)
    for I, Val in enumerate(Out):
        if isinstance(Val, dict) and Val.get('_refcursor'):
            # 9i's arrives with its rows already read (#2254).
            Rows = Val.get('rows')
            if Rows is None:
                Rows = Connection.fetch_all_rows(Val['cursor_id'], Val['row_format'])
            Out[I] = _build_refcursor_cursor(Connection, Rows or [], Val)
    return Out


# The LOB-class types a RETURNING bind can bring back as a LOB object. JSON and
# VECTOR are LOB-class too but never surface as LOBs -- their image decodes to a
# Python value -- and they are handled ahead of this (#985).
_LOB_RETURN_TYPES = (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE)


def _return_bind_lobs(Bind) -> list:
    """Every LOB a RETURNING bind brought back, paired with the Var holding it.

    A RETURNING Var holds a LIST per iteration, not a single value, so these
    cannot go through _out_bind_lobs (#985)."""
    from seerdb.common.lob import LOB

    if not isinstance(Bind, list):
        return []
    Out = []
    for B in Bind:
        Variable = _bind_var(B)
        if Variable is None:
            continue
        for Bucket in _return_value_lists(Variable):
            for Index, Value in enumerate(Bucket):
                if isinstance(Value, LOB):
                    Out.append((Bucket, Index, Value))
    return Out


def _return_value_lists(Variable) -> list:
    # The per-iteration value lists a RETURNING Var holds: `_value` is the first
    # iteration's list, and `_iteration_values` the whole set when an array DML
    # returned more than one.
    Lists = Variable._iteration_values or (
        [Variable._value] if isinstance(Variable._value, list) else []
    )
    return [L for L in Lists if isinstance(L, list)]


def _resolve_return_bind_lobs(Connection, Bind) -> None:
    # Attach the connection to every LOB a RETURNING bind returned and, unless
    # the connection asks for LOB objects, materialise it -- the same rule
    # _resolve_lobs applies to a fetched cell. The async cursor does the awaited
    # half itself.
    from seerdb.common.lob import _EXTERNAL_LOB_TYPES

    KeepLobs = getattr(Connection, 'fetch_lobs', False)
    for Bucket, Index, Value in _return_bind_lobs(Bind):
        Value._connection = Connection
        if not KeepLobs and Value.data_type not in _EXTERNAL_LOB_TYPES:
            Bucket[Index] = Value.read()


def _bind_var(B) -> 'Var | None':
    # The Var behind a bind-list entry, whether it is still the Var itself or
    # the temp-LOB marker it was promoted to on the way out (#902/#978), or None
    # when the entry is a plain value with nothing to write an OUT value back to.
    if isinstance(B, Var):
        return B
    if isinstance(B, TempLob) and isinstance(B.var, Var):
        return B.var
    return None


def _out_bind_lobs(Bind) -> list:
    """Every OUT / IN OUT bind that came back holding a LOB (#978).

    The LOB still has no connection on it and has not been materialised, which
    the sync and async cursors finish differently -- so, like the REF CURSOR
    markers :func:`_assign_out_binds` returns, they are collected here and left
    to the caller."""
    from seerdb.common.lob import LOB

    if not isinstance(Bind, list):
        return []
    Vars = (_bind_var(B) for B in Bind)
    return [V for V in Vars if V is not None and isinstance(V._value, LOB)]


def _resolve_out_bind_lobs(Connection, Bind) -> None:
    # The sync half of _out_bind_lobs: attach the connection and, unless the
    # connection asks for LOB objects, materialise -- the same rule
    # _resolve_lobs applies to a fetched LOB cell.
    from seerdb.common.lob import _DECODED_IMAGE_TYPES, _EXTERNAL_LOB_TYPES

    KeepLobs = getattr(Connection, 'fetch_lobs', False)
    for Variable in _out_bind_lobs(Bind):
        Variable._value._connection = Connection
        if Variable._value.data_type in _EXTERNAL_LOB_TYPES:
            continue
        if KeepLobs and Variable._value.data_type not in _DECODED_IMAGE_TYPES:
            continue
        Variable._value = Variable._value.read()


def _resolve_lobs(Connection, Row: list) -> list:
    # Attach the connection to every LOB cell so it can be read from, and --
    # unless the connection asks for LOB objects (`fetch_lobs`, the default,
    # #964) -- materialise it: CLOB -> str, BLOB -> bytes, empty -> "" / b"".
    # NULL stays None (the row decoder hands back None for a NULL LOB before it
    # ever becomes a LOB object).
    #
    # A JSON / VECTOR column arrives as a LOB too but is never a LOB to the
    # caller: its image decodes to a Python value whatever `fetch_lobs` says.
    from seerdb.common.lob import _DECODED_IMAGE_TYPES, _EXTERNAL_LOB_TYPES, LOB

    Out = list(Row)
    KeepLobs = getattr(Connection, 'fetch_lobs', False)
    for I, Val in enumerate(Out):
        if isinstance(Val, LOB):
            Val._connection = Connection
            if Val.data_type in _EXTERNAL_LOB_TYPES:
                continue
            if KeepLobs and Val.data_type not in _DECODED_IMAGE_TYPES:
                continue
            Out[I] = Val.read()
    return Out


def _check_returning_support(Connection, ReturnBinds, Operation: str = '') -> None:
    # RETURNING ... INTO needs the 10g+ request form, which the pre-10g servers
    # refuse for this client type -- 9i answers ORA-00439. Both 9i and 8i run the
    # identical statement wrapped in a PL/SQL block, where the INTO targets are
    # ordinary OUT binds, so the connection rewrites it there (#801, #802) and it
    # is allowed here.
    #
    # The rewrite also settles the failure mode #716 reported: in the native
    # form a failing RETURNING leaves 8i mid-protocol, but inside a block the
    # same failure is an ordinary PL/SQL error -- verified live, the statement
    # raises ORA-00001 and the session stays usable.
    #
    # Only a dialect with no block path is refused, because there is nothing to
    # rewrite into.
    from seerdb.client.dialect import CAP_BLOCK

    Version = getattr(Connection, 'field_version', None)
    if not ReturnBinds or Version is None or Version >= FIELD_VERSION_10_2:
        return
    Dialect = getattr(Connection, '_dialect', None)
    Caps = Dialect.capabilities() if Dialect is not None else frozenset()
    if CAP_BLOCK not in Caps:
        # No PL/SQL block path to rewrite into, so there is nothing to fall back
        # on; refuse rather than send a form the server will reject.
        raise NotSupportedError(
            'RETURNING ... INTO requires an Oracle 10g+ server '
            'or a pre-10g dialect that supports PL/SQL blocks'
        )
    # BULK COLLECT gathers every returned row into a collection, which the
    # rewrite's scalar OUT binds cannot hold and these tiers have no array DML
    # to fill anyway. Refuse before the server answers with a PL/SQL compile
    # error whose text is itself unreliable here (#810).
    if Operation and _BULK_COLLECT_RE.search(strip_non_bind_text(Operation)):
        raise NotSupportedError(
            'RETURNING ... BULK COLLECT INTO is not supported below 10g: the '
            'statement runs as a PL/SQL block there and its INTO targets are '
            'scalar binds. Return a single row, or read the rows with a SELECT.'
        )
    # A quoted placeholder survives plain pre-10g DML but not the block the
    # rewrite needs: the server answers ORA-01006 for `:"name"` inside a block,
    # measured on 9i. Say so, rather than let that surface as a bare ORA.
    if Operation and any(Quoted for _Name, Quoted in bind_placeholders(Operation)):
        raise NotSupportedError(
            'RETURNING ... INTO with a quoted bind name is not supported below '
            '10g: the statement has to run as a PL/SQL block there, and the '
            'server rejects a quoted placeholder inside one (ORA-01006). '
            'Use an unquoted bind name.'
        )


def _check_object_bind_support(Connection, Bind, Batch=None) -> None:
    # Some binds need the 12c+ bind-OAC layout and have no pre-12c reference
    # (python-oracledb is 12.1+): a SQL OBJECT (ADT) value (#116; pre-12c
    # rejects it with a fatal ORA-03106 that desyncs the connection) and a
    # PL/SQL associative-array bind (#122; pre-12c mis-types it, PLS-00306),
    # and a VECTOR (#1762: a 23ai answers an 11.2 session's ORA-03106, fatal,
    # and serves the same bind from 12.1 up). Refuse them up front on pre-12c
    # with a clear error. (Object/collection *decode* works on all tiers --
    # only these binds are 12c+.)
    from seerdb.common.dbobject import DbObject, DbObjectType, DbRef

    if getattr(Connection, 'field_version', 0) >= FIELD_VERSION_12_1:
        return
    # 11g's native form binds an object or a collection, IN and OUT, as OCI
    # 11.2 does (#2463); its dialect refuses what it does not serve yet.
    Native11 = bool(getattr(Connection, '_native11', False))
    Rows = [Bind] + (Batch or []) if Bind else (Batch or [])
    for Row in Rows:
        if isinstance(Row, dict):
            Values = list(Row.values())
        elif isinstance(Row, (list, tuple)):
            Values = list(Row)
        else:
            Values = [Row]
        for V in Values:
            # An object or collection Var -- the OUT bind -- is the same bind on
            # the wire as an object value, and pre-12c answers it with the same
            # fatal ORA-03106 (#2039).
            if Native11 and (
                isinstance(V, DbObject)
                or (isinstance(V, Var) and isinstance(V.dbtype, DbObjectType))
            ):
                continue
            if isinstance(V, DbObject) or (
                isinstance(V, Var) and isinstance(V.dbtype, DbObjectType)
            ):
                raise NotSupportedError(
                    'binding a SQL OBJECT value requires an Oracle 12.1+ server'
                )
            if isinstance(V, DbRef):
                # OCI 11.2's form serves it on the native session.
                if Native11:
                    continue
                raise NotSupportedError(
                    'binding a REF value requires an Oracle 12.1+ server, '
                    'or a 10g or 11g session with oall8=True'
                )
            if isinstance(V, Var) and getattr(V, 'is_array', False):
                # OCI 11.2's form serves it on the native session.
                if Native11:
                    continue
                raise NotSupportedError(
                    'binding a PL/SQL associative array (arrayvar) requires an '
                    'Oracle 12.1+ server, or a 10g or 11g session with oall8=True'
                )
            if (
                isinstance(V, Var) and V.dbtype.tns_type == TNS_TYPE_VECTOR
            ) or is_vector_bind(V):
                raise NotSupportedError(
                    'binding a VECTOR value requires an Oracle 12.1+ session'
                )


def _resolve_objects(Connection, Row: list) -> list:
    # Turn any object (ADT) placeholders into DbObjects (#115). The row decoder
    # kept the packed image without decoding it (the attribute layout isn't
    # known at decode time); fetch the layout for the type now (cached on the
    # connection) and walk the image. NULL objects already came back as None.
    from seerdb.common.dbobject import (
        DbObject,
        ObjectImage,
        decode_collection_keyed,
        decode_object_image,
        decode_xmltype,
    )
    from seerdb.common.lob import LOB

    Out = list(Row)
    for I, Val in enumerate(Out):
        if isinstance(Val, ObjectImage):
            if Val.type_name == 'XMLTYPE':
                # XMLType (#124): type 109 with no user object type. Decode the
                # image directly (no describe round trip) -> str, or read the
                # CLOB locator for a large document.
                (IsLob, XmlVal) = decode_xmltype(
                    Val.image, Val.charset or AL32UTF8_CHARSET
                )
                if IsLob:
                    Lob = LOB(TNS_TYPE_CLOB, XmlVal)
                    Lob._connection = Connection
                    Out[I] = Lob.read()
                else:
                    Out[I] = XmlVal
                continue
            Typ = Connection._describe_object_type(Val.type_schema, Val.type_name)
            Charset = Val.charset or AL32UTF8_CHARSET
            if Typ is not None and Typ.is_collection:
                (Elements, Keys) = decode_collection_keyed(
                    Val.image, Typ.element or {}, Charset
                )
                Out[I] = DbObject(
                    Val.type_name, elements=Elements, dbtype=Typ, keys=Keys
                )
            else:
                Layout = Typ.attrs if Typ is not None else []
                Attrs = decode_object_image(Val.image, Layout, Charset)
                Out[I] = DbObject(Val.type_name, Attrs, dbtype=Typ)
            Out[I] = _object_with_lobs(Out[I], Connection)
    return Out


def _bind_temp_lobs(Bind: list, Connection: object = None) -> list:
    """Turn every LOB object bound into the marker that binds it by its locator.

    A LOB from ``connection.createlob`` (#1066) and one a query returned bind
    alike, as python-oracledb binds them: a CLOB or BLOB with the temp-LOB
    locator bind of #91 -- same OAC, the same value framing, a persistent
    CLOB's 114-byte locator as much as a temporary one's 40, captured against
    python-oracledb on 21c -- and a BFILE with its own OAC (BfileBind). The
    TempLob marker holds the BARE locator and writes its own ub2 in front, so the
    ub2 the LOB object carries is stripped here rather than written twice.

    A fetched one is bound so on the thin 10g+ path alone, where it is measured.
    A dialect's session (8i, 9i, a pooled 11g one) keeps it as the LOB object,
    which its own codec binds or refuses: given a marker it does not know, a
    pooled 11g server process aborted (ORA-03137)."""
    from seerdb.common.lob import LOB

    if not Bind:
        return Bind
    Thin = getattr(Connection, '_dialect', None) is None
    Out: list = []
    for V in Bind:
        if not isinstance(V, LOB) or not (V._temp or Thin):
            Out.append(V)
        elif V.data_type == TNS_TYPE_BFILE:
            Out.append(BfileBind(bytes(V.raw)))
        elif V.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
            # Oracle's locator leads with its own ub2 length, which the marker
            # writes itself; a Mirror's does not, and goes whole (#2505).
            Bare = V.raw[2:] if is_prefixed_locator(V.raw) else V.raw
            Out.append(TempLob(Bare, V.data_type == TNS_TYPE_BLOB, csfrm=V._csfrm))
        else:
            Out.append(V)
    return Out


def _resolve_parameters(SQL: str, Params) -> list:
    # Translate the caller-supplied parameters into a positional list. The
    # wire protocol sends bind values positionally; named placeholders
    # (`:foo`) just give the caller a way to refer to them by name.
    #
    # For a dict, each `:name` occurrence is expanded to its value — so a plain
    # SQL statement gets one value per textual occurrence, while a PL/SQL block
    # dedupes by unique placeholder name (the OCI binding contract; detected on
    # the SQL by `_is_plsql`). A dict may carry extra keys the SQL never uses —
    # they are ignored.
    #
    # A list/tuple is passed through unchanged. seerdb is DELIBERATELY more
    # forgiving here than python-oracledb (see README §Compatibility): oracledb
    # requires exactly one positional value
    # per textual placeholder occurrence and rejects a short list (DPY-4009),
    # whereas seerdb lets a short list stand — the server then reuses a value by
    # placeholder name (`"... :x ... :x ..."`, `[v]` binds `:x` once). The bytes
    # that reach the server are identical; seerdb simply doesn't second-guess the
    # count. This is an intentional divergence, not an oversight.
    if Params is None:
        return []
    if isinstance(Params, (list, tuple)):
        return list(Params)
    if isinstance(Params, dict):
        Placeholders = bind_placeholders(SQL, dedupe=is_plsql(SQL))
        Keyed = {canonical_bind_key(str(K)): V for K, V in Params.items()}
        Out = []
        for Name, Quoted in Placeholders:
            if Name not in Keyed:
                Spelling = f'"{Name}"' if Quoted else Name
                raise ProgrammingError(f'missing bind value for :{Spelling}')
            Out.append(Keyed[Name])
        return Out
    raise NotSupportedError(
        f'parameters must be a list, tuple, or dict; got {type(Params).__name__}'
    )


def _col_annotations(Col: dict) -> dict | None:
    # Decode a column's raw annotation map (bytes -> str), or None if the column
    # carries no annotations (#89). Values are '' for a name-only annotation.
    Ann = Col.get('annotations')
    if not Ann:
        return None

    def _s(B):
        return B.decode('utf-8', errors='replace') if isinstance(B, bytes) else B

    return {_s(K): _s(V) for K, V in Ann.items()}


def _is_xmltype(Col: dict) -> bool:
    return (Col.get('type_schema') or '').upper() == 'SYS' and (
        Col.get('type_name') or ''
    ).upper() == 'XMLTYPE'


def _column_description(Col: dict) -> 'FetchInfo':
    # PEP 249 description tuple, matching python-oracledb's FetchInfo exactly:
    #   (name, type_code, display_size, internal_size, precision, scale, null_ok)
    Name = Col.get('column_name')
    if isinstance(Name, bytes):
        Name = Name.decode('utf-8', errors='replace')
    TnsType = Col.get('data_type') or 0
    Csfrm = Col.get('csfrm') or 1
    # type_code is the seerdb.DB_TYPE_* object (so it compares equal to the
    # module constants, PEP-249 §type_code); fall back to the raw wire code for
    # a type with no DbType object yet.
    TypeCode: object = dbtype_for_oracle_type(TnsType, Csfrm)
    if TypeCode is None:
        TypeCode = TnsType
    elif TypeCode is DB_TYPE_OBJECT and _is_xmltype(Col):
        # An XMLType is an object column on the wire; its type name is what
        # python-oracledb reports it apart by (#1478).
        TypeCode = DB_TYPE_XMLTYPE
    Precision = Col.get('precision') or 0
    Scale = Col.get('data_scale') or 0
    MaxSize = Col.get('max_size') or 0
    BufferSize = Col.get('data_length') or 0
    # oracledb's "max_size" is the declared column size — the char count for
    # char types (OACmxlc = MaxSize), but the byte length for RAW, which carries
    # it in the buffer size (OACmxlc is 0 there).
    DeclaredSize = BufferSize if TnsType == TNS_TYPE_RAW else MaxSize
    # precision / scale are reported only for the NUMBER family (either set),
    # else None (oracledb FetchInfo.precision / .scale).
    OutPrecision = Precision if (Precision or Scale) else None
    OutScale = Scale if (Precision or Scale) else None
    # display_size (oracledb FetchInfo.display_size): the declared char/raw size
    # when set; 23 for DATE/TIMESTAMP; a computed width for the NUMBER family;
    # None otherwise.
    if DeclaredSize > 0:
        DisplaySize: int | None = DeclaredSize
    elif TnsType in _DATE_TNS_TYPES:
        DisplaySize = 23
    elif TnsType in _NUMBER_TNS_TYPES:
        if Precision:
            DisplaySize = Precision + 1
            if Scale > 0:
                DisplaySize += Scale + 1
        else:
            DisplaySize = 127
    else:
        DisplaySize = None
    # internal_size (oracledb): the byte buffer, only for sized char/raw types.
    InternalSize = BufferSize if DeclaredSize > 0 else None
    fields = (
        Name,
        TypeCode,
        DisplaySize,
        InternalSize,
        OutPrecision,
        OutScale,
        bool(Col.get('null_ok', 0)),
    )
    # A native VECTOR column additionally carries its element format and declared
    # dimension count (23ai, #55) — metadata a plain type code cannot express, so
    # a describe would otherwise drop it. oracledb exposes the same on FetchInfo.
    return FetchInfo(
        fields,
        vector_dimensions=Col.get('vector_dimensions'),
        vector_format=Col.get('vector_format'),
        vector_flags=Col.get('vector_flags'),
        type_schema=Col.get('type_schema'),
        type_name=Col.get('type_name'),
        type_oid=Col.get('type_oid') or None,
        is_json=bool(Col.get('is_json')),
        is_oson=bool(Col.get('is_oson')),
        domain_schema=_text(Col.get('domain_schema')),
        domain_name=_text(Col.get('domain_name')),
        annotations=_col_annotations(Col),
        max_size=DeclaredSize,
    )


def _text(Value: object) -> str | None:
    # A describe string as python-oracledb reports it: str, or None when absent.
    if not Value:
        return None
    return (
        Value.decode('utf-8', errors='replace')
        if isinstance(Value, bytes)
        else str(Value)
    )


class FetchInfo(tuple):
    """One ``cursor.description`` entry: the PEP-249 7-tuple ``(name, type_code,
    display_size, internal_size, precision, scale, null_ok)``, with 23ai vector
    metadata attached as attributes (oracledb parity).

    It *is* the 7-tuple — it indexes, unpacks and compares equal to the plain
    tuple every PEP-249 consumer expects — and adds:

    * ``vector_dimensions`` — a native VECTOR column's declared dimension count
      (0 for a flexible ``VECTOR`` with no fixed dimension), else ``None``.
    * ``vector_format`` — its element format code (2 FLOAT32, 3 FLOAT64, 4 INT8,
      5 BINARY; 0 flexible), matching the value image's element type, else
      ``None``.
    * ``domain_schema`` / ``domain_name`` / ``annotations`` — a 23ai column's
      SQL domain (``str``) and annotation map (``dict``, ``''`` for a name-only
      annotation); ``None`` for a column without them (#1083).
    * ``type_schema`` / ``type_name`` / ``type_oid`` — an object (ADT / REF)
      column's referenced type identity, carried in the per-column describe
      (§21.1); ``None`` for a non-object column. The Mirror re-emits these so an
      external client can resolve the type (#888).

    The vector and object attributes are ``None`` for a column that does not
    carry them (and the vector pair whenever the server is older than 23.4, which
    sends no vector descriptor)."""

    def __new__(
        cls,
        fields,
        *,
        vector_dimensions=None,
        vector_format=None,
        vector_flags=None,
        type_schema=None,
        type_name=None,
        type_oid=None,
        is_json=False,
        is_oson=False,
        domain_schema=None,
        domain_name=None,
        annotations=None,
        max_size=0,
    ):
        self = super().__new__(cls, fields)
        # The declared size, which the older six-argument output type handler
        # form is passed (#2458).
        self._max_size = max_size
        self.vector_flags = vector_flags
        # A VECTOR column that allows ANY number of dimensions says so with a
        # flag, not with a count -- the count alongside it is 0 and means
        # nothing. Reporting that 0 tells a caller the column holds zero-element
        # vectors, which is a different claim and a wrong one, so it is reported
        # as None the way python-oracledb reports it (#1012).
        #
        # The FORMAT needs no flag: a flexible format simply is 0. It still has
        # to become None for the same reason -- 0 is not a format.
        if vector_flags is not None and vector_flags & VECTOR_FLAG_FLEXIBLE_DIM:
            vector_dimensions = None
        self.vector_dimensions = vector_dimensions or None
        self.vector_format = vector_format or None
        self.type_schema = type_schema
        self.type_name = type_name
        self.type_oid = type_oid
        # is_json: a native JSON column. is_oson: a BLOB / CLOB holding an OSON
        # image, which a client decodes with decode_oson instead of surfacing as
        # a LOB (oracledb's FetchInfo.is_oson). Carried so the Mirror can re-mark
        # the column for an external client (#826).
        self.is_json = is_json
        self.is_oson = is_oson
        # A 23ai column's SQL domain and annotations, as python-oracledb's
        # FetchInfo carries them: None for a column without (#1083).
        self.domain_schema = domain_schema
        self.domain_name = domain_name
        self.annotations = annotations
        return self

    # The 7-tuple's fields by name, as python-oracledb's FetchInfo has them; an
    # output type handler reads them (#2458).
    @property
    def name(self) -> str:
        return self[0]

    @property
    def type_code(self) -> object:
        return self[1]

    @property
    def type(self) -> object:
        """The column's type. python-oracledb returns the object type for an
        object column; seerdb returns its type code, as `type_code` does."""
        return self[1]

    @property
    def display_size(self) -> int | None:
        return self[2]

    @property
    def internal_size(self) -> int | None:
        return self[3]

    @property
    def precision(self) -> int | None:
        return self[4]

    @property
    def scale(self) -> int | None:
        return self[5]

    @property
    def null_ok(self) -> bool:
        return self[6]
