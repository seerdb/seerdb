# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Sans-io wire dialects for the pre-10g Oracle tiers (#369).

The pre-10g tiers (9i / fv2, and 8i) speak wire *dialects* that are hard forks of
the modern 10g→23ai protocol — different TTC function codes, request framing and
describe/row shapes — so they can't be folded into the modern encoders behind
another ``if field_version <`` branch. Historically each became a parallel set of
``_fv2_* `` / ``_8i_*`` methods on both :class:`OracleConnect` **and**
:class:`AsyncOracleConnect` — a near-verbatim ``await``-sprinkled duplicate.

This module removes both the 3-way dispatch ladder and the sync/async duplication
at once. A :class:`Dialect` is written **once** as *sans-io* generators: each
method yields :class:`Send` / :data:`RECV` intents instead of touching a socket,
and the connection drives it with a tiny sync or async loop (``_drive`` on each
connection class). The wire codecs (``encode_o7_*`` / ``decode_fv2_*`` …) are
already colorless byte-in/byte-out functions, so the dialect just sequences them.

A generator method that yields ``Send(data)`` means "send this as a TNS_DATA
packet"; ``yield RECV`` means "give me the next data packet" and evaluates to the
``(type, packet)`` tuple (or ``False`` on a closed connection), exactly as
``_next_data_packet`` returns. Sibling steps compose with ``yield from``; ORA
errors are raised inline and propagate through the driver.
"""

from __future__ import annotations

from typing import Callable, Protocol

from seerdb.common.sqltext import is_reusable_dml
from seerdb.common.tns import (
    FV2_BIND_IN,
    FV2_BIND_OUT,
    O8I_STMT_BEGIN,
    O8I_STMT_DECLARE,
    O8I_STMT_SELECT,
    O8I_STMT_TXN,
    OCI11_LOB_CALLS,
    decode_8i_block_cursor,
    decode_8i_block_out,
    decode_8i_cursor_id,
    decode_8i_dcb_describe,
    decode_8i_dml_response,
    decode_8i_dml_rowid,
    decode_8i_exec_response,
    decode_8i_terminal_error,
    decode_9i_oall8_batch_errors,
    decode_9i_oall8_bind_directions,
    decode_9i_oall8_block_cursor,
    decode_9i_oall8_block_out,
    decode_9i_oall8_cursor_id,
    decode_9i_oall8_describe,
    decode_9i_oall8_dml_response,
    decode_9i_oall8_dml_rowid,
    decode_9i_oall8_error_position,
    decode_9i_oall8_exec_response,
    decode_9i_oall8_lob_value,
    decode_9i_oall8_terminal_error,
    decode_9i_oall8_warn_flags,
    decode_fv2_batch_errors,
    decode_fv2_bind_directions,
    decode_fv2_block_out,
    decode_fv2_describe,
    decode_fv2_dml_response,
    decode_fv2_dml_rowid,
    decode_fv2_error_position,
    decode_fv2_exec_status,
    decode_fv2_lob_chunks,
    decode_fv2_lob_getlen,
    decode_fv2_lob_value,
    decode_fv2_oer_error,
    decode_fv2_opened_cursor,
    decode_fv2_opened_locator,
    decode_fv2_version,
    decode_fv2_warn_flags,
    decode_o8i_bfile_getlen,
    decode_oci11_block,
    decode_oci11_create_temp,
    decode_oci11_describe,
    decode_oci11_lob_read,
    decode_oci11_lobop,
    decode_oci11_piggybacks,
    decode_oci11_rows,
    decode_oci11_status,
    decode_ub4,
    encode_8i_close_cursors,
    encode_8i_lob_read,
    encode_8i_oall8_dml,
    encode_8i_oall8_fetch,
    encode_8i_oall8_query,
    encode_8i_sql_text,
    encode_9i_oall8_close_cursors,
    encode_9i_oall8_dml,
    encode_9i_oall8_fetch,
    encode_9i_oall8_lob_read,
    encode_9i_oall8_lobop,
    encode_9i_oall8_query,
    encode_9i_sql_text,
    encode_o7_bfile_close,
    encode_o7_bfile_open,
    encode_o7_block,
    encode_o7_close,
    encode_o7_describe,
    encode_o7_exec,
    encode_o7_free,
    encode_o7_lob_getlen,
    encode_o7_lob_read,
    encode_o7_lobop,
    encode_o7_open,
    encode_o7_parse,
    encode_o7_version,
    encode_o8i_bfile_close,
    encode_o8i_bfile_getlen,
    encode_o8i_bfile_open,
    encode_oci11_close_cursors,
    encode_oci11_create_temp,
    encode_oci11_cursor_fetch,
    encode_oci11_execute,
    encode_oci11_fetch,
    encode_oci11_lob_read,
    encode_oci11_lobop,
    encode_oci11_long_fetch,
    encode_tokens_rxd,
    exec_oac_signature,
    has_long_class_bind,
    o8i_block_complete,
    o8i_stmt_type,
    o8i_terminal_complete,
    o9i_oall8_terminal_complete,
    oci11_stmt_type,
)
from seerdb.common.tns_consts import (
    ISO_LATIN_1_CHARSET,
    ORA_NO_DATA_FOUND,
    TNS_LOB_OP_FILE_CLOSE,
    TNS_LOB_OP_FILE_OPEN,
    TNS_LOB_OP_GET_LENGTH,
    TNS_TYPE_ADT,
    TNS_TYPE_BFILE,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_REFCURSOR,
    TTI_LOB,
    TTI_OER,
    TTI_RPA,
)

# Oracle 8i LONG / LONG RAW type codes — a LONG changes the fetch shape (one row
# per round trip, read the whole value) (#377).
_O8I_LONG_TYPES = frozenset((8, 24))
# The fetch's LONG cap that asks for a LONG / LONG RAW value whole (#377).
_LONG_WHOLE = 0x7FFFFFFF


class Send:
    """A wire intent: write ``data`` as a single TNS_DATA packet."""

    __slots__ = ('data',)

    def __init__(self, data: bytes) -> None:
        self.data = data


# The "receive the next data packet" intent. A bare sentinel — the driver returns
# ``_next_data_packet()``'s result (``(type, packet)`` or ``False``) back into the
# generator at the ``yield RECV`` site.
RECV = object()


def fv2_raise_for_error(
    packet: bytes, *, end_of_fetch_ok: bool = True, with_offset: bool = False
) -> None:
    """Raise the server's error if ``packet`` is a 9i OER carrying a real ORA
    code (not success / end-of-fetch), so a parse-time failure surfaces as its
    true code + message instead of a downstream desync (#102). Colorless — shared
    by the fv2 dialect and the (still-inline) 8i methods.

    ``end_of_fetch_ok`` says whether ORA-01403 is this call's end-of-fetch
    sentinel. It is for a query; it is NOT for a PL/SQL block, where the same
    code is the real error a `SELECT ... INTO` raises when it matches no row,
    and treating it as a sentinel returned a silent success with a NULL OUT
    value (#1039). The 10g+ path draws the same line in `_drain_cursor`.
    """
    (err_code, message) = decode_fv2_oer_error(packet)
    benign = (0, ORA_NO_DATA_FOUND) if end_of_fetch_ok else (0,)
    if err_code and err_code not in benign:
        from seerdb.common.exceptions import from_ora_code

        exc = from_ora_code(err_code)(message or f'ORA-{err_code:05d}', code=err_code)
        # 9i's status says where in the statement the error is, as 10g+ does;
        # 8i's does not (#719), so only the 9i dialect asks (#2263).
        exc.offset = decode_fv2_error_position(packet) if with_offset else 0
        raise exc


class Dialect(Protocol):
    """A pre-10g wire dialect as sans-io generators. Each ``execute_*`` yields
    :class:`Send` / :data:`RECV` intents and returns the same 9-tuple the modern
    execute path produces, so ``_drain_cursor`` and the cursor are unchanged."""

    keep_lobs: bool  # the connection's fetch_lobs, set per statement (#2259)

    def capabilities(self) -> frozenset[str]: ...
    def execute_query(self, sql: str, bind: list | None, fetch: int): ...
    def execute_dml(
        self,
        sql: str,
        bind: list | None,
        batch: list | None,
        batcherrors: bool,
        cache: dict | None,
    ): ...
    def execute_block(self, sql: str, bind: list | None): ...
    def txn_control(self, statement: str): ...  # only when CAP_OWN_TXN is set
    def flush_cursors(self, cache: dict): ...  # free the cached cursors (#2261)
    def bfile_read(self, locator: bytes): ...


# Capability tokens a dialect advertises via capabilities() — one honest place for
# "does this tier do array DML / its own commit / …" instead of ad-hoc branching.
CAP_QUERY = 'query'
CAP_DML = 'dml'
CAP_BLOCK = 'block'
CAP_LOB = 'lob'
CAP_ARRAY_DML = 'array_dml'
# The dialect serves a LOB object's calls -- read at an offset, write, trim,
# size, chunk size, open / close -- through its own LOBOPS form (#2259).
CAP_LOB_OBJECT = 'lob_object'
# The dialect drives its own COMMIT / ROLLBACK (8i has no modern TTI_COMMIT); a
# dialect without this capability leaves transaction control to the modern path.
CAP_OWN_TXN = 'own_txn'
# The dialect binds a plain str or bytes past the SQL inline limits (4000 and
# 2000 bytes) as itself, as OCI does on a pooled 11g session (#2466); the 8i
# and 9i dialects, without it, refuse one up front (#2260).
CAP_WIDE_BINDS = 'wide_binds'
# The dialect makes a temporary LOB itself (create_temp_lob), so a LOB Var's
# value and a large PL/SQL value bind through one, as on 12c+ (#2466).
CAP_TEMP_LOB = 'temp_lob'


# The cursor cache's cap, as on 10g+ (OracleConnect._cursor_cache_max).
_FV2_CURSOR_CACHE_MAX = 32


def _fv2_cache_key(
    sql: str, bind: list | None, batch: list | None, batcherrors: bool
) -> tuple | None:
    # A 9i statement's cursor-cache key, or None when it is never cached: as on
    # 10g+, only a reusable DML without a LONG-class bind (#703, #720), and on
    # 9i not an array DML, whose re-execute is not captured (#2261).
    if batch or batcherrors or not is_reusable_dml(sql):
        return None
    if has_long_class_bind(bind or [], [], _FV2_MAX_STRING_SIZE):
        return None
    return (sql, exec_oac_signature(bind or [], []))


# The widest value 9i takes in place: a pre-12c server's 4000 bytes.
_FV2_MAX_STRING_SIZE = 4000


def _is_cursor_var(value: object) -> bool:
    from seerdb.common.datatypes import Var

    return isinstance(value, Var) and value.dbtype.tns_type == TNS_TYPE_REFCURSOR


def _cursor_marker(cursor_id: int, columns: list, rows: list) -> dict:
    # A cursor 9i already read, in the marker a 10g+ REF CURSOR leaves, with its
    # rows, so the cursor wraps them where 10g+ fetches by id (#2246, #2254).
    return {
        '_refcursor': True,
        'cursor_id': cursor_id,
        'row_format': columns,
        'rows': rows,
    }


def _block_input(value: object) -> object:
    # A block bind's IN value. A REF CURSOR's is an empty cursor slot, the one
    # byte ojdbc14 sends (#2246); a NULL there is a bind the server cannot use.
    from seerdb.common.datatypes import Var

    if _is_cursor_var(value):
        return b'\x00'
    return value._value if isinstance(value, Var) else value


class Fv2Dialect:
    """Oracle 9i (TTC field version 2) — the four-call TTI_ALL7 dialect (#102,
    PROTOCOL.md §19). Sans-io: driven by ``OracleConnect._drive`` (sync) or
    ``AsyncOracleConnect._drive`` (async)."""

    def capabilities(self) -> frozenset[str]:
        # 9i does query / DML / PL/SQL blocks / LOB, and array DML over
        # TTI_ALL7 (#2245). It uses the modern commit path, so it does NOT
        # advertise CAP_OWN_TXN.
        return frozenset(
            {CAP_QUERY, CAP_DML, CAP_BLOCK, CAP_LOB, CAP_ARRAY_DML, CAP_LOB_OBJECT}
        )

    # Whether a fetch keeps its LOB cells as LOB objects -- the connection's
    # fetch_lobs, set before each statement -- rather than reading their content
    # while the cursor is open (#2259).
    keep_lobs = False

    def __init__(self) -> None:
        # The server cursor every uncached statement is parsed on, opened once
        # (#2288). Each statement sent an OOPEN and parsed on cursor 1 whatever
        # it gave, so every OOPEN after the first left a cursor open, and a
        # session that alternated statements ran out at open_cursors.
        self._shared = 0

    def _shared_cursor(self):
        # The shared cursor, opened by the first statement that needs it.
        if not self._shared:
            yield Send(encode_o7_open(0))
            resp = yield RECV  # OOPEN RPA, the cursor's id
            self._shared = decode_fv2_opened_cursor(resp[1]) if resp else 0
        return self._shared

    def txn_control(self, statement: str):
        # 9i commits via the modern TTI_COMMIT path (CAP_OWN_TXN absent), so this
        # is never driven; present only to satisfy the Dialect protocol.
        raise NotImplementedError('9i uses the modern commit path')
        yield  # unreachable — makes the signature a generator for a uniform type

    def execute_query(self, sql: str, bind: list | None = None, fetch: int = 0):
        # 9i SELECT: the four-call TTI_ALL7 sequence (parse, describe, execute +
        # fetch, close). `fetch` is ignored — the exec loop drains the cursor
        # itself. Returns the same tuple shape as a normal execute response so the
        # cursor / _drain_cursor machinery is unchanged.
        cursor = yield from self._shared_cursor()
        yield Send(encode_o7_parse(0, sql, bind, Cursor=cursor))
        resp = yield RECV  # parse RPA ack — or an OER
        if resp is not False:  # surface a parse error (e.g. ORA-00942)
            fv2_raise_for_error(resp[1], with_offset=True)
        (columns, all_rows) = yield from self._drain(cursor)
        # call_status 0 + ora_code 0 => _drain_cursor won't issue TTI_FETCHes.
        return (0, 0, 0, (len(all_rows), columns), all_rows, None, None, [], None)

    def _drain(self, cursor: int):
        # Describe a parsed or opened server cursor, fetch every row, and close
        # it: the query's own cursor, or a REF CURSOR a block returned (#2246),
        # which ojdbc14 reads with the same three calls by its id.
        yield Send(encode_o7_describe(0, cursor))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i describe')
        columns = decode_fv2_describe(resp[1])
        # Execute, then fetch in batches: each batch re-sends the same exec+fetch
        # TTI_ALL7; the server continues the cursor and ends with ORA-01403 (#99).
        # A batch with no rows also terminates the loop so a malformed response
        # can't spin forever.
        all_rows: list = []
        err_code = 0
        message = None
        while True:
            yield Send(encode_o7_exec(0, columns, cursor))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i fetch')
            (rows, err_code, message) = decode_fv2_exec_status(resp[1], columns)
            all_rows.extend(rows)
            if err_code or not rows:
                break
        # Resolve LOB cells while the cursor is still open (JDBC does the same):
        # decode_fv2_exec_response left LOB objects in the rows; replace each with
        # its content.
        yield from self.resolve_lobs(all_rows, columns)
        # A CURSOR(...) column's cell is its nested cursor's id. Read each one
        # now, while this cursor is open -- ojdbc14 closes the parent last --
        # and the same way, so a cursor nested in it is read in turn (#2254).
        for j, col in enumerate(columns):
            if col.get('data_type') != TNS_TYPE_REFCURSOR:
                continue
            for row in all_rows:
                if row[j]:
                    nested = decode_ub4(row[j])[0]
                    (nested_columns, nested_rows) = yield from self._drain(nested)
                    row[j] = _cursor_marker(nested, nested_columns, nested_rows)
        yield Send(encode_o7_close(0, cursor))
        yield RECV  # close STA
        if err_code != ORA_NO_DATA_FOUND:
            # With the status's text: from the code alone, an error the fetch
            # met had none (#2315).
            _raise_ora(err_code, message)
        return (columns, all_rows)

    def execute_dml(
        self,
        sql: str,
        bind: list | None = None,
        batch: list | None = None,
        batcherrors: bool = False,
        cache: dict | None = None,
    ):
        # 9i DML over TTI_ALL7 (#101): OOPEN, then a single parse that also
        # executes (option 02 80 21) — no describe/fetch. The affected-row count
        # comes back in the response OER. (Autocommit is applied by the caller.)
        # An executemany's further rows ride the same call (#2245), and the
        # count is then the whole batch's. In `batcherrors` mode the server
        # applies the good rows and lists the failures (#2247).
        # The connection's cursor cache (#2261), keyed and kept as on 10g+:
        # DDL flushes it, a cacheable DML is parsed into a cursor of its own
        # and then re-executed by its id.
        key = None if cache is None else _fv2_cache_key(sql, bind, batch, batcherrors)
        if cache is not None and not is_reusable_dml(sql):
            yield from self.flush_cursors(cache)
        cursor = cache.get(key, 0) if cache is not None and key is not None else 0
        if not cursor and key is not None:
            # A statement to cache gets a cursor of its own; the server never
            # hands out one that is open, so it is not the shared one.
            yield Send(encode_o7_open(0))
            resp = yield RECV  # OOPEN RPA, the cursor's id
            cursor = decode_fv2_opened_cursor(resp[1]) if resp else 0
        if not cursor:
            cursor = yield from self._shared_cursor()
        reexecute = cache is not None and key is not None and key in cache
        yield Send(
            encode_o7_parse(
                0,
                sql,
                bind,
                batch,
                batcherrors,
                Cursor=cursor,
                Reexecute=reexecute,
            )
        )
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i DML')
        # An error (ORA-00942, a constraint) comes back in the result, as on
        # 10g+, so the cursor can report the rows applied before it: a batch
        # that fails part-way applied the rows before the failing one, and the
        # status counts them as a success counts its own (#998, #2245).
        (err_code, message) = decode_fv2_oer_error(resp[1])
        (row_count, _) = decode_fv2_dml_response(resp[1])
        rowid = None if err_code else decode_fv2_dml_rowid(resp[1])  # #1079
        batch_errors = decode_fv2_batch_errors(resp[1]) if batcherrors else []
        offset = decode_fv2_error_position(resp[1]) if err_code else 0  # #2263
        yield Send(encode_o7_close(0, cursor))  # still parsed, if cached
        yield RECV  # close STA
        status: tuple = (0, err_code, 0, (row_count, None), [], message, rowid)
        warnings = decode_fv2_warn_flags(resp[1])  # cursor.warning (#2262)
        if key is not None and cache is not None:
            yield from self._keep(cache, key, cursor, failed=bool(err_code))
        return (*status, batch_errors, None, offset, warnings)

    def _keep(self, cache: dict, key: tuple, cursor: int, failed: bool):
        # Remember a cached statement's cursor (LRU, the 10g+ cap), or forget it
        # if its execute failed: the server has dropped it (#709). An evicted
        # cursor is freed, so its slot comes back.
        cache.pop(key, None)
        if failed or not cursor or cursor == self._shared:
            return
        cache[key] = cursor
        while len(cache) > _FV2_CURSOR_CACHE_MAX:
            oldest = next(iter(cache))
            yield from self._free(cache.pop(oldest))

    def flush_cursors(self, cache: dict):
        # Free every cached cursor: DDL or a PL/SQL block may invalidate them,
        # and a stale one re-executed reused an old LONG-class value (#720).
        cursors = list(cache.values())
        cache.clear()
        for cursor in cursors:
            yield from self._free(cursor)

    def _free(self, cursor: int):
        yield Send(encode_o7_free(0, cursor))
        yield RECV

    def server_version(self):
        # The packed release, which the 9i login leaves out (#2278).
        yield Send(encode_o7_version(0))
        reply = yield RECV
        return decode_fv2_version(reply[1]) if reply else 0

    def execute_block(self, sql: str, bind: list | None = None):
        # Anonymous PL/SQL block over the fv2 TTI_ALL7 block path (#102, PROTOCOL
        # §19.6 / §19.7). OOPEN, then encode_o7_block parse-executes the block with
        # an OAC per bind (no inline values). The server replies with a bind
        # prompt; the client sends the INPUT values (IN + IN OUT, position order)
        # as a standalone RXD, and the reply carries any OUT / IN OUT return values
        # (an RXD before the RPA + OER). A pure-OUT block packs prompt + returns +
        # status in one packet and expects no input; a no-bind block returns the
        # RPA + OER directly. OUT values ride back as an {out_positions, out_values}
        # record the cursor's _assign_out_binds decodes into the Var objects.
        from seerdb.common.datatypes import Var

        bind = bind or []
        # What the caller's binds suggest: every plain value and every Var holding
        # one is an input, every Var an output. The server's bind prompt says
        # which each bind really is, and replaces this guess below.
        input_values = [
            _block_input(b) for b in bind if not isinstance(b, Var) or b.has_value
        ]
        out_positions = [i for i, b in enumerate(bind) if isinstance(b, Var)]
        cursor = yield from self._shared_cursor()
        yield Send(encode_o7_block(0, sql, bind, Cursor=cursor))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i PL/SQL block')
        packet = resp[1]
        # The server returns values only for the binds the block writes, and
        # takes inputs only for those it reads. A Var used only as input counted
        # as an output shifted every value after it, decoding the next bind's
        # bytes as the wrong type (#1242). Its prompt names each bind's
        # direction, in bind order, so follow that.
        directions = decode_fv2_bind_directions(packet)
        if directions is not None and len(directions) != len(bind):
            directions = None  # not this block's prompt: keep the guess
        if directions is not None:
            input_values = [
                _block_input(b) for b, d in zip(bind, directions) if d & FV2_BIND_IN
            ]
            out_positions = [i for i, d in enumerate(directions) if d & FV2_BIND_OUT]
        if input_values:
            # `packet` is the bind prompt (or an OER on a compile error). Send the
            # input values; the reply carries OUT values + RPA + OER.
            fv2_raise_for_error(packet, end_of_fetch_ok=False, with_offset=True)
            yield Send(encode_tokens_rxd(input_values, b''))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i PL/SQL bind send')
            packet = resp[1]
        # A block's ORA-01403 is a real error, not an end of fetch (#1039).
        fv2_raise_for_error(  # ORA-06512, 01403 …
            packet, end_of_fetch_ok=False, with_offset=True
        )
        (out_values, row_count, err_code) = decode_fv2_block_out(
            packet, len(out_positions)
        )
        yield Send(encode_o7_close(0, cursor))
        yield RECV  # close STA
        _raise_terminal(err_code)
        # A REF CURSOR comes back as its server cursor's id. Its rows are read
        # here, by that id, and travel with the marker the cursor wraps (#2246).
        # Then it is freed, as ojdbc14 frees it: only closed, every call that
        # returned one left a cursor open (#2288).
        for i, pos in enumerate(out_positions):
            if _is_cursor_var(bind[pos]) and out_values[i]:
                cursor_id = decode_ub4(out_values[i])[0]
                (columns, rows) = yield from self._drain(cursor_id)
                yield from self._free(cursor_id)
                out_values[i] = _cursor_marker(cursor_id, columns, rows)
        # The prompt's masks are the 10g+ IOV's (OUT 0x10, IN 0x20), and they
        # are what cursor.bind_directions reports, for a block whose binds are
        # all IN too (#1064, #2264).
        if out_positions:
            record: dict = {'out_positions': out_positions, 'out_values': out_values}
            record['directions'] = directions
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        if directions:
            record = {'out_positions': [], 'out_values': [], 'directions': directions}
            return (0, 0, 0, (row_count, None), [record], None, None, [], None)
        return (0, 0, 0, (row_count, None), [], None, None, [], None)

    def resolve_lobs(self, rows: list, columns: list):
        # Replace LOB objects left by decode_fv2_exec_response with their content,
        # in place, by round-tripping each locator (#102). Done while the 9i cursor
        # is still open. A BFILE stays a locator, read when its read() is called:
        # reading it opens the file, so a missing one failed the fetch (#1103).
        from seerdb.common.lob import LOB
        from seerdb.common.types import decode_fv2_lob, fv2_lob_charset

        if self.keep_lobs:
            return  # LOB objects, read through their own calls (#2259)
        for row in rows:
            for i, val in enumerate(row):
                if isinstance(val, LOB) and val.data_type != TNS_TYPE_BFILE:
                    content = yield from self.lob_read(val.raw)
                    # In the session's charset, not the column's (#2383).
                    row[i] = decode_fv2_lob(
                        columns[i].get('data_type'),
                        content,
                        fv2_lob_charset(
                            columns[i].get('charset'), columns[i].get('csfrm')
                        ),
                    )

    def lob_read(self, locator: bytes, offset: int = 1, amount: int | None = None):
        # 9i CLOB/BLOB content read: the two-call TTI_LOBOPS GETLEN + READ
        # (PROTOCOL.md §19.5). Returns raw bytes (CLOB decoding happens in the
        # caller with the column charset). An empty LOB (amount 0) reads nothing.
        # A LOB object's read names its offset and amount (#2259); with no
        # amount, it reads to the end.
        if amount is None:
            yield Send(encode_o7_lob_getlen(0, locator))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i LOB GETLEN')
            amount = decode_fv2_lob_getlen(resp[1]) - offset + 1
        if amount <= 0:
            return b''
        yield Send(encode_o7_lob_read(0, locator, amount, offset))
        return (yield from self.read_lob_content())

    def lob_operation(
        self,
        locator: bytes,
        operation: int,
        amount: int = 0,
        offset: int = 0,
        data: bytes | None = None,
    ):
        # One 9i LOB call (#2259): its reply value -- a size, the amount a write
        # wrote, OPEN's mode, IS_OPEN's 1 or 0 -- and the locator it echoes, as
        # the server now sees it. An error comes back as a bare status.
        yield Send(
            encode_o7_lobop(
                0, locator, operation, Offset=offset, Amount=amount, Data=data
            )
        )
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i LOB call')
        fv2_raise_for_error(resp[1])
        return decode_fv2_lob_value(resp[1], operation)

    def bfile_read(self, locator: bytes):
        # 9i BFILE read: FILE_OPEN → GETLEN → READ → FILE_CLOSE over TTI_LOBOPS
        # (PROTOCOL §19.8). FILE_OPEN returns an *updated* locator (open flag set);
        # GETLEN/READ/CLOSE must use that one. The FILE_CLOSE runs in a finally so
        # an opened file is always closed even if the read fails.
        yield Send(encode_o7_bfile_open(0, locator))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i BFILE FILE_OPEN')
        fv2_raise_for_error(resp[1])  # e.g. ORA-22285
        opened = decode_fv2_opened_locator(resp[1])
        if opened is None:
            raise Exception('Unexpected 9i BFILE FILE_OPEN reply', resp[1][:8].hex())
        try:
            yield Send(encode_o7_lob_getlen(0, opened))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i BFILE GETLEN')
            amount = decode_fv2_lob_getlen(resp[1])
            if amount <= 0:
                return b''
            yield Send(encode_o7_lob_read(0, opened, amount))
            return (yield from self.read_lob_content())
        finally:
            yield Send(encode_o7_bfile_close(0, opened))
            yield RECV  # drain FILE_CLOSE RPA + OER

    def read_lob_content(self):
        # Read a 9i TTI_LOBOPS READ reply by accumulating packets and re-parsing
        # with decode_fv2_lob_chunks until it reports the zero-length terminator.
        # The fv2 reply carries no OER call-status, so that terminator (not an OER)
        # is the stop signal. (#102)
        data = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during 9i LOB READ')
            data += received[1]
            (content, complete) = decode_fv2_lob_chunks(data)
            if complete:
                return content


def _raise_terminal(err_code: int) -> None:
    # Raise the ORA error carried by a terminal status (not success / no-data).
    if err_code and err_code not in (0, ORA_NO_DATA_FOUND):
        from seerdb.common.exceptions import from_ora_code

        raise from_ora_code(err_code)(f'ORA-{err_code:05d}', code=err_code)


def _8i_fetch_ended(terminal: bytes) -> bool:
    # Whether an 8i query reply's status ends the fetch with ORA-01403; any
    # other error it carries is raised. Fetching past the 01403 draws
    # ORA-01002 (fetch out of sequence).
    (err_code, message) = decode_8i_terminal_error(terminal)
    if err_code == ORA_NO_DATA_FOUND:
        return True
    _raise_ora(err_code, message)
    return False


def _9i_oall8_fetch_ended(terminal: bytes) -> bool:
    # Whether a 9i OALL8 query reply's status ends the fetch with ORA-01403; any
    # other error it carries is raised (#792), as the 8i path does.
    (err_code, message) = decode_9i_oall8_terminal_error(terminal)
    if err_code == ORA_NO_DATA_FOUND:
        return True
    _raise_ora(err_code, message)
    return False


def _raise_ora(err_code: int, message: str | None) -> None:
    # Raise a mapped ORA error from a decoded (code, message) pair.
    if err_code:
        from seerdb.common.exceptions import from_ora_code

        raise from_ora_code(err_code)(message or f'ORA-{err_code:05d}', code=err_code)


class Oall8Dialect:
    """The native OALL8 (0x5e) wire dialect (#244, PROTOCOL.md §19.9-19.17),
    shared by Oracle 8i and the opt-in 9i OALL8 path (#716). Sans-io: driven by
    ``_drive``. It numbers each call from the connection's sequence, so it takes
    the connection's ``next_seq`` callable (colorless — a pure counter).

    The tiers subclass this: :class:`O8iDialect` for 8i and
    :class:`Fv2Oall8Dialect` for 9i. They share every wire method here and differ
    only in the DML request width (``_encode_dml`` — 8i is 32-bit, 9i 64-bit) and
    in which statement kinds they serve. The login path (short DTY + O3LOGON
    OSESSKEY for 8i) is selected in connection.py by ``isinstance(O8iDialect)``,
    so the 9i subclass — not being an O8iDialect — logs in as an ordinary 9i
    client."""

    def __init__(self, next_seq: Callable[[], int]) -> None:
        self._next_seq = next_seq
        # The cursors finished statements left open, closed in front of the
        # next call (#2286): 8i parses every statement on a new cursor and
        # keeps it until told, so a session ran out at open_cursors.
        self._to_close: list[int] = []

    def _finished(self, cursor: int) -> None:
        # A statement is done with its cursor: close it with the next call. A
        # statement the server refused at parse names cursor 0, having none.
        if cursor:
            self._to_close.append(cursor)

    # 8i reads every LOB's content at fetch time whatever fetch_lobs says: its
    # dialect serves no LOB object calls (#2259).
    keep_lobs = False

    def flush_cursors(self, cache: dict):
        # 8i keeps no cursor cache of its own (#2261), and the connection's map
        # is not this dialect's to clear: emptied before every PL/SQL block, the
        # 8i suite broke -- a DROP later answered ORA-01403 -- so it is left
        # exactly as it was.
        return
        yield  # unreachable -- makes this a generator, as the protocol has it

    # --- the per-version hooks (#798): 8i's here, 9.2's in Fv2Oall8Dialect. The
    # call sequences below are shared; only what goes on the wire differs.
    _wire = '8i'

    def _sql_text(self, sql: str) -> bytes:
        # The statement's text in the session's charset: 8i's is the database's.
        return encode_8i_sql_text(sql)

    def _close_frames(self, cursors: list[int]) -> bytes:
        # The close of finished cursors, one piggyback (#2286).
        return encode_8i_close_cursors(self._next_seq(), cursors)

    def _cursor_id(self, reply: bytes) -> int:
        return decode_8i_cursor_id(reply)

    def _terminal_error(self, reply: bytes) -> tuple[int, str | None]:
        return decode_8i_terminal_error(reply)

    def _error_offset(self, reply: bytes) -> int:
        # Where in the statement an error is: 8i's status carries none (#719).
        return 0

    def _fetch_ended(self, terminal: bytes) -> bool:
        return _8i_fetch_ended(terminal)

    def _terminal_complete(self, terminal: bytes) -> bool:
        return o8i_terminal_complete(terminal)

    def _dml_response(self, reply: bytes) -> tuple[int, int, str | None]:
        return decode_8i_dml_response(reply)

    def _decode_describe(self, buf: bytes) -> tuple[list, bytes]:
        return decode_8i_dcb_describe(buf)

    def _decode_rows(self, buf: bytes, columns: list, last_row: list | None) -> tuple:
        return decode_8i_exec_response(buf, columns, last_row)

    def _long_size(self, columns: list, fetch: int) -> int:
        # The fetch's LONG cap for a query with no LONG column: on 8i a prefetch
        # hint, the rows asked for.
        return fetch

    # --- the shared call sequences

    def _closing(self) -> bytes:
        # The close of every cursor waiting, piggybacked ahead of a call as
        # python-oracledb does on 10g+; empty when none waits. It takes its
        # sequence number first, so it must be built before the call it rides
        # on: `self._closing() + encode_...(self._next_seq(), ...)`.
        if not self._to_close:
            return b''
        (cursors, self._to_close) = (self._to_close, [])
        return self._close_frames(cursors)

    def execute_query(self, sql: str, bind: list | None = None, fetch: int = 15):
        # A SELECT: the OALL8 query (§19.9-10, #792). The reply is a TTI_DCB
        # describe and the first row batch; fetches by the cursor's id pull the
        # rest. Returns the same 9-tuple as Fv2Dialect.execute_query so the cursor
        # path is unchanged.
        yield Send(self._closing() + self._encode_query(self._sql_text(sql), bind))
        resp = yield RECV
        if resp is False:
            raise Exception(f'Connection closed during {self._wire} query response')
        packet = resp[1]
        # A rejected SELECT comes back as a TTI_OER (0x04) error, not the TTI_DCB
        # (0x10) describe -- surface the mapped ORA error rather than overrunning
        # the describe (#384). Refused at execute, it keeps its cursor: close it.
        if packet[:1] == bytes([TTI_OER]):
            self._finished(self._cursor_id(packet))
            (err_code, message) = self._terminal_error(packet)
            if err_code:
                from seerdb.common.exceptions import from_ora_code

                exc = from_ora_code(err_code)(
                    message or f'ORA-{err_code:05d}', code=err_code
                )
                exc.offset = self._error_offset(packet)  # #2263
                raise exc
            from seerdb.common.exceptions import DatabaseError

            raise DatabaseError(f'Oracle {self._wire} rejected the query (no ORA code)')
        (columns, rest) = yield from self._recv_describe(packet)
        (rows, terminal, last_row) = yield from self.recv_rows(rest, columns, None)
        cursor = self._cursor_id(terminal)
        try:
            if not self._fetch_ended(terminal):
                rows.extend(
                    (yield from self._fetch_rest(cursor, columns, last_row, fetch))
                )
            yield from self._read_nested(rows, columns)
        finally:
            self._finished(cursor)
        # CLOB / BLOB cells came back as locators: read their content while the
        # cursor is still open. A BFILE stays a locator, read on demand.
        yield from self.resolve_lobs(rows, columns)
        return (0, 0, 0, (len(rows), columns), rows, None, None, [], None)

    def _read_cursor(self, cursor: int, columns: list):
        # Every row of a cursor the server opened and described for us -- a REF
        # CURSOR OUT bind's, a CURSOR(...) column's -- fetched by its id, with the
        # cursors nested in its own rows, then closed with the next call (#798).
        try:
            rows = yield from self._fetch_rest(cursor, columns, None)
            yield from self._read_nested(rows, columns)
        finally:
            self._finished(cursor)
        yield from self.resolve_lobs(rows, columns)
        return rows

    def _read_nested(self, rows: list, columns: list):
        # A CURSOR(...) column's cell came back as its cursor's (id, columns), the
        # dialect's _decode_rows reading it so (9.2's; 8i's has none). Read each
        # while the parent is open -- ojdbc14 closes the parent last -- into the
        # marker the cursor wraps, as the compact path does (#2254).
        for j, col in enumerate(columns):
            if col.get('data_type') != TNS_TYPE_REFCURSOR:
                continue
            for row in rows:
                if isinstance(row[j], tuple):
                    (nested, nested_columns) = row[j]
                    nested_rows = yield from self._read_cursor(nested, nested_columns)
                    row[j] = _cursor_marker(nested, nested_columns, nested_rows)

    def _fetch_rest(
        self, cursor: int, columns: list, last_row: list | None, fetch: int = 15
    ):
        # Fetch an open cursor's remaining rows by its id, to the end of fetch: a
        # query's after its execute reply, or every row of a REF CURSOR a block
        # opened (#798). A LONG / LONG RAW column caps the value at the fetch's
        # long-size field and returns one row per fetch, so ask for the whole
        # value (#377).
        has_long = any(col.get('data_type') in _O8I_LONG_TYPES for col in columns)
        long_size = _LONG_WHOLE if has_long else self._long_size(columns, fetch)
        row_count = 1 if has_long else (fetch or 15)
        rows: list = []
        ended = False
        while cursor and not ended:
            yield Send(self._encode_fetch(cursor, row_count, long_size))
            (more, terminal, last_row) = yield from self.recv_rows(
                b'', columns, last_row
            )
            # A fetch that fails brings no rows and the error in its status.
            # Ending on the empty fetch alone returned the rows before it as the
            # whole result (#2314).
            ended = self._fetch_ended(terminal)
            if not more:
                break
            rows.extend(more)
        return rows

    def _recv_describe(self, packet: bytes):
        # The describe, read on across packets: the server caps each DATA packet
        # at the SDU with no end-of-message flag, and a wide select list -- the 45
        # columns of V$SESSION -- does not fit in one. Decoding the first packet
        # alone ran off its end with an IndexError (#1226). Read on only while a
        # field runs off the end (Truncated, or IndexError from an older
        # primitive), as recv_rows does for the row stream.
        #
        # A statement that fails as it executes can stop the describe partway:
        # 8i sends what fitted in the first packet, then the error as a TTI_OER
        # of its own and nothing more. That error is the answer, not more of
        # the describe.
        from seerdb.common.exceptions import Truncated

        buf = bytes(packet)
        while True:
            try:
                return self._decode_describe(buf)
            except (Truncated, IndexError):
                received = yield RECV
                if received is False:
                    raise Exception(
                        f'Connection closed during {self._wire} describe'
                    ) from None
                more = received[1]
                if more[:1] == bytes([TTI_OER]):
                    (err_code, message) = self._terminal_error(more)
                    if err_code and message:
                        _raise_ora(err_code, message)
                buf += more

    def recv_rows(self, buf: bytes, columns: list, last_row: list | None):
        # Read one logical execute/fetch response and decode its row stream. The
        # server caps each DATA packet at the SDU with no end-of-message flag, so
        # a LONG value (or wide batch) larger than the SDU spans several packets
        # with no framing signal (#377). Accumulate until the stream decodes
        # cleanly AND leaves a whole status -- a reply cut a few bytes short
        # decodes, and its tail then answered the next call (#2280).
        #
        # "Read more" is ONLY a field that ran off the end -- Truncated, the codec's
        # explicit signal for it (#849), or an IndexError from an older primitive.
        # Any OTHER DataError came from a message that is complete and holds a value
        # that genuinely does not decode, and must propagate: a BC date -- valid
        # Oracle data a Python datetime cannot hold -- hung for the full read
        # timeout instead of raising (#1061).
        from seerdb.common.exceptions import Truncated

        while True:
            try:
                (rows, terminal, last) = self._decode_rows(buf, columns, last_row)
                if terminal and self._terminal_complete(terminal):
                    return (rows, terminal, last)
            except (Truncated, IndexError):
                pass
            received = yield RECV
            if received is False:
                try:
                    return self._decode_rows(buf, columns, last_row)
                except (Truncated, IndexError):
                    # The connection closed on a genuinely incomplete message:
                    # nothing more is coming, so there are no rows to return. A
                    # value that is complete but bad still raises, as above.
                    return ([], b'', last_row)
            buf += received[1]

    def _recv_terminal(self, what: str):
        # A non-query reply, read on across packets until its status is whole (a
        # short reply arrives in one packet; this guards a split one, as the row
        # reader does, #2280).
        buf = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception(f'Connection closed during {self._wire} {what}')
            buf += received[1]
            if self._terminal_complete(buf):
                return buf

    def txn_control(self, statement: str):
        # Commit / rollback as an ordinary OALL8 statement: no modern TTI_COMMIT on
        # these sessions (#716). Driven by the connection when CAP_OWN_TXN is set.
        yield Send(
            self._closing() + self._encode_dml(self._sql_text(statement), O8I_STMT_TXN)
        )
        buf = yield from self._recv_terminal(statement)
        self._finished(self._cursor_id(buf))
        (_row_count, err_code, message) = self._dml_response(buf)
        _raise_ora(err_code, message)

    def capabilities(self) -> frozenset[str]:
        # 8i does query / DML / PL/SQL / LOB and drives its own COMMIT / ROLLBACK
        # (no modern TTI_COMMIT); no array DML.
        return frozenset({CAP_QUERY, CAP_DML, CAP_BLOCK, CAP_LOB, CAP_OWN_TXN})

    def _encode_query(self, sql_text: bytes, bind: list | None) -> bytes:
        # The OALL8 SELECT execute. 8i sends the 32-bit form; the 9i OALL8 dialect
        # overrides this to send the native 64-bit form (#792).
        return encode_8i_oall8_query(self._next_seq(), sql_text, bind)

    def _encode_fetch(self, cursor: int, count: int, long_size: int) -> bytes:
        # The OALL8 array fetch. 8i 32-bit; the 9i OALL8 dialect overrides it.
        return encode_8i_oall8_fetch(self._next_seq(), cursor, count, long_size)

    def _encode_dml(
        self, sql_text: bytes, stmt_type: int, bind: list | None = None
    ) -> bytes:
        # The OALL8 DML / DDL / txn request body (SQL already encoded via
        # encode_8i_sql_text). 8i sends the 32-bit OALL8 form; the 9i OALL8
        # dialect overrides this to send the native 64-bit form (#716/#790).
        return encode_8i_oall8_dml(self._next_seq(), sql_text, stmt_type, bind)

    def execute_dml(
        self,
        sql: str,
        bind: list | None = None,
        batch: list | None = None,
        batcherrors: bool = False,
        cache: dict | None = None,
    ):
        # 8i INSERT/UPDATE/DELETE and DDL (#360, §19.12): the same OALL8 as a
        # SELECT but with the statement-type option word and no fetch. The
        # affected-row count comes back in the response OER. (Autocommit: caller.)
        # No array DML here: the caller refuses a batch (refuse_pre10_batch).
        assert not batch
        stmt_type = o8i_stmt_type(sql.strip().upper())
        yield Send(
            self._closing() + self._encode_dml(encode_8i_sql_text(sql), stmt_type, bind)
        )
        received = yield RECV
        if received is False:
            raise Exception('Connection closed during 8i DML')
        self._finished(decode_8i_cursor_id(received[1]))
        (row_count, err_code, message) = decode_8i_dml_response(received[1])
        _raise_ora(err_code, message)
        rowid = decode_8i_dml_rowid(received[1])  # the touched row (#1079)
        return (0, 0, 0, (row_count, None), [], None, rowid, [], None)

    def execute_block(self, sql: str, bind: list | None = None):
        # 8i anonymous PL/SQL block (#361/#362, §19.13-14): the same OALL8 as DML
        # with the BEGIN/DECLARE statement type. IN bind values ride inline, so the
        # block runs in one round trip — the reply is the bind prompt then any
        # OUT-value RXD + RPA + OER. OUT / IN OUT binds are Var objects whose
        # returned values ride back and go to the cursor's _assign_out_binds.
        from seerdb.common.datatypes import Var

        bind = bind or []
        out_positions = [i for i, b in enumerate(bind) if isinstance(b, Var)]
        stmt_type = o8i_stmt_type(sql.strip().upper())
        yield Send(
            self._closing() + self._encode_dml(encode_8i_sql_text(sql), stmt_type, bind)
        )
        received = yield RECV
        if received is False:
            raise Exception('Connection closed during 8i PL/SQL block')
        packet = received[1]
        # 8i marks no packet as a reply's last: read on until the reply is whole.
        # Read alone, the first packet of a long OUT value's reply ran off its
        # end, and the rest answered the next call (#2334).
        while not o8i_block_complete(packet):
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during 8i PL/SQL block')
            packet += received[1]
        # The reply may open with a 0x0b bind prompt; decode_8i_dml_response
        # surfaces any ORA- error regardless (its rowcount is not meaningful here).
        (_row_count, err_code, message) = decode_8i_dml_response(packet)
        if err_code and packet[:1] in (bytes([TTI_OER]), bytes([TTI_RPA])):
            self._finished(decode_8i_cursor_id(packet))
        _raise_ora(err_code, message)
        # Values come back only for the binds the block writes; the prompt says
        # which, as on 9i (#1242), with the count in 8i's encoding.
        directions = decode_fv2_bind_directions(packet, O8i=True)
        if directions is not None and len(directions) == len(bind):
            out_positions = [i for i, d in enumerate(directions) if d & FV2_BIND_OUT]
        # Its cursor is in the status behind the prompt and the OUT values.
        self._finished(decode_8i_block_cursor(packet, len(out_positions)))
        if out_positions:
            out_values = decode_8i_block_out(packet, len(out_positions))
            record = {'out_positions': out_positions, 'out_values': out_values}
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        return (0, 0, 0, (0, None), [], None, None, [], None)

    def resolve_lobs(self, rows: list, columns: list):
        # Replace each LOB locator left by decode_8i_exec_response with its content:
        # read the locator, decode CLOB text with the column charset (latin-1) and
        # keep BLOB bytes (decode_fv2_lob, shared with the 9i path). A BFILE stays
        # a locator, read on demand as on 9i (#1103).
        from seerdb.common.lob import LOB
        from seerdb.common.types import decode_fv2_lob

        for row in rows:
            for i, val in enumerate(row):
                if isinstance(val, LOB) and val.data_type != TNS_TYPE_BFILE:
                    content = yield from self.lob_read(val.raw)
                    row[i] = decode_fv2_lob(
                        columns[i].get('data_type'),
                        content,
                        self._clob_charset(columns[i]),
                    )

    def _clob_charset(self, column: dict) -> int:
        # The charset a CLOB's text comes in: the session's (#2383). 8i's whole
        # session is the single-byte database charset, national data too (#366).
        # Its describe gives a CLOB column charset 0, which decoded as UTF-8 and
        # turned 'é' into U+FFFD.
        return ISO_LATIN_1_CHARSET

    def lob_read(self, locator: bytes):
        # 8i CLOB/BLOB content read (#364, §19.15): a single TTI_LOBOPS READ (8i
        # reads the whole value at once, unlike 9i's GETLEN + READ). The reply is
        # the shared `0e fe <chunks> 00` form, which may span packets.
        yield Send(encode_8i_lob_read(self._next_seq(), locator, 1 << 30))
        data = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during 8i LOB read')
            data += received[1]
            # An empty LOB (EMPTY_CLOB / EMPTY_BLOB) has no TTI_LOB (0x0e) content
            # block — the server replies with a bare 0x08 piggyback — so there is
            # no zero-length chunk to wait for; report it empty (#387).
            if data[0] != TTI_LOB:
                return b''
            (content, complete) = decode_fv2_lob_chunks(data)
            if complete:
                return content

    def bfile_read(self, locator: bytes):
        # Native 8i BFILE read (#401, §19.17): FILE_OPEN → GETLEN → READ →
        # FILE_CLOSE over TTI_LOBOPS, no DBMS_LOB helper. FILE_OPEN returns the
        # open-flagged locator the rest reuse (decode_fv2_opened_locator, shared
        # with 9i). FILE_CLOSE runs in a finally so the file is always closed.
        yield Send(encode_o8i_bfile_open(self._next_seq(), locator))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 8i BFILE FILE_OPEN')
        # A file that does not open is answered with an 8i status alone; one
        # that does, with the LOBOPS RPA. The 9i reader missed the error,
        # unseen while a fetch read the BFILE (#1103).
        if resp[1][:1] == bytes([TTI_OER]):
            # e.g. ORA-22285 (no such directory)
            _raise_ora(*decode_8i_terminal_error(resp[1]))
        opened = decode_fv2_opened_locator(resp[1])
        if opened is None:
            raise Exception('Unexpected 8i BFILE FILE_OPEN reply', resp[1][:8].hex())
        try:
            yield Send(encode_o8i_bfile_getlen(self._next_seq(), opened))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 8i BFILE GETLEN')
            amount = decode_o8i_bfile_getlen(resp[1])
            if amount <= 0:
                return b''
            yield Send(encode_8i_lob_read(self._next_seq(), opened, amount))
            return (yield from self.read_lob_content())
        finally:
            yield Send(encode_o8i_bfile_close(self._next_seq(), opened))
            yield RECV  # drain FILE_CLOSE RPA + OER

    def read_lob_content(self):
        # Accumulate an 8i TTI_LOBOPS READ reply until decode_fv2_lob_chunks reports
        # the zero-length terminator (used by the BFILE read, where the amount is
        # known non-zero, so no empty-LOB shortcut is needed).
        data = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during 8i LOB READ')
            data += received[1]
            (content, complete) = decode_fv2_lob_chunks(data)
            if complete:
                return content


class O8iDialect(Oall8Dialect):
    """Oracle 8i (8.1.7): the OALL8 wire dialect with the 8i login path (the
    short _DTY_8I capability block and the O3LOGON OSESSKEY envelope, selected in
    connection.py by ``isinstance(O8iDialect)``). It adds nothing to the shared
    base — 8i uses the 32-bit ``_encode_dml`` the base provides — but is its own
    type so the login tier stays detectable and the 9i OALL8 dialect distinct."""


class Fv2Oall8Dialect(Oall8Dialect):
    """Oracle 9i over the native 64-bit OALL8 (0x5e), opt-in and experimental
    (#716/#790). The session authenticates as an ordinary 9i client (it is not an
    O8iDialect) and then speaks the native thick (OCI) wire.

    Served: SELECT (with scalar binds, positional and named, temporal and
    interval ones too) including LONG, ROWID / UROWID, CLOB / BLOB and BFILE
    columns, INSERT/UPDATE/DELETE and DDL under its own commit/rollback, PL/SQL
    blocks with IN, OUT, IN OUT and REF CURSOR binds, and DML...RETURNING
    (through its PL/SQL wrap) -- all over the native 64-bit OALL8 reply decode
    (decode_9i_oall8_*), array DML and LOB objects (fetch_lobs=False).
    Synchronous only, and no cursor cache. Not yet: nested cursors (CURSOR()
    columns) and object / collection types."""

    def _clob_charset(self, column: dict) -> int:
        # The native OALL8 session is AL32UTF8 like the compact 9i one, so its
        # CLOB text is too (#2383), not the 8i base's Latin-1.
        from seerdb.common.types import fv2_lob_charset

        return fv2_lob_charset(column.get('charset'), column.get('csfrm'))

    # --- the 9.2 hooks for the shared call sequences in Oall8Dialect (#798)
    _wire = '9i OALL8'

    def _sql_text(self, sql: str) -> bytes:
        # UTF-8, the session's negotiated charset (#797).
        return encode_9i_sql_text(sql)

    def _close_frames(self, cursors: list[int]) -> bytes:
        # The 64-bit close a native 9.2 OCI client sends, one piggyback a cursor,
        # each taking a sequence number (#798); the 8i form broke the session.
        return b''.join(
            encode_9i_oall8_close_cursors(self._next_seq(), [cursor])
            for cursor in cursors
        )

    def _cursor_id(self, reply: bytes) -> int:
        return decode_9i_oall8_cursor_id(reply)

    def _terminal_error(self, reply: bytes) -> tuple[int, str | None]:
        return decode_9i_oall8_terminal_error(reply)

    def _error_offset(self, reply: bytes) -> int:
        return decode_9i_oall8_error_position(reply)  # #2263

    def _fetch_ended(self, terminal: bytes) -> bool:
        return _9i_oall8_fetch_ended(terminal)

    def _terminal_complete(self, terminal: bytes) -> bool:
        return o9i_oall8_terminal_complete(terminal)

    def _dml_response(self, reply: bytes) -> tuple[int, int, str | None]:
        return decode_9i_oall8_dml_response(reply)

    def _decode_describe(self, buf: bytes) -> tuple[list, bytes]:
        return decode_9i_oall8_describe(buf)

    def _decode_rows(self, buf: bytes, columns: list, last_row: list | None) -> tuple:
        return decode_9i_oall8_exec_response(buf, columns, last_row)

    def _long_size(self, columns: list, fetch: int) -> int:
        # The widest column's buffer + 1, as the native 9.2 client sends: a huge
        # value made the server return nothing at more than one row (#792).
        return max((col.get('data_length') or 0) for col in columns) + 1

    def capabilities(self) -> frozenset[str]:
        # SELECT, DML / DDL, PL/SQL blocks and own commit/rollback over the native
        # 64-bit OALL8 (#792/#716/#793): the request is the 64-bit execute
        # (byte-verified), the reply the OCI fixed-width DCB / RXH / RXD / OER stream
        # (decode_9i_oall8_*), decoded by the overrides below. Commit/rollback ride
        # the OALL8 as ordinary statements (CAP_OWN_TXN), as 8i does -- the 8i and
        # thin-9i close frames both break an OALL8 session, and so does the modern
        # TTI_COMMIT, so this session drives its own transaction. CLOB / BLOB
        # content is read at fetch time (CAP_LOB); BFILE, kept-open LOB objects and
        # array DML are follow-ups.
        return frozenset(
            {
                CAP_QUERY,
                CAP_DML,
                CAP_BLOCK,
                CAP_LOB,
                CAP_OWN_TXN,
                CAP_ARRAY_DML,
                CAP_LOB_OBJECT,
            }
        )

    def _encode_query(self, sql_text: bytes, bind: list | None) -> bytes:
        # Native 64-bit OALL8 SELECT execute (FETCH option, byte-verified #792).
        return encode_9i_oall8_query(self._next_seq(), sql_text, bind)

    def _encode_fetch(self, cursor: int, count: int, long_size: int) -> bytes:
        # Native 64-bit OALL8 array fetch (byte-verified #792). `long_size` caps a
        # column's bytes per row; a huge value makes the 9.2 server return nothing,
        # so the caller passes the widest column's buffer (+1), not 0x7FFFFFFF.
        return encode_9i_oall8_fetch(self._next_seq(), cursor, count, long_size)

    def lob_read(self, locator: bytes, offset: int = 1, amount: int | None = None):
        # CLOB / BLOB content over a native 9i OALL8 session (#795): one 64-bit
        # TTI_LOBOPS READ (encode_9i_oall8_lob_read) from `offset` -- a large amount
        # reads the whole value in one call, as on 8i. The reply is the shared
        # `0e fe <chunks> 00` form, which may span packets; an empty LOB has no
        # TTI_LOB block (a bare piggyback), so it reads as empty.
        yield Send(
            encode_9i_oall8_lob_read(
                self._next_seq(),
                locator,
                (1 << 30) if amount is None else amount,
                offset,
            )
        )
        data = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during 9i OALL8 LOB read')
            data += received[1]
            if data[0] != TTI_LOB:
                return b''
            (content, complete) = decode_fv2_lob_chunks(data)
            if complete:
                return content

    def resolve_lobs(self, rows: list, columns: list):
        # CLOB / BLOB content in place of the locators, as on 8i -- unless the
        # connection keeps LOB objects (fetch_lobs=False), which read through
        # their own calls (lob_read / lob_operation, #798), as on the compact
        # 9i path (#2259).
        if self.keep_lobs:
            return
        yield from super().resolve_lobs(rows, columns)

    def lob_operation(
        self,
        locator: bytes,
        operation: int,
        amount: int = 0,
        offset: int = 0,
        data: bytes | None = None,
    ):
        # One LOB object call over a native 9i OALL8 session (#798), in the 64-bit
        # TTI_LOBOPS form (encode_9i_oall8_lobop): its reply value -- a size, the
        # amount a write wrote, OPEN's mode, IS_OPEN's 1 or 0 -- and the locator as
        # the server now sees it. An error (ORA-22920 for an unlocked row) is a bare
        # status, raised.
        yield Send(
            encode_9i_oall8_lobop(
                self._next_seq(), locator, operation, offset, amount, data
            )
        )
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i OALL8 LOB call')
        (value, updated) = decode_9i_oall8_lob_value(resp[1], operation)
        if not updated:
            (err_code, message) = decode_9i_oall8_terminal_error(resp[1])
            _raise_ora(err_code, message)
        return (value, updated or None)

    def bfile_read(self, locator: bytes):
        # BFILE read over a native 9i OALL8 session (#796): FILE_OPEN -> GET_LENGTH
        # -> READ -> FILE_CLOSE, as on 8i, each a 64-bit TTI_LOBOPS
        # (encode_9i_oall8_lobop). FILE_OPEN (read-only, mode 0x0b) answers with
        # the open-flagged locator the rest must use (decode_fv2_opened_locator);
        # GET_LENGTH's reply has the length where 8i's has it
        # (decode_o8i_bfile_getlen). A file or directory that cannot open is
        # answered with a status alone. FILE_CLOSE runs in a finally so an opened
        # file is always closed.
        yield Send(
            encode_9i_oall8_lobop(
                self._next_seq(), locator, TNS_LOB_OP_FILE_OPEN, 0, 0x0B
            )
        )
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i OALL8 BFILE FILE_OPEN')
        if resp[1][:1] == bytes([TTI_OER]):
            # e.g. ORA-22285 (no such directory)
            _raise_ora(*decode_9i_oall8_terminal_error(resp[1]))
        opened = decode_fv2_opened_locator(resp[1])
        if opened is None:
            raise Exception(
                'Unexpected 9i OALL8 BFILE FILE_OPEN reply', resp[1][:8].hex()
            )
        try:
            yield Send(
                encode_9i_oall8_lobop(self._next_seq(), opened, TNS_LOB_OP_GET_LENGTH)
            )
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i OALL8 BFILE GETLEN')
            amount = decode_o8i_bfile_getlen(resp[1])
            if amount <= 0:
                return b''
            return (yield from self.lob_read(opened, 1, amount))
        finally:
            yield Send(
                encode_9i_oall8_lobop(self._next_seq(), opened, TNS_LOB_OP_FILE_CLOSE)
            )
            yield RECV  # drain FILE_CLOSE RPA + OER

    def _encode_dml(
        self, sql_text: bytes, stmt_type: int, bind: list | None = None
    ) -> bytes:
        # Native 64-bit OALL8 DML / DDL / txn request (byte-verified #716).
        return encode_9i_oall8_dml(self._next_seq(), sql_text, stmt_type, bind)

    def execute_dml(
        self,
        sql: str,
        bind: list | None = None,
        batch: list | None = None,
        batcherrors: bool = False,
        cache: dict | None = None,
    ):
        # 9i native OALL8 INSERT / UPDATE / DELETE and DDL (#716): the 64-bit
        # execute with the statement-type option and no fetch; the affected-row
        # count comes back in the reply OER (decode_9i_oall8_dml_response, the row
        # count a ub4 at offset 6). Scalar binds ride the request (byte-verified).
        # An executemany's further rows ride the same call (#798), and the count
        # is then the whole batch's; in `batcherrors` mode the server applies the
        # good rows and lists the failures. No cursor cache. (Autocommit is applied
        # by the caller.)
        stmt_type = o8i_stmt_type(sql.strip().upper())
        yield Send(
            self._closing()
            + encode_9i_oall8_dml(
                self._next_seq(),
                encode_9i_sql_text(sql),
                stmt_type,
                bind,
                batch,
                batcherrors,
            )
        )
        buf = yield from self._recv_terminal('DML')
        self._finished(decode_9i_oall8_cursor_id(buf))  # closed with the next call
        # The error comes back in the result, as on the compact path, so the
        # cursor reports what the call managed: the rows a batch applied before a
        # failing one, and none for a statement that failed outright -- raised
        # here, it kept the count of the statement before (#998). The status
        # counts a batch's applied rows even when it fails (Applied).
        (row_count, err_code, message) = decode_9i_oall8_dml_response(
            buf, Applied=bool(batch)
        )
        rowid = None if err_code else decode_9i_oall8_dml_rowid(buf)  # #1079
        batch_errors = decode_9i_oall8_batch_errors(buf) if batcherrors else []
        # Where the error is (#2263), and the warning a CREATE that compiled with
        # errors carries (cursor.warning, #2262), as the compact path reports them.
        offset = decode_9i_oall8_error_position(buf) if err_code else 0
        return (
            0,
            err_code,
            0,
            (row_count, None),
            [],
            message,
            rowid,
            batch_errors,
            None,
            offset,
            decode_9i_oall8_warn_flags(buf),
        )

    def execute_block(self, sql: str, bind: list | None = None):
        # 9i native OALL8 anonymous PL/SQL block (#793/#794). The reply opens with a
        # TTI_IOV (0x0b) bind prompt when there are binds, then (when the block
        # writes OUT / IN OUT binds) a TTI_RXD of their values, then the RPA and OER
        # -- all in one packet, as the IN values ride inline in the request, so there
        # is no two-phase round trip. OUT values are read back by their bind position
        # and travel as an {out_positions, out_values} record the cursor turns into
        # the Vars' values; a block with no OUT bind returns the status alone.
        from seerdb.common.datatypes import Var

        bind = bind or []
        out_positions = [i for i, b in enumerate(bind) if isinstance(b, Var)]
        stmt_type = o8i_stmt_type(sql.strip().upper())
        yield Send(
            self._closing() + self._encode_dml(encode_9i_sql_text(sql), stmt_type, bind)
        )
        buf = yield from self._recv_terminal('PL/SQL block')
        # The prompt says which binds the block writes; only those come back. A
        # Var read only as input beside an OUT one was taken for OUT and shifted
        # the values (#1242). The masks are also cursor.bind_directions (#1064).
        directions = decode_9i_oall8_bind_directions(buf, len(bind))
        if directions is not None:
            out_positions = [i for i, d in enumerate(directions) if d & FV2_BIND_OUT]
        cursors = frozenset(
            i for (i, pos) in enumerate(out_positions) if _is_cursor_var(bind[pos])
        )
        # The block's own cursor, closed with the next call, read from its status
        # past the IOV and the OUT values (#798).
        self._finished(
            decode_9i_oall8_block_cursor(buf, len(bind), len(out_positions), cursors)
        )
        if out_positions:
            (out_values, _row_count, err_code, message) = decode_9i_oall8_block_out(
                buf, len(bind), len(out_positions), cursors
            )
            _raise_ora(err_code, message)
            # A REF CURSOR comes back opened and described, its rows unread: fetch
            # them by its id now, into the marker the cursor wraps, as the compact
            # path does (#2246).
            for i in cursors:
                if isinstance(out_values[i], tuple):
                    (cursor_id, columns) = out_values[i]
                    rows = yield from self._read_cursor(cursor_id, columns)
                    out_values[i] = _cursor_marker(cursor_id, columns, rows)
            record = {
                'out_positions': out_positions,
                'out_values': out_values,
                'directions': directions,
            }
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        (_row_count, err_code, message) = decode_9i_oall8_dml_response(
            buf[50 + len(bind) :] if directions is not None else buf
        )
        _raise_ora(err_code, message)
        if directions:
            record = {'out_positions': [], 'out_values': [], 'directions': directions}
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        return (0, 0, 0, (None, None), [], None, None, [], None)


# The column and bind types a pooled 11g session does not read yet (#2466):
# they come back in forms not measured against 11g. CLOB and BLOB columns are
# read (their locators, then the content); as binds they are not yet. A LONG
# or LONG RAW bind is: OCI sends it as a VARCHAR or a RAW of its size.
_OCI11_UNREAD_BINDS = {
    TNS_TYPE_BFILE: 'BFILE',
    TNS_TYPE_ADT: 'object or collection',
    TNS_TYPE_BLOB: 'BLOB',
    TNS_TYPE_CLOB: 'CLOB or NCLOB',
}
_OCI11_LOB_TYPES = frozenset({TNS_TYPE_CLOB, TNS_TYPE_BLOB})
_OCI11_UNREAD_TYPES = {
    TNS_TYPE_BFILE: 'BFILE',
    TNS_TYPE_ADT: 'object or collection',
}


def lob_object_charset(dialect: object, charset: int | None) -> int:
    """The charset a dialect's LOB object reads a CLOB's text in: UTF-16 on a
    pooled 11g session (#2466), the 9i session's otherwise (#2383)."""
    from seerdb.common.types import fv2_lob_charset

    if isinstance(dialect, Oci11Dialect):
        return dialect._clob_charset({'charset': charset})
    return fv2_lob_charset(charset)


def _oci11_unsupported(what: str):
    from seerdb.common.exceptions import NotSupportedError

    return NotSupportedError(
        f'{what} is not supported on a pooled Oracle 11g connection yet'
    )


class Oci11Dialect(Oall8Dialect):
    """A pooled Oracle 11g session, in the native form (#2466).

    11g's DRCP serves a pooled session only to a client in OCI's native form,
    so once the native login has run, every call is sqlplus 11.2's: the execute
    and the fetch at OCI's widths, COMMIT and ROLLBACK as statements, cursors
    closed in front of the next call. The call sequences are the native
    dialects' (Oall8Dialect); the hooks below are 11g's (encode_oci11_* /
    decode_oci11_*, measured against sqlplus 11.2 through 11g XE's pool). The
    rows are the native 9i form's, which 11g's are.

    Served: queries over scalar, CLOB, NCLOB and BLOB columns, DML and array
    DML, DDL, COMMIT and ROLLBACK, and PL/SQL blocks, with scalar IN, OUT and
    IN OUT binds of any size, LONG and LONG RAW ones too, and a LOB object's
    calls, temporary LOBs and LOB binds IN, OUT and IN OUT. Not yet, and
    refused before anything is sent: an array DML's RETURNING, an array DML's
    LOB Var, BFILE, a REF CURSOR bound IN or outside a block, and object binds,
    and BFILE and object columns (refused at the describe). LONG and LONG RAW
    columns are read a row a fetch, each value whole; a cursor the server opened
    (a REF CURSOR OUT bind's, a CURSOR(...) column's) with sqlplus's fetch."""

    _wire = '11g native'

    def __init__(
        self,
        next_seq: Callable[[], int],
        on_session: Callable[[int, int], None] | None = None,
        on_call_status: Callable[[int], None] | None = None,
    ) -> None:
        super().__init__(next_seq)
        # The rows an execute asks for with it, the cursor's arraysize.
        self._rows = 1
        # Told the pooled session's id and serial when the server hands it over
        # (its session return), which are not the login's.
        self._on_session = on_session
        # Told each reply's call status, the OER's first byte (its
        # TXN_IN_PROGRESS bit 0x02 says a transaction is open).
        self._on_call_status = on_call_status
        # The cursors the server opened that are being read: their fetches say
        # how wide the values are.
        self._opened: set[int] = set()

    def _session_return(self, reply: bytes) -> bytes:
        # The reply without the piggybacks ahead of it, the session return
        # among them reported.
        (ret, rest) = decode_oci11_piggybacks(reply)
        if ret is not None and self._on_session is not None:
            self._on_session(ret['session_id'], ret['serial'])
        return rest

    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                CAP_QUERY,
                CAP_DML,
                CAP_BLOCK,
                CAP_OWN_TXN,
                CAP_ARRAY_DML,
                CAP_LOB_OBJECT,
                CAP_WIDE_BINDS,
                CAP_TEMP_LOB,
            }
        )

    @staticmethod
    def _check_binds(bind: list | None, block: bool = False) -> None:
        # The binds this session sends: scalar values and Vars. A BFILE, REF
        # CURSOR or object Var travels in forms not measured against 11g. A LOB
        # Var goes by a locator: an unset one (OUT) the empty one, one with a
        # value through a temporary LOB (the cursor's), so a LOB Var still
        # holding a value here -- an array DML's row -- is not served, nor an
        # unset one outside a block, which has no OUT value to take. A REF
        # CURSOR Var is served OUT, in a block; an open cursor bound IN is not.
        from seerdb.common.datatypes import RefCursorBind, Var

        for value in bind or []:
            if isinstance(value, RefCursorBind):
                raise _oci11_unsupported('a REF CURSOR IN bind')
            if isinstance(value, Var) and value.dbtype.tns_type == TNS_TYPE_REFCURSOR:
                if not block:
                    raise _oci11_unsupported('a REF CURSOR bind outside a block')
                continue
            if not isinstance(value, Var) or (
                block
                and value.dbtype.tns_type in _OCI11_LOB_TYPES
                and not value.has_value
            ):
                continue
            if value.dbtype.tns_type in _OCI11_UNREAD_BINDS:
                name = _OCI11_UNREAD_BINDS[value.dbtype.tns_type]
                raise _oci11_unsupported(f'a {name} bind')

    @staticmethod
    def _cursor_outs(bind: list) -> frozenset[int]:
        # The positions whose OUT value is a cursor the block opened.
        return frozenset(i for (i, value) in enumerate(bind) if _is_cursor_var(value))

    @staticmethod
    def _lob_outs(bind: list) -> frozenset[int]:
        # The positions whose OUT value is a LOB's locator: a LOB Var, as itself
        # or as the temporary LOB it went out as.
        from seerdb.common.datatypes import TempLob, Var

        return frozenset(
            i
            for (i, value) in enumerate(bind)
            if isinstance(value, TempLob)
            or (isinstance(value, Var) and value.dbtype.tns_type in _OCI11_LOB_TYPES)
        )

    @staticmethod
    def _lob_out_value(value: object, locator: bytes | None):
        # A returned locator as the LOB object the Var takes, its type and
        # charset form the bind's.
        from seerdb.common.datatypes import TempLob
        from seerdb.common.lob import LOB

        if locator is None:
            return None
        if isinstance(value, TempLob):
            (data_type, csfrm) = (
                TNS_TYPE_BLOB if value.is_blob else TNS_TYPE_CLOB,
                value.csfrm,
            )
        else:
            dbtype = getattr(value, 'dbtype')
            (data_type, csfrm) = (dbtype.tns_type, getattr(dbtype, 'csfrm', 1))
        return LOB(data_type, locator, csfrm=csfrm)

    # --- the 11g hooks for the shared call sequences in Oall8Dialect

    def _sql_text(self, sql: str) -> bytes:
        return encode_9i_sql_text(sql)  # UTF-8, the session's charset

    def _close_frames(self, cursors: list[int]) -> bytes:
        return encode_oci11_close_cursors(self._next_seq(), cursors)

    def _status(self, reply: bytes) -> dict:
        status = decode_oci11_status(self._session_return(reply))
        if self._on_call_status is not None:
            self._on_call_status(status['status'])
        return status

    def _cursor_id(self, reply: bytes) -> int:
        return self._status(reply).get('cursor', 0)

    def _terminal_error(self, reply: bytes) -> tuple[int, str | None]:
        status = self._status(reply)
        return (status.get('error_code', 0), status.get('message'))

    def _error_offset(self, reply: bytes) -> int:
        return self._status(reply).get('error_pos', 0)

    def _fetch_ended(self, terminal: bytes) -> bool:
        # ORA-01403 ends the fetch; any other error is raised.
        (err_code, message) = self._terminal_error(terminal)
        if err_code == ORA_NO_DATA_FOUND:
            return True
        _raise_ora(err_code, message)
        return False

    def _terminal_complete(self, terminal: bytes) -> bool:
        from seerdb.common.exceptions import Truncated

        try:
            decode_oci11_status(terminal)
        except Truncated:
            return False
        return True

    def _dml_response(self, reply: bytes) -> tuple[int, int, str | None]:
        # A DML's affected rows ride the OER where a fetch's row count does.
        status = self._status(reply)
        return (
            status.get('row_kind', 0),
            status.get('error_code', 0),
            status.get('message'),
        )

    def _decode_describe(self, buf: bytes) -> tuple[list, bytes]:
        # A query that fails as the session's first call has its error behind
        # the session return, where the shared sequence looks for a describe.
        reply = self._session_return(buf)
        if reply[:1] == bytes([TTI_OER]):
            self._finished(self._cursor_id(reply))
            (err_code, message) = self._terminal_error(reply)
            from seerdb.common.exceptions import DatabaseError, from_ora_code

            if not err_code:
                raise DatabaseError('Oracle 11g rejected the query (no ORA code)')
            exc = from_ora_code(err_code)(
                message or f'ORA-{err_code:05d}', code=err_code
            )
            exc.offset = self._error_offset(reply)
            raise exc
        (columns, rest) = decode_oci11_describe(reply)
        for col in columns:
            if col['data_type'] in _OCI11_UNREAD_TYPES:
                name = _OCI11_UNREAD_TYPES[col['data_type']]
                raise _oci11_unsupported(f'a {name} column')
        return (columns, rest)

    def _decode_rows(self, buf: bytes, columns: list, last_row: list | None) -> tuple:
        return decode_oci11_rows(buf, columns, last_row)

    def _encode_query(self, sql_text: bytes, bind: list | None) -> bytes:
        self._check_binds(bind)
        return encode_oci11_execute(
            self._next_seq(), sql_text, O8I_STMT_SELECT, self._rows, bind
        )

    def _encode_fetch(self, cursor: int, count: int, long_size: int) -> bytes:
        # A query with a LONG or LONG RAW column fetches each row with the
        # OALL8 that says how much of the value to read; its execute brought
        # none (encode_oci11_long_fetch, sqlplus 11.2's). Any other, the plain
        # fetch.
        if long_size == _LONG_WHOLE:
            return encode_oci11_long_fetch(self._next_seq(), cursor, long_size)
        if cursor in self._opened:
            # A cursor the server opened -- a REF CURSOR's, a CURSOR(...)
            # column's -- fetched as sqlplus 11.2 fetches one: the OALL8 that
            # says how wide its values are (encode_oci11_cursor_fetch).
            return encode_oci11_cursor_fetch(self._next_seq(), cursor, count, long_size)
        return encode_oci11_fetch(self._next_seq(), cursor, count)

    def _long_size(self, columns: list, fetch: int) -> int:
        # The widest column's buffer and one, as sqlplus 11.2 sends a cursor's
        # fetch (the native 9.2 form's).
        return max((col.get('data_length') or 0) for col in columns) + 1

    def _read_cursor(self, cursor: int, columns: list):
        # A cursor the server opened, read with its own fetch while it is.
        self._opened.add(cursor)
        try:
            return (yield from super()._read_cursor(cursor, columns))
        finally:
            self._opened.discard(cursor)

    def _encode_dml(
        self, sql_text: bytes, stmt_type: int, bind: list | None = None
    ) -> bytes:
        self._check_binds(bind, block=stmt_type in (O8I_STMT_BEGIN, O8I_STMT_DECLARE))
        if stmt_type == O8I_STMT_TXN:
            # COMMIT and ROLLBACK, which 8i's table types as 0, have their own.
            stmt_type = oci11_stmt_type(
                sql_text.decode('utf-8', 'replace').strip().upper()
            )
        return encode_oci11_execute(self._next_seq(), sql_text, stmt_type, 1, bind)

    # --- the calls

    def execute_query(self, sql: str, bind: list | None = None, fetch: int = 15):
        # The execute brings the first `fetch` rows, as a fetch does.
        self._check_binds(bind)
        self._rows = fetch or 15
        return (yield from super().execute_query(sql, bind, fetch))

    def execute_dml(
        self,
        sql: str,
        bind: list | None = None,
        batch: list | None = None,
        batcherrors: bool = False,
        cache: dict | None = None,
    ):
        # INSERT / UPDATE / DELETE, DDL and transaction statements. The error
        # comes back in the result, as the other dialects return it, so the
        # cursor reports what the statement did.
        stmt_type = oci11_stmt_type(sql.strip().upper())
        self._check_binds(bind)
        for row in batch or []:
            self._check_binds(row)
        yield Send(
            self._closing()
            + encode_oci11_execute(
                self._next_seq(),
                self._sql_text(sql),
                stmt_type,
                1,
                bind,
                batch,
                batcherrors,
            )
        )
        buf = yield from self._recv_terminal('DML')
        status = self._status(buf)
        self._finished(status.get('cursor', 0))
        err_code = status.get('error_code', 0)
        applied = status.get('row_kind', 0)
        # A batch's count is the rows it applied, a failing one's too, and the
        # row it failed at is its error's offset, as python-oracledb reports it;
        # in batch-errors mode the failed rows come back as a list.
        if batch:
            offset = applied if err_code and not batcherrors else 0
            row_count = applied
        else:
            offset = status.get('error_pos', 0) if err_code else 0
            row_count = 0 if err_code else applied
        return (
            0,
            err_code,
            0,
            (row_count, None),
            [],
            status.get('message'),
            status.get('rowid'),  # the touched row, cursor.lastrowid
            status.get('batch_errors', []) if batcherrors else [],
            None,
            offset,
            status.get('warn_flags', 0),
        )

    # --- LOBs

    def _clob_charset(self, column: dict) -> int:
        # 11g sends a CLOB's text as UTF-16 to a native client, as it does to
        # the converted form (measured through the pool, #2466).
        from seerdb.common.tns_consts import AL16UTF16_CHARSET

        return AL16UTF16_CHARSET

    def resolve_lobs(self, rows: list, columns: list):
        # CLOB / BLOB content in place of the locators, unless the connection
        # keeps LOB objects (fetch_lobs, the default), whose calls are
        # lob_read and lob_operation below.
        if self.keep_lobs:
            return
        yield from super().resolve_lobs(rows, columns)

    def lob_read(self, locator: bytes, offset: int = 1, amount: int | None = None):
        # A LOB's content from `offset` (1-based): one native TTI_LOBOPS READ
        # asking for all of it, its reply read on across packets.
        from seerdb.common.exceptions import Truncated

        yield Send(
            encode_oci11_lob_read(
                self._next_seq(),
                locator,
                offset,
                (1 << 30) if amount is None else amount,
            )
        )
        buf = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during an 11g LOB read')
            buf += received[1]
            try:
                (content, rest) = decode_oci11_lob_read(buf, len(locator))
                status = self._status(rest)
            except Truncated:
                continue
            _raise_ora(status.get('error_code', 0), status.get('message'))
            return content

    def lob_operation(
        self,
        locator: bytes,
        operation: int,
        amount: int = 0,
        offset: int = 0,
        data: bytes | None = None,
    ):
        # A LOB object's other calls -- its size and chunk size, a write, a
        # trim, open, close and is-open -- as OCI 11.2 makes them through the
        # pool: one native TTI_LOBOPS each (encode_oci11_lobop), answered with
        # the call's value and the locator as the server now sees it, or, for
        # one that fails (ORA-22920 for a row not locked), the status alone.
        from seerdb.common.exceptions import Truncated

        if operation not in OCI11_LOB_CALLS:
            raise _oci11_unsupported('this LOB call')
        yield Send(
            encode_oci11_lobop(
                self._next_seq(), locator, operation, offset, amount, data
            )
        )
        buf = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during an 11g LOB call')
            buf += received[1]
            try:
                (value, updated, rest) = decode_oci11_lobop(buf, operation)
                status = self._status(rest)
            except Truncated:
                continue
            _raise_ora(status.get('error_code', 0), status.get('message'))
            return (value, updated)

    def create_temp_lob(self, is_blob: bool, csfrm: int = 1):
        # A temporary CLOB, NCLOB (csfrm 2) or BLOB of the session's duration,
        # as OCI 11.2's OCILobCreateTemporary makes one through the pool: one
        # native TTI_LOBOPS CREATE_TEMP (encode_oci11_create_temp), answered
        # with the new locator, its ub2 length in front.
        from seerdb.common.exceptions import Truncated

        yield Send(
            encode_oci11_create_temp(
                self._next_seq(),
                TNS_TYPE_BLOB if is_blob else TNS_TYPE_CLOB,
                0 if is_blob else csfrm,
            )
        )
        buf = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during an 11g CREATE_TEMP')
            buf += received[1]
            try:
                (locator, rest) = decode_oci11_create_temp(buf)
                status = self._status(rest)
            except Truncated:
                continue
            _raise_ora(status.get('error_code', 0), status.get('message'))
            if locator is None:
                raise Exception('An 11g CREATE_TEMP answered without a locator')
            return locator

    def execute_block(self, sql: str, bind: list | None = None):
        # An anonymous PL/SQL block, its binds inline. The reply opens with the
        # bind prompt when there are binds, which says each bind's direction,
        # then the OUT and IN OUT values, then the status (decode_oci11_block).
        # The values go back to the cursor by bind position, as on the native
        # 9i dialect; a block without OUT binds returns its status alone.
        bind = bind or []
        self._check_binds(bind, block=True)
        stmt_type = oci11_stmt_type(sql.strip().upper())
        yield Send(
            self._closing() + self._encode_dml(self._sql_text(sql), stmt_type, bind)
        )
        lobs = self._lob_outs(bind)
        cursors = self._cursor_outs(bind)
        buf = yield from self._recv_block(len(bind), lobs, cursors)
        (directions, out_values, rest, session) = decode_oci11_block(
            buf, len(bind), lobs, cursors
        )
        if session is not None and self._on_session is not None:
            self._on_session(session['session_id'], session['serial'])
        status = self._status(rest)
        self._finished(status.get('cursor', 0))
        _raise_ora(status.get('error_code', 0), status.get('message'))
        if directions is None:
            return (0, 0, 0, (None, None), [], None, None, [], None)
        out_positions = [i for i, d in enumerate(directions) if d & FV2_BIND_OUT]
        out_values = [
            self._lob_out_value(bind[pos], value) if pos in lobs else value
            for (pos, value) in zip(out_positions, out_values)
        ]
        # A REF CURSOR the block opened comes back as its (id, columns): its rows
        # are read now, by that id, and travel with the marker the cursor wraps,
        # as on the native 9i dialect.
        for i, pos in enumerate(out_positions):
            if pos in cursors and isinstance(out_values[i], tuple):
                (opened, columns) = out_values[i]
                rows = yield from self._read_cursor(opened, columns)
                out_values[i] = _cursor_marker(opened, columns, rows)
        record = {
            'out_positions': out_positions,
            'out_values': out_values,
            'directions': directions,
        }
        return (0, 0, 0, (None, None), [record], None, None, [], None)

    def _recv_block(
        self,
        num_binds: int,
        lobs: frozenset[int] = frozenset(),
        cursors: frozenset[int] = frozenset(),
    ):
        # A block's reply, read on across packets until it holds its prompt, its
        # OUT values and a whole status: a long OUT value spans packets.
        from seerdb.common.exceptions import Truncated

        buf = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during an 11g PL/SQL block')
            buf += received[1]
            try:
                (_, _, rest, _) = decode_oci11_block(buf, num_binds, lobs, cursors)
                decode_oci11_status(self._session_return(rest))
            except Truncated:
                continue
            return buf

    def bfile_read(self, locator: bytes):
        raise _oci11_unsupported('reading a BFILE')
        yield  # unreachable -- makes this a generator, as the protocol has it
