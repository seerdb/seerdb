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

from seerdb.common.tns import (
    FV2_BIND_IN,
    FV2_BIND_OUT,
    O8I_STMT_TXN,
    _scan_ora_message,
    decode_8i_block_out,
    decode_8i_cursor_id,
    decode_8i_dcb_describe,
    decode_8i_dml_response,
    decode_8i_exec_response,
    decode_fv2_bind_directions,
    decode_fv2_block_out,
    decode_fv2_describe,
    decode_fv2_dml_response,
    decode_fv2_exec_response,
    decode_fv2_lob_chunks,
    decode_fv2_lob_getlen,
    decode_fv2_oer_error,
    decode_fv2_opened_locator,
    decode_o8i_bfile_getlen,
    encode_8i_lob_read,
    encode_8i_oall8_dml,
    encode_8i_oall8_fetch,
    encode_8i_oall8_query,
    encode_o7_bfile_close,
    encode_o7_bfile_open,
    encode_o7_block,
    encode_o7_close,
    encode_o7_describe,
    encode_o7_exec,
    encode_o7_lob_getlen,
    encode_o7_lob_read,
    encode_o7_open,
    encode_o7_parse,
    encode_o8i_bfile_close,
    encode_o8i_bfile_getlen,
    encode_o8i_bfile_open,
    encode_tokens_rxd,
    o8i_stmt_type,
)
from seerdb.common.tns_consts import ORA_NO_DATA_FOUND, TTI_LOB, TTI_OER

# Oracle 8i LONG / LONG RAW type codes — a LONG changes the fetch shape (one row
# per round trip, read the whole value) (#377).
_O8I_LONG_TYPES = frozenset((8, 24))


class Send:
    """A wire intent: write ``data`` as a single TNS_DATA packet."""

    __slots__ = ('data',)

    def __init__(self, data: bytes) -> None:
        self.data = data


# The "receive the next data packet" intent. A bare sentinel — the driver returns
# ``_next_data_packet()``'s result (``(type, packet)`` or ``False``) back into the
# generator at the ``yield RECV`` site.
RECV = object()


def fv2_raise_for_error(packet: bytes, *, end_of_fetch_ok: bool = True) -> None:
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

        raise from_ora_code(err_code)(message or f'ORA-{err_code:05d}', code=err_code)


class Dialect(Protocol):
    """A pre-10g wire dialect as sans-io generators. Each ``execute_*`` yields
    :class:`Send` / :data:`RECV` intents and returns the same 9-tuple the modern
    execute path produces, so ``_drain_cursor`` and the cursor are unchanged."""

    def capabilities(self) -> frozenset[str]: ...
    def execute_query(self, sql: str, bind: list | None, fetch: int): ...
    def execute_dml(self, sql: str, bind: list | None): ...
    def execute_block(self, sql: str, bind: list | None): ...
    def txn_control(self, statement: str): ...  # only when CAP_OWN_TXN is set


# Capability tokens a dialect advertises via capabilities() — one honest place for
# "does this tier do array DML / its own commit / …" instead of ad-hoc branching.
CAP_QUERY = 'query'
CAP_DML = 'dml'
CAP_BLOCK = 'block'
CAP_LOB = 'lob'
CAP_ARRAY_DML = 'array_dml'
# The dialect drives its own COMMIT / ROLLBACK (8i has no modern TTI_COMMIT); a
# dialect without this capability leaves transaction control to the modern path.
CAP_OWN_TXN = 'own_txn'


class Fv2Dialect:
    """Oracle 9i (TTC field version 2) — the four-call TTI_ALL7 dialect (#102,
    PROTOCOL.md §19). Sans-io: driven by ``OracleConnect._drive`` (sync) or
    ``AsyncOracleConnect._drive`` (async)."""

    def capabilities(self) -> frozenset[str]:
        # 9i does query / DML / PL/SQL blocks / LOB, but NOT array DML
        # (executemany) — that's a 10g+ feature. It uses the modern commit path,
        # so it does NOT advertise CAP_OWN_TXN.
        return frozenset({CAP_QUERY, CAP_DML, CAP_BLOCK, CAP_LOB})

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
        yield Send(encode_o7_open(0))  # allocate a server cursor
        yield RECV  # OOPEN RPA (cursor id)
        yield Send(encode_o7_parse(0, sql, bind))
        resp = yield RECV  # parse RPA ack — or an OER
        if resp is not False:  # surface a parse error (e.g. ORA-00942)
            fv2_raise_for_error(resp[1])
        yield Send(encode_o7_describe(0))
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
        while True:
            yield Send(encode_o7_exec(0, columns))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i fetch')
            (rows, err_code) = decode_fv2_exec_response(resp[1], columns)
            all_rows.extend(rows)
            if err_code == ORA_NO_DATA_FOUND or not rows:
                break
        # Resolve LOB cells while the cursor is still open (JDBC does the same):
        # decode_fv2_exec_response left LOB objects in the rows; replace each with
        # its content.
        yield from self.resolve_lobs(all_rows, columns)
        yield Send(encode_o7_close(0))
        yield RECV  # close STA
        _raise_terminal(err_code)
        # call_status 0 + ora_code 0 => _drain_cursor won't issue TTI_FETCHes.
        return (0, 0, 0, (len(all_rows), columns), all_rows, None, None, [], None)

    def execute_dml(self, sql: str, bind: list | None = None):
        # 9i DML over TTI_ALL7 (#101): OOPEN, then a single parse that also
        # executes (option 02 80 21) — no describe/fetch. The affected-row count
        # comes back in the response OER. (Autocommit is applied by the caller.)
        yield Send(encode_o7_open(0))
        yield RECV  # OOPEN RPA
        yield Send(encode_o7_parse(0, sql, bind))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i DML')
        fv2_raise_for_error(resp[1])  # e.g. ORA-00942 / constraint
        (row_count, err_code) = decode_fv2_dml_response(resp[1])
        yield Send(encode_o7_close(0))
        yield RECV  # close STA
        _raise_terminal(err_code)
        return (0, 0, 0, (row_count, None), [], None, None, [], None)

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
            (b._value if isinstance(b, Var) else b)
            for b in bind
            if not isinstance(b, Var) or b.has_value
        ]
        out_positions = [i for i, b in enumerate(bind) if isinstance(b, Var)]
        yield Send(encode_o7_open(0))
        yield RECV  # OOPEN RPA
        yield Send(encode_o7_block(0, sql, bind))
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
        if directions is not None and len(directions) == len(bind):
            input_values = [
                (b._value if isinstance(b, Var) else b)
                for b, d in zip(bind, directions)
                if d & FV2_BIND_IN
            ]
            out_positions = [i for i, d in enumerate(directions) if d & FV2_BIND_OUT]
        if input_values:
            # `packet` is the bind prompt (or an OER on a compile error). Send the
            # input values; the reply carries OUT values + RPA + OER.
            fv2_raise_for_error(packet, end_of_fetch_ok=False)
            yield Send(encode_tokens_rxd(input_values, b''))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i PL/SQL bind send')
            packet = resp[1]
        # A block's ORA-01403 is a real error, not an end of fetch (#1039).
        fv2_raise_for_error(packet, end_of_fetch_ok=False)  # ORA-06512, 01403 …
        (out_values, row_count, err_code) = decode_fv2_block_out(
            packet, len(out_positions)
        )
        yield Send(encode_o7_close(0))
        yield RECV  # close STA
        _raise_terminal(err_code)
        if out_positions:
            record = {'out_positions': out_positions, 'out_values': out_values}
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        return (0, 0, 0, (row_count, None), [], None, None, [], None)

    def resolve_lobs(self, rows: list, columns: list):
        # Replace LOB objects left by decode_fv2_exec_response with their content,
        # in place, by round-tripping each locator (#102). Done while the 9i cursor
        # is still open.
        from seerdb.common.lob import LOB
        from seerdb.common.types import decode_fv2_lob

        for row in rows:
            for i, val in enumerate(row):
                if isinstance(val, LOB):
                    if val.data_type == 114:  # BFILE: open / read / close
                        content = yield from self.bfile_read(val.raw)
                    else:  # CLOB / BLOB: GETLEN + READ
                        content = yield from self.lob_read(val.raw)
                    row[i] = decode_fv2_lob(
                        columns[i].get('data_type'),
                        content,
                        columns[i].get('charset') or 0,
                    )

    def lob_read(self, locator: bytes):
        # 9i CLOB/BLOB content read: the two-call TTI_LOBOPS GETLEN + READ
        # (PROTOCOL.md §19.5). Returns raw bytes (CLOB decoding happens in the
        # caller with the column charset). An empty LOB (amount 0) reads nothing.
        yield Send(encode_o7_lob_getlen(0, locator))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i LOB GETLEN')
        amount = decode_fv2_lob_getlen(resp[1])
        if amount <= 0:
            return b''
        yield Send(encode_o7_lob_read(0, locator, amount))
        return (yield from self.read_lob_content())

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


def _raise_ora(err_code: int, message: str | None) -> None:
    # Raise a mapped ORA error from a decoded (code, message) pair.
    if err_code:
        from seerdb.common.exceptions import from_ora_code

        raise from_ora_code(err_code)(message or f'ORA-{err_code:05d}', code=err_code)


class O8iDialect:
    """Oracle 8i (8.1.7) — the 9.2-era OALL8 (0x5e) dialect (#244, PROTOCOL.md
    §19.9-19.17). Sans-io: driven by ``_drive``. Unlike 9i it numbers each call
    from the connection's sequence, so it takes the connection's ``next_seq``
    callable (colorless — a pure counter)."""

    def __init__(self, next_seq: Callable[[], int]) -> None:
        self._next_seq = next_seq

    def capabilities(self) -> frozenset[str]:
        # 8i does query / DML / PL/SQL / LOB and drives its own COMMIT / ROLLBACK
        # (no modern TTI_COMMIT); no array DML.
        return frozenset({CAP_QUERY, CAP_DML, CAP_BLOCK, CAP_LOB, CAP_OWN_TXN})

    def execute_query(self, sql: str, bind: list | None = None, fetch: int = 15):
        # 8i SELECT: the 9.2-era OALL8 query (§19.9-10). The reply is an 8i TTI_DCB
        # describe then a 9i-style RXH/RXD row stream. Row values are latin-1
        # (WE8ISO8859P1); the column charset drives decoding. Returns the same
        # 9-tuple as Fv2Dialect.execute_query so the cursor path is unchanged.
        yield Send(encode_8i_oall8_query(self._next_seq(), sql.encode('latin-1'), bind))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 8i query response')
        packet = resp[1]
        # A rejected SELECT comes back as a TTI_OER (0x04) error, not the TTI_DCB
        # (0x10) describe — surface the mapped ORA error rather than overrunning
        # decode_8i_dcb_describe (#384).
        if packet[:1] == bytes([TTI_OER]):
            (err_code, message) = _scan_ora_message(packet)
            if err_code:
                _raise_ora(err_code, message)
            from seerdb.common.exceptions import DatabaseError

            raise DatabaseError('Oracle 8i rejected the query (no ORA code)')
        (columns, rest) = yield from self._recv_describe(packet)
        # A LONG / LONG RAW column caps the value at the fetch long-size field and
        # returns one row per fetch, so ask for the whole value (#377).
        has_long = any(col.get('data_type') in _O8I_LONG_TYPES for col in columns)
        (rows, terminal, last_row) = yield from self.recv_rows(rest, columns, None)
        cursor = decode_8i_cursor_id(terminal)
        row_count = 1 if has_long else fetch
        long_size = 0x7FFFFFFF if has_long else fetch
        while cursor:
            yield Send(
                encode_8i_oall8_fetch(self._next_seq(), cursor, row_count, long_size)
            )
            (more, _terminal, last_row) = yield from self.recv_rows(
                b'', columns, last_row
            )
            if not more:
                break
            rows.extend(more)
        yield from self.resolve_lobs(rows, columns)
        return (0, 0, 0, (len(rows), columns), rows, None, None, [], None)

    def _recv_describe(self, packet: bytes):
        # The 8i describe, read on across packets: 8i caps each DATA packet at
        # the SDU with no end-of-message flag, and a wide select list -- the 45
        # columns of V$SESSION -- does not fit in one. Decoding the first packet
        # alone ran off its end with an IndexError (#1226). Read on only while
        # a field runs off the end (Truncated, or IndexError from an older
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
                return decode_8i_dcb_describe(buf)
            except (Truncated, IndexError):
                received = yield RECV
                if received is False:
                    raise Exception('Connection closed during 8i describe') from None
                more = received[1]
                if more[:1] == bytes([TTI_OER]):
                    (err_code, message) = _scan_ora_message(more)
                    if err_code and message:
                        _raise_ora(err_code, message)
                buf += more

    def recv_rows(self, buf: bytes, columns: list, last_row: list | None):
        # Read one logical 8i execute/fetch response and decode its RXH/RXD row
        # stream. 8i caps each DATA packet at the SDU with no end-of-message flag,
        # so a LONG value (or wide batch) larger than the SDU spans several packets
        # with no framing signal (#377). Accumulate until the stream decodes
        # cleanly AND leaves a non-empty terminal (a value split mid-boundary makes
        # the decoder raise DataError/IndexError; a clean split at a row boundary
        # leaves nothing after the rows — both mean "read more").
        #
        # "Read more" is ONLY a field that ran off the end -- Truncated, the codec's
        # explicit signal for it (#849), or an IndexError from an older primitive.
        # Any OTHER DataError came from a message that is complete and holds a value
        # that genuinely does not decode, and must propagate. Catching the whole
        # DataError family treated that as "incomplete" too: the loop read on for a
        # packet that was never coming, and a BC date -- valid Oracle data a Python
        # datetime cannot hold -- hung for the full read timeout instead of raising
        # (#1061). Same distinction the Mirror draws in _complete_message (#1000).
        from seerdb.common.exceptions import Truncated

        while True:
            try:
                (rows, terminal, last) = decode_8i_exec_response(buf, columns, last_row)
                if terminal:
                    return (rows, terminal, last)
            except (Truncated, IndexError):
                pass
            received = yield RECV
            if received is False:
                try:
                    return decode_8i_exec_response(buf, columns, last_row)
                except (Truncated, IndexError):
                    # The connection closed on a genuinely incomplete message:
                    # nothing more is coming, so there are no rows to return. A
                    # value that is complete but bad still raises, as above.
                    return ([], b'', last_row)
            buf += received[1]

    def execute_dml(self, sql: str, bind: list | None = None):
        # 8i INSERT/UPDATE/DELETE and DDL (#360, §19.12): the same OALL8 as a
        # SELECT but with the statement-type option word and no fetch. The
        # affected-row count comes back in the response OER. (Autocommit: caller.)
        stmt_type = o8i_stmt_type(sql.strip().upper())
        yield Send(
            encode_8i_oall8_dml(
                self._next_seq(), sql.encode('latin-1'), stmt_type, bind
            )
        )
        received = yield RECV
        if received is False:
            raise Exception('Connection closed during 8i DML')
        (row_count, err_code, message) = decode_8i_dml_response(received[1])
        _raise_ora(err_code, message)
        return (0, 0, 0, (row_count, None), [], None, None, [], None)

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
            encode_8i_oall8_dml(
                self._next_seq(), sql.encode('latin-1'), stmt_type, bind
            )
        )
        received = yield RECV
        if received is False:
            raise Exception('Connection closed during 8i PL/SQL block')
        packet = received[1]
        # The reply may open with a 0x0b bind prompt; decode_8i_dml_response
        # surfaces any ORA- error regardless (its rowcount is not meaningful here).
        (_row_count, err_code, message) = decode_8i_dml_response(packet)
        _raise_ora(err_code, message)
        # Values come back only for the binds the block writes; the prompt says
        # which, as on 9i (#1242), with 8i's bind count at offset 2.
        directions = decode_fv2_bind_directions(packet, CountAt=2)
        if directions is not None and len(directions) == len(bind):
            out_positions = [i for i, d in enumerate(directions) if d & FV2_BIND_OUT]
        if out_positions:
            out_values = decode_8i_block_out(packet, len(out_positions))
            record = {'out_positions': out_positions, 'out_values': out_values}
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        return (0, 0, 0, (0, None), [], None, None, [], None)

    def txn_control(self, statement: str):
        # 8i has no modern TTI_COMMIT / TTI_ROLLBACK: commit and rollback ride the
        # OALL8 as ordinary statements (§19.12, statement type 0).
        yield Send(
            encode_8i_oall8_dml(
                self._next_seq(), statement.encode('latin-1'), O8I_STMT_TXN
            )
        )
        received = yield RECV
        if received is False:
            raise Exception(f'Connection closed during 8i {statement}')
        (_row_count, err_code, message) = decode_8i_dml_response(received[1])
        _raise_ora(err_code, message)

    def resolve_lobs(self, rows: list, columns: list):
        # Replace each LOB locator left by decode_8i_exec_response with its content:
        # read the locator, decode CLOB text with the column charset (latin-1) and
        # keep BLOB bytes (decode_fv2_lob, shared with the 9i path).
        from seerdb.common.lob import LOB
        from seerdb.common.types import decode_fv2_lob

        for row in rows:
            for i, val in enumerate(row):
                if isinstance(val, LOB):
                    if val.data_type == 114:  # BFILE — external file pointer
                        row[i] = yield from self.bfile_read(val.raw)
                        continue
                    content = yield from self.lob_read(val.raw)
                    row[i] = decode_fv2_lob(
                        columns[i].get('data_type'),
                        content,
                        columns[i].get('charset') or 0,
                    )

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
        fv2_raise_for_error(resp[1])  # e.g. ORA-22285 (file not found)
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
