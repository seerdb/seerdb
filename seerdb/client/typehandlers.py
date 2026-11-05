# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Output type handlers and ``fetch_decimals``: what a fetched column becomes.

An ``outputtypehandler`` -- on the cursor, else on the connection -- is called
once per column when a statement's result set is described, as python-oracledb
calls it. It returns ``None`` (the column is fetched as usual) or a ``Var`` from
``cursor.var()``, whose type says what the column's values become and whose
``outconverter`` is applied to each of them.

Everything here is client-side. A value arrives decoded as it would without a
handler and is then converted, so no conversion changes what is asked of the
server. A CLOB / BLOB the handler wants as ``str`` / ``bytes`` is read through
the LOB it arrives as, where python-oracledb redefines the column for the server
to send inline; the values are the same.

Which conversions are accepted follows python-oracledb's table (measured against
26.1 thin on 23ai, 2026-11-05). One that isn't raises when the statement is
executed, as it does there.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from decimal import Decimal, InvalidOperation

from seerdb.common.datatypes import (
    DB_TYPE_BINARY_DOUBLE,
    DB_TYPE_BINARY_FLOAT,
    DB_TYPE_BINARY_INTEGER,
    DB_TYPE_BLOB,
    DB_TYPE_CHAR,
    DB_TYPE_CLOB,
    DB_TYPE_DATE,
    DB_TYPE_INTERVAL_DS,
    DB_TYPE_LONG,
    DB_TYPE_LONG_RAW,
    DB_TYPE_NCHAR,
    DB_TYPE_NCLOB,
    DB_TYPE_NUMBER,
    DB_TYPE_NVARCHAR,
    DB_TYPE_RAW,
    DB_TYPE_ROWID,
    DB_TYPE_TIMESTAMP,
    DB_TYPE_TIMESTAMP_LTZ,
    DB_TYPE_TIMESTAMP_TZ,
    DB_TYPE_UROWID,
    DB_TYPE_VARCHAR,
    Var,
)
from seerdb.common.exceptions import DatabaseError, DataError, ProgrammingError

_NUMERIC = frozenset(
    {
        DB_TYPE_NUMBER,
        DB_TYPE_BINARY_INTEGER,
        DB_TYPE_BINARY_FLOAT,
        DB_TYPE_BINARY_DOUBLE,
    }
)
_STRING = frozenset(
    {DB_TYPE_VARCHAR, DB_TYPE_CHAR, DB_TYPE_NVARCHAR, DB_TYPE_NCHAR, DB_TYPE_LONG}
)
_DATETIME = frozenset(
    {DB_TYPE_DATE, DB_TYPE_TIMESTAMP, DB_TYPE_TIMESTAMP_TZ, DB_TYPE_TIMESTAMP_LTZ}
)
# Columns python-oracledb converts to text and to nothing else.
_TEXT_ONLY = frozenset({DB_TYPE_INTERVAL_DS, DB_TYPE_ROWID, DB_TYPE_UROWID})
_CLOBS = frozenset({DB_TYPE_CLOB, DB_TYPE_NCLOB})
_BYTES = frozenset({DB_TYPE_RAW, DB_TYPE_LONG_RAW})


class ColumnPlan:
    """What one column's fetched values go through."""

    __slots__ = ('convert', 'read_lob', 'outconverter', 'convert_nulls')

    def __init__(
        self,
        convert: Callable[[object], object] | None,
        read_lob: bool = False,
        outconverter: Callable[[object], object] | None = None,
        convert_nulls: bool = False,
    ):
        # The conversion to the requested type, or None when the value already
        # is that type.
        self.convert = convert
        # Whether a LOB the value arrives as is read first (a CLOB / BLOB the
        # handler wants as str / bytes).
        self.read_lob = read_lob
        self.outconverter = outconverter
        self.convert_nulls = convert_nulls


def _number_text(Value: object) -> object:
    # A NUMBER as python-oracledb's text for it: positional, never an exponent
    # ('-0.0000001', not '-1E-7').
    if isinstance(Value, Decimal):
        return format(Value, 'f')
    return str(Value)


def _parse_number(Value: object) -> Decimal:
    try:
        return Decimal(str(Value).strip())
    except InvalidOperation as Exc:
        raise DataError(f'cannot convert {Value!r} to a number') from Exc


def _to_decimal(Value: object) -> object:
    if isinstance(Value, Decimal):
        return Value
    if isinstance(Value, (int, float)) and not isinstance(Value, bool):
        # Through the decimal string for a float, as Var._as_requested does:
        # Decimal(1.1) is the exact binary value, not 1.1.
        return Decimal(str(Value)) if isinstance(Value, float) else Decimal(Value)
    return _parse_number(Value)


def _to_float(Value: object) -> object:
    if isinstance(Value, (int, float, Decimal)) and not isinstance(Value, bool):
        return float(Value)
    return float(_parse_number(Value))


def _to_integer(Value: object) -> object:
    # BINARY_INTEGER: the fractional part goes, toward zero, as int() does.
    if isinstance(Value, (int, float, Decimal)) and not isinstance(Value, bool):
        return int(Value)
    return int(_parse_number(Value))


def _to_number(Value: object) -> object:
    # A NUMBER as seerdb fetches one: int when whole, else Decimal. A binary
    # float stays a float, the type it was fetched as.
    if isinstance(Value, (int, float, Decimal)) and not isinstance(Value, bool):
        return Value
    Number = _parse_number(Value)
    return int(Number) if Number == Number.to_integral_value() else Number


def _numeric_converter(Target: object, PyType: object) -> Callable[[object], object]:
    if Target is DB_TYPE_BINARY_INTEGER:
        return _to_integer
    if Target in (DB_TYPE_BINARY_FLOAT, DB_TYPE_BINARY_DOUBLE) or PyType is float:
        return _to_float
    if PyType is Decimal:
        return _to_decimal
    return _to_number


def _refuse(Source: object, Target: object) -> None:
    raise DatabaseError(
        f'cannot convert a column of type {Source} to {Target} '
        '(the output type handler asked for it)'
    )


def plan_for_var(Source: object, V: Var) -> ColumnPlan:
    """The plan for a column of type `Source` fetched into `V`.

    Raises DatabaseError for a conversion python-oracledb refuses."""
    Target = V.dbtype
    PyType = V._pytype
    Convert: Callable[[object], object] | None = None
    ReadLob = False
    if Target in _STRING:
        if Source in _NUMERIC:
            Convert = _number_text
        elif Source in _DATETIME or Source in _TEXT_ONLY:
            Convert = str
        elif Source in _CLOBS:
            ReadLob = True
        elif Source not in _STRING:
            _refuse(Source, Target)
    elif Target in _NUMERIC:
        if Source in _NUMERIC or Source in _STRING:
            Convert = _numeric_converter(Target, PyType)
        else:
            _refuse(Source, Target)
    elif Target in _DATETIME:
        # DATE <-> TIMESTAMP keeps the value as fetched, fraction included, as
        # python-oracledb keeps it.
        if Source not in _DATETIME:
            _refuse(Source, Target)
    elif Target in _BYTES:
        if Source is DB_TYPE_BLOB:
            ReadLob = True
        elif Source not in _BYTES:
            _refuse(Source, Target)
    elif Target is not Source:
        _refuse(Source, Target)
    return ColumnPlan(
        Convert,
        read_lob=ReadLob,
        outconverter=V.outconverter,
        convert_nulls=V.convert_nulls,
    )


def _uses_metadata(Handler: object) -> bool:
    # python-oracledb's rule: a handler of two parameters takes (cursor,
    # metadata); any other is the older (cursor, name, default_type, size,
    # precision, scale) form.
    if not callable(Handler):
        return False
    try:
        return len(inspect.signature(Handler).parameters) == 2
    except (TypeError, ValueError):
        return False


def build_fetch_plan(
    Cursor: object, Description: list, FetchDecimals: bool
) -> list[ColumnPlan | None] | None:
    """One plan per column of a described result set, or None when no column
    needs one. Calls the output type handler, the cursor's else the
    connection's, once per column."""
    Handler = getattr(Cursor, 'outputtypehandler', None)
    if Handler is None:
        Handler = getattr(
            getattr(Cursor, '_connection', None), 'outputtypehandler', None
        )
    if Handler is None and not FetchDecimals:
        return None
    Metadata = _uses_metadata(Handler) if Handler is not None else False
    Plan: list[ColumnPlan | None] = []
    for Info in Description:
        V = None
        if Handler is not None:
            if Metadata:
                V = Handler(Cursor, Info)
            else:
                V = Handler(
                    Cursor,
                    Info.name,
                    Info.type_code,
                    getattr(Info, '_max_size', 0),
                    Info.precision or 0,
                    Info.scale or 0,
                )
        if V is not None:
            if not isinstance(V, Var):
                raise ProgrammingError(
                    'an output type handler must return None or a variable from '
                    f'cursor.var(), not {type(V).__name__}'
                )
            Plan.append(plan_for_var(Info.type_code, V))
        elif FetchDecimals and Info.type_code is DB_TYPE_NUMBER:
            Plan.append(ColumnPlan(_to_decimal))
        else:
            Plan.append(None)
    if all(P is None for P in Plan):
        return None
    return Plan


def lob_columns(Plan: list[ColumnPlan | None]) -> list[int]:
    """The columns whose LOB is read before the plan is applied."""
    return [I for I, P in enumerate(Plan) if P is not None and P.read_lob]


def apply_fetch_plan(Plan: list[ColumnPlan | None], Row: list | tuple) -> list:
    """`Row` with each column's plan applied. A LOB the plan reads has been read
    already (see lob_columns), so this does no I/O and serves both cursors."""
    Out = list(Row)
    for I, P in enumerate(Plan):
        if P is None:
            continue
        Value = Out[I]
        if Value is None:
            if P.outconverter is not None and P.convert_nulls:
                Out[I] = P.outconverter(None)
            continue
        if P.convert is not None:
            Value = P.convert(Value)
        if P.outconverter is not None:
            Value = P.outconverter(Value)
        Out[I] = Value
    return Out
