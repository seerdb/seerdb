# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Public value/marker types for binds and fetches that have no faithful stdlib
# equivalent. Kept in their own low-level module (stdlib-only imports) so both
# the encoder (`tns.py`) and the decoders (`types.py`) can import them without a
# circular dependency.

import datetime
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from seerdb.common.tns_consts import (
    TNS_TYPE_ADT,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFILE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INT,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REFCURSOR,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_UROWID,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
)

# ROWID is reported by the DCB describe with wire type code 11 (TNS_TYPE_ROWID
# = 104 is Oracle's other, bind-side rowid code). Keep a local name for the
# fetch code so the description map below is unambiguous.
TNS_TYPE_ROWID_FETCH = 11


class TempLob:
    """A bind marker for a server-side temporary LOB (#91).

    Large CLOB / BLOB values (> 32767 bytes) cannot be bound into a PL/SQL
    locator parameter through the regular streamed path — the server rejects
    them with ORA-01460. The driver instead allocates a temp LOB
    (TTI_LOBOPS CREATE_TEMP), streams the value into it (WRITE) and binds this
    marker, which carries the resulting locator. The bind encoder emits a
    CLOB / BLOB OAC plus the LOB-descriptor value (`01 28 28` + ub2 length +
    locator), the same descriptor framing the native VECTOR / JSON binds use.

    The OAC announces a fixed LOB buffer size, not the value's byte budget --
    python-oracledb sends its DB_TYPE buffer_size_factor for every temp-LOB bind
    regardless of the value, and a size of 0 makes the server bind NULL (#903).
    So the marker carries only the locator and its kind -- plus, when the value
    came from a `Var` the marker replaced on the bind list, that `Var`, so an
    OUT / IN OUT value still has somewhere to be written back to (#978).
    """

    __slots__ = ('locator', 'is_blob', 'var', 'csfrm')

    def __init__(
        self, locator: bytes, is_blob: bool, var: object = None, csfrm: int = 1
    ):
        self.locator = locator
        self.is_blob = is_blob
        self.var = var
        # The charset form: 2 for an NCLOB, 1 for a CLOB (and meaningless for a
        # BLOB). An NCLOB binds as a CLOB OAC that differs ONLY in this byte
        # (#1066), so without it the marker could not say which it was.
        self.csfrm = csfrm

    def __repr__(self) -> str:
        kind = 'BLOB' if self.is_blob else 'CLOB'
        return f'TempLob({kind}, {len(self.locator)}B locator)'


class BfileBind:
    """A bind marker for a BFILE bound IN by its locator, as fetched.

    python-oracledb binds one with the BFILE OAC -- type 114, the type's
    buffer of 4000, no LOB cont-flag, no charset -- and the locator in the LOB
    framing a CLOB's or BLOB's takes (a ub4 length, then the bytes with their
    length), measured against a live 21c. The marker holds the locator as a
    row carries it, its own ub2 length in front."""

    __slots__ = ('locator',)

    def __init__(self, locator: bytes):
        self.locator = locator

    def __repr__(self) -> str:
        return f'BfileBind({len(self.locator)}B locator)'


class _DbType:
    """An Oracle bind type usable as a `cursor.var()` / OUT-bind type spec."""

    __slots__ = ('name', 'tns_type', 'default_size', 'csfrm')

    def __init__(self, name: str, tns_type: int, default_size: int, csfrm: int = 1):
        self.name = name
        self.tns_type = tns_type
        self.default_size = default_size
        # Character-set form: 1 = database charset (default), 2 = national
        # charset (NCHAR / NVARCHAR2 → AL16UTF16). #174.
        self.csfrm = csfrm

    def __repr__(self) -> str:
        return self.name


# oracledb-compatible type-constant aliases for cursor.var() / OUT binds.
# The default sizes are the fixed wire widths the server reserves for each
# scalar OUT value (matching the value-sized OAC in tns.encode_token_oac).
DB_TYPE_NUMBER = NUMBER = _DbType('DB_TYPE_NUMBER', TNS_TYPE_NUMBER, 22)
DB_TYPE_VARCHAR = STRING = _DbType('DB_TYPE_VARCHAR', TNS_TYPE_VARCHAR, 32767)
# National-charset string types (#174): csfrm 2 → AL16UTF16. Bind a str through
# cursor.var(seerdb.DB_TYPE_NVARCHAR) / DB_TYPE_NCHAR to target an NVARCHAR2 /
# NCHAR column. Needed on 9i (a non-Unicode DB charset can't store all of
# Unicode, but the national charset can); harmless on 10g+.
DB_TYPE_NVARCHAR = _DbType('DB_TYPE_NVARCHAR', TNS_TYPE_VARCHAR, 32767, csfrm=2)
DB_TYPE_NCHAR = _DbType('DB_TYPE_NCHAR', TNS_TYPE_CHAR, 32767, csfrm=2)
DB_TYPE_RAW = _DbType('DB_TYPE_RAW', TNS_TYPE_RAW, 32767)
DB_TYPE_DATE = _DbType('DB_TYPE_DATE', TNS_TYPE_DATE, 7)
DB_TYPE_CURSOR = CURSOR = _DbType('DB_TYPE_CURSOR', TNS_TYPE_REFCURSOR, 1)
DB_TYPE_TIMESTAMP = _DbType('DB_TYPE_TIMESTAMP', TNS_TYPE_TIMESTAMP, 11)
DB_TYPE_TIMESTAMP_TZ = _DbType('DB_TYPE_TIMESTAMP_TZ', TNS_TYPE_TIMESTAMPTZ, 13)
DB_TYPE_BINARY_FLOAT = _DbType('DB_TYPE_BINARY_FLOAT', TNS_TYPE_BFLOAT, 4)
DB_TYPE_BINARY_DOUBLE = _DbType('DB_TYPE_BINARY_DOUBLE', TNS_TYPE_BDOUBLE, 8)
# PL/SQL BINARY_INTEGER / PLS_INTEGER (#1044). It travels as an Oracle NUMBER on
# the wire -- `decode_value` reads TNS_TYPE_INT and TNS_TYPE_NUMBER through the
# same branch -- but it is NOT a NUMBER to the server: assigning 2.9 to one
# yields 2, and a call overloaded on the two resolves by this type. Without it a
# caller could only bind NUMBER and got 2.9 back.
DB_TYPE_BINARY_INTEGER = _DbType('DB_TYPE_BINARY_INTEGER', TNS_TYPE_INT, 22)
DB_TYPE_INTERVAL_DS = _DbType('DB_TYPE_INTERVAL_DS', TNS_TYPE_INTERVALDS, 11)
DB_TYPE_INTERVAL_YM = _DbType('DB_TYPE_INTERVAL_YM', TNS_TYPE_INTERVALYM, 5)
# Fetch-oriented types (mostly appear in cursor.description; kept as objects so
# description[i][1] is the same seerdb.DB_TYPE_* constant, matching oracledb).
# tns_type is the wire code the DCB reports for a column of that type.
DB_TYPE_CHAR = _DbType('DB_TYPE_CHAR', TNS_TYPE_CHAR, 2000)
DB_TYPE_LONG = _DbType('DB_TYPE_LONG', TNS_TYPE_LONG, 32767)
DB_TYPE_LONG_RAW = _DbType('DB_TYPE_LONG_RAW', TNS_TYPE_LONGRAW, 32767)
DB_TYPE_ROWID = _DbType('DB_TYPE_ROWID', TNS_TYPE_ROWID_FETCH, 18)
DB_TYPE_UROWID = _DbType('DB_TYPE_UROWID', TNS_TYPE_UROWID, 5267)
DB_TYPE_CLOB = _DbType('DB_TYPE_CLOB', TNS_TYPE_CLOB, 32767)
DB_TYPE_NCLOB = _DbType('DB_TYPE_NCLOB', TNS_TYPE_CLOB, 32767, csfrm=2)
DB_TYPE_BLOB = _DbType('DB_TYPE_BLOB', TNS_TYPE_BLOB, 32767)
DB_TYPE_TIMESTAMP_LTZ = _DbType('DB_TYPE_TIMESTAMP_LTZ', TNS_TYPE_TIMESTAMPLTZ, 11)
DB_TYPE_JSON = _DbType('DB_TYPE_JSON', TNS_TYPE_JSON, 32767)
DB_TYPE_BOOLEAN = _DbType('DB_TYPE_BOOLEAN', TNS_TYPE_BOOLEAN, 4)
DB_TYPE_VECTOR = _DbType('DB_TYPE_VECTOR', TNS_TYPE_VECTOR, 32767)
# An object or collection column, and the two kinds python-oracledb names apart
# from it (#1478): a BFILE, and an XMLType -- on the wire an object (ADT) column
# of type SYS.XMLTYPE, told apart by that type name when a column describes.
DB_TYPE_OBJECT = _DbType('DB_TYPE_OBJECT', TNS_TYPE_ADT, 32767)
DB_TYPE_BFILE = _DbType('DB_TYPE_BFILE', TNS_TYPE_BFILE, 32767)
DB_TYPE_XMLTYPE = _DbType('DB_TYPE_XMLTYPE', TNS_TYPE_ADT, 32767)

# The rest of the type objects PEP 249 requires a module to expose, alongside
# STRING and NUMBER above. Each is an alias for the DbType the server reports for
# that kind of column, which is the same convention STRING and NUMBER already
# follow — so they double as `cursor.var()` type specs.
#
# One consequence worth stating: each matches a single wire type, so comparing
# `cursor.description[i][1] == STRING` is true for VARCHAR but not for CHAR or
# CLOB. PEP 249 allows a type object to match a whole family; broadening these
# would change what the existing STRING and NUMBER compare equal to, so it is a
# separate decision rather than part of adding the missing names.
BINARY = DB_TYPE_RAW
ROWID = DB_TYPE_ROWID
# Oracle's DATE carries a time component, so it — not TIMESTAMP — is the type a
# plain date/time column reports.
DATETIME = DB_TYPE_DATE


# The constructors PEP 249 requires. A caller that has a date, a time or a byte
# string already can bind it directly; these exist so code written against the
# DB-API generically, without knowing which driver is underneath, works here too.
def Date(year: int, month: int, day: int) -> datetime.date:  # noqa: N802
    """A value holding a date (PEP 249)."""
    return datetime.date(year, month, day)


def Time(hour: int, minute: int, second: int) -> datetime.time:  # noqa: N802
    """A value holding a time of day (PEP 249)."""
    return datetime.time(hour, minute, second)


def Timestamp(  # noqa: N802
    year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0
) -> datetime.datetime:
    """A value holding a date and time (PEP 249)."""
    return datetime.datetime(year, month, day, hour, minute, second)


def DateFromTicks(ticks: float) -> datetime.date:  # noqa: N802
    """A date from a Unix timestamp, in local time (PEP 249)."""
    return datetime.date.fromtimestamp(ticks)


def TimeFromTicks(ticks: float) -> datetime.time:  # noqa: N802
    """A time of day from a Unix timestamp, in local time (PEP 249)."""
    return datetime.datetime.fromtimestamp(ticks).time()


def TimestampFromTicks(ticks: float) -> datetime.datetime:  # noqa: N802
    """A date and time from a Unix timestamp, in local time (PEP 249)."""
    return datetime.datetime.fromtimestamp(ticks)


def Binary(value) -> bytes:  # noqa: N802
    """A value holding binary data (PEP 249).

    Accepts what a caller is likely to already have — bytes, a bytearray or a
    memoryview pass through as bytes; a str is encoded UTF-8, which is what
    binding one to a RAW column would do anyway.
    """
    if isinstance(value, str):
        return value.encode('utf-8')
    return bytes(value)


# Map the (wire type code, charset form) the server reports for a fetched column
# (DCB data_type + csfrm) to its DbType. Keyed on the actual fetch codes so
# cursor.description[i][1] is the seerdb.DB_TYPE_* object (oracledb parity). The
# csfrm split distinguishes national types (VARCHAR/NVARCHAR, CHAR/NCHAR,
# CLOB/NCLOB) that share a wire code.
_FETCH_DBTYPE: dict[tuple[int, int], _DbType] = {
    (TNS_TYPE_NUMBER, 1): DB_TYPE_NUMBER,
    # BINARY_INTEGER / PLS_INTEGER. It used to map onto NUMBER, because seerdb
    # had no binary-integer type at all (#888); that made every such bind a
    # NUMBER to the server, so PL/SQL never truncated (`:v := 2.9` came back
    # 2.9, not 2) and a call overloaded on the two could not resolve (#1044).
    (TNS_TYPE_INT, 1): DB_TYPE_BINARY_INTEGER,
    (TNS_TYPE_VARCHAR, 1): DB_TYPE_VARCHAR,
    (TNS_TYPE_VARCHAR, 2): DB_TYPE_NVARCHAR,
    (TNS_TYPE_CHAR, 1): DB_TYPE_CHAR,
    (TNS_TYPE_CHAR, 2): DB_TYPE_NCHAR,
    (TNS_TYPE_RAW, 1): DB_TYPE_RAW,
    (TNS_TYPE_DATE, 1): DB_TYPE_DATE,
    (TNS_TYPE_LONG, 1): DB_TYPE_LONG,
    (TNS_TYPE_LONGRAW, 1): DB_TYPE_LONG_RAW,
    (TNS_TYPE_ROWID_FETCH, 1): DB_TYPE_ROWID,
    (TNS_TYPE_UROWID, 1): DB_TYPE_UROWID,
    (TNS_TYPE_CLOB, 1): DB_TYPE_CLOB,
    (TNS_TYPE_CLOB, 2): DB_TYPE_NCLOB,
    (TNS_TYPE_BLOB, 1): DB_TYPE_BLOB,
    (TNS_TYPE_BFLOAT, 1): DB_TYPE_BINARY_FLOAT,
    (TNS_TYPE_BDOUBLE, 1): DB_TYPE_BINARY_DOUBLE,
    (TNS_TYPE_TIMESTAMP, 1): DB_TYPE_TIMESTAMP,
    (TNS_TYPE_TIMESTAMPTZ, 1): DB_TYPE_TIMESTAMP_TZ,
    (TNS_TYPE_TIMESTAMPLTZ, 1): DB_TYPE_TIMESTAMP_LTZ,
    (TNS_TYPE_INTERVALYM, 1): DB_TYPE_INTERVAL_YM,
    (TNS_TYPE_INTERVALDS, 1): DB_TYPE_INTERVAL_DS,
    (TNS_TYPE_REFCURSOR, 1): DB_TYPE_CURSOR,
    (TNS_TYPE_JSON, 1): DB_TYPE_JSON,
    (TNS_TYPE_BOOLEAN, 1): DB_TYPE_BOOLEAN,
    (TNS_TYPE_VECTOR, 1): DB_TYPE_VECTOR,
    (TNS_TYPE_ADT, 1): DB_TYPE_OBJECT,
    (TNS_TYPE_BFILE, 1): DB_TYPE_BFILE,
}


def dbtype_for_oracle_type(tns_type: int, csfrm: int) -> _DbType | None:
    # Resolve a fetched column's DbType. Fall back to the non-national (csfrm 1)
    # entry when the server reports csfrm 0 for a non-char type.
    return _FETCH_DBTYPE.get((tns_type, csfrm or 1)) or _FETCH_DBTYPE.get((tns_type, 1))


# Wire type codes whose cursor.description display_size follows oracledb's
# special rules: 23 for the DATE/TIMESTAMP family, a computed width for the
# NUMBER family (NUMBER, BINARY_FLOAT, BINARY_DOUBLE).
_DATE_TNS_TYPES = frozenset(
    {TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_TIMESTAMPLTZ}
)
_NUMBER_TNS_TYPES = frozenset({TNS_TYPE_NUMBER, TNS_TYPE_BFLOAT, TNS_TYPE_BDOUBLE})

_PYTYPE_TO_DBTYPE = {
    int: NUMBER,
    float: NUMBER,
    Decimal: NUMBER,
    str: STRING,
    bytes: DB_TYPE_RAW,
    bytearray: DB_TYPE_RAW,
    datetime.date: DB_TYPE_DATE,
    datetime.datetime: DB_TYPE_DATE,
    datetime.timedelta: DB_TYPE_INTERVAL_DS,
}


def _resolve_dbtype(typ: object):
    if isinstance(typ, _DbType):
        return typ
    if isinstance(typ, type) and typ in _PYTYPE_TO_DBTYPE:
        return _PYTYPE_TO_DBTYPE[typ]
    # An object type (from connection.gettype) is a valid var() type: it exposes
    # the DbType surface a Var reads (tns_type / default_size / csfrm) so an
    # object / collection OUT bind and a typed-NULL object bind carry their type
    # (#888). Imported lazily to avoid a datatypes <- dbobject import cycle.
    from seerdb.common.dbobject import DbObjectType

    if isinstance(typ, DbObjectType):
        return typ
    raise ValueError(f'unsupported var() type: {typ!r}')


# What a variable of each type accepts as its value, as python-oracledb accepts
# it (#2477). The value is encoded by its own Python type while the bind says
# the variable's, so anything else reached the server as the wrong type's bytes
# and came back as garbage, or as NULL. A type not listed keeps what it took
# before: LOBs, objects, cursors, JSON, VECTOR, BOOLEAN, INTERVAL YEAR TO MONTH.
_NUMERIC_VALUES = (int, float, Decimal)  # bool is an int
_DATE_VALUES = (datetime.date,)  # a datetime is a date; a BcDate also goes
_ACCEPTED_VALUES: dict[object, tuple[type, ...]] = {
    DB_TYPE_VARCHAR: (str, bytes),
    DB_TYPE_CHAR: (str, bytes),
    DB_TYPE_NVARCHAR: (str, bytes),
    DB_TYPE_NCHAR: (str, bytes),
    DB_TYPE_LONG: (str, bytes),
    DB_TYPE_NUMBER: _NUMERIC_VALUES,
    DB_TYPE_BINARY_INTEGER: _NUMERIC_VALUES,
    DB_TYPE_BINARY_FLOAT: _NUMERIC_VALUES,
    DB_TYPE_BINARY_DOUBLE: _NUMERIC_VALUES,
    DB_TYPE_RAW: (str, bytes, bytearray),
    DB_TYPE_LONG_RAW: (str, bytes, bytearray),
    DB_TYPE_DATE: _DATE_VALUES,
    DB_TYPE_TIMESTAMP: _DATE_VALUES,
    DB_TYPE_TIMESTAMP_TZ: _DATE_VALUES,
    DB_TYPE_TIMESTAMP_LTZ: _DATE_VALUES,
    DB_TYPE_INTERVAL_DS: (datetime.timedelta,),
}
_BINARY_FLOATS = (DB_TYPE_BINARY_FLOAT, DB_TYPE_BINARY_DOUBLE)


def _checked_value(dbtype: object, value: object) -> object:
    """`value` as a variable of `dbtype` binds it, or NotSupportedError."""
    if value is None:
        return value
    Accepted = _ACCEPTED_VALUES.get(dbtype)
    if Accepted is None:
        return value
    if not isinstance(value, Accepted) and not (
        # seerdb's own date before year 1, which no datetime can hold.
        Accepted is _DATE_VALUES and isinstance(value, BcDate)
    ):
        from seerdb.common.exceptions import NotSupportedError

        raise NotSupportedError(
            f'a value of type {type(value).__name__} cannot be set on a '
            f'{dbtype} variable'
        )
    if dbtype in _BINARY_FLOATS and not isinstance(value, float):
        # The binary encoders take a float; a Decimal or a bool reached the
        # server as NULL (#2477).
        return float(value)  # type: ignore[arg-type]
    return value


# The types whose size is the most bytes a value may take, so a longer value
# grows the variable to fit it (#2564).
_SIZED_TYPES = frozenset(
    {TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_RAW, TNS_TYPE_LONG, TNS_TYPE_LONGRAW}
)


def _value_size(dbtype: _DbType, value: object) -> int:
    """The bytes `value` takes as a bind of `dbtype`, or 0 for a value whose
    width the type fixes. A variable's size is its bind's announced maximum
    length, and the server refuses a longer value with ORA-01461, so setting a
    longer one grows the variable, as python-oracledb's does (#2564)."""
    if dbtype.tns_type not in _SIZED_TYPES:
        return 0
    if isinstance(value, str):
        return len(value.encode('utf-16-be' if dbtype.csfrm == 2 else 'utf-8'))
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    return 0


class Var:
    """A bind container that can receive an OUT / IN OUT value.

    Create via `cursor.var(typ, size=None)`, where `typ` is a Python type
    (`int`, `str`, `bytes`, `datetime`, ...) or an `seerdb.*` type constant.
    Pass it in a `callproc` / `execute` parameter list for an OUT or IN OUT
    argument; seed an IN OUT value with `setvalue(0, value)` and read the
    result afterwards with `getvalue()`.
    """

    __slots__ = (
        'dbtype',
        'size',
        '_value',
        'has_value',
        'is_array',
        'num_elements',
        '_iteration_values',
        '_pytype',
        'inconverter',
        'outconverter',
        'convert_nulls',
    )

    def __init__(
        self,
        typ: object,
        size: int | None = None,
        is_array: bool = False,
        num_elements: int = 0,
        inconverter: Callable[[Any], Any] | None = None,
        outconverter: Callable[[Any], Any] | None = None,
        convert_nulls: bool = False,
    ):
        self.dbtype = _resolve_dbtype(typ)
        # The Python type the caller asked for, when they asked with one. Three
        # of them share a single database type, so the wire cannot say which was
        # wanted and the value has to be brought back to it on the way out
        # (#688). Asking with a database type instead records nothing here, and
        # the value arrives however that type decodes.
        self._pytype = typ if isinstance(typ, type) else None
        self.size = size if size is not None else self.dbtype.default_size
        self._value: object = [] if is_array else None
        self.has_value = False
        # PL/SQL associative-array (index-by table) bind (#122): is_array marks
        # the bulk-array form; num_elements is the declared maximum capacity.
        self.is_array = is_array
        self.num_elements = num_elements
        # One entry per execute iteration, set only by an array execute whose
        # statement has a RETURNING ... INTO clause (#687). `getvalue(pos)`
        # reads it; a single execute leaves it None and reads `_value`.
        self._iteration_values: list | None = None
        # python-oracledb's converters (#2458). `inconverter` is applied to a
        # value set on this variable; `outconverter` to each value a fetch into
        # it returns -- not to NULL unless `convert_nulls`.
        self.inconverter = inconverter
        self.outconverter = outconverter
        self.convert_nulls = convert_nulls

    @property
    def type(self) -> object:
        """The variable's database type (python-oracledb's ``Var.type``)."""
        return self.dbtype

    def setvalue(self, pos: int, value: object) -> None:
        if self.inconverter is not None:
            value = self.inconverter(value)
        # A value the variable's type can't bind is refused here, as
        # python-oracledb refuses it, rather than reaching the server as the
        # wrong type's bytes (#2477). An array variable checks each element.
        # A value longer than the variable's size grows it (#2564).
        if self.is_array and isinstance(value, (list, tuple)):
            value = [_checked_value(self.dbtype, Item) for Item in value]
            for Item in value:
                self.size = max(self.size, _value_size(self.dbtype, Item))
        else:
            value = _checked_value(self.dbtype, value)
            self.size = max(self.size, _value_size(self.dbtype, value))
        self._value = value
        self.has_value = True

    def _as_requested(self, value: object) -> object:
        """`value` brought back to the Python type this bind was created with.

        Only the numeric types need it. A NUMBER column can be read as an `int`,
        a `float` or a `Decimal`, and the wire says nothing about which, so
        without this a `var(float)` came back holding a `Decimal` -- the type the
        caller named gave them nothing (#688). Text, bytes and the temporal types
        each have their own database type, which already decides the result.

        `int` is deliberately left alone. Rounding a value to it would discard
        the fractional part the statement actually returned, which is worse than
        handing back a number of a neighbouring type; a NUMBER that is whole
        already arrives as an `int`.
        """
        if isinstance(value, list):
            return [self._as_requested(item) for item in value]
        if value is None or self._pytype not in (float, Decimal):
            return value
        if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
            return value
        if self._pytype is Decimal and isinstance(value, float):
            # Through the decimal string, not the float itself: Decimal(8.55) is
            # the exact binary value, which reads as
            # 8.550000000000000710542735760100185871124267578125. Reachable by
            # seeding an IN OUT bind with a float and reading it back before the
            # server has written one.
            return Decimal(str(value))
        return self._pytype(value)

    def getvalue(self, pos: int = 0) -> object:
        """The value this bind received, as the type it was created with.

        After an array execute of a `RETURNING ... INTO` statement, each
        iteration returns its own rows, so `pos` selects the iteration and the
        result is that iteration's list of values. Everywhere else there is a
        single iteration and `pos` is ignored, matching python-oracledb.
        """
        if self._iteration_values is not None:
            return self._as_requested(self._iteration_values[pos])
        return self._as_requested(self._value)

    def __repr__(self) -> str:
        if self.is_array:
            return f'Var({self.dbtype}[{self.num_elements}], value={self._value!r})'
        return f'Var({self.dbtype}, size={self.size}, value={self._value!r})'


class BinaryFloat(float):
    """Bind marker: send the value as a native BINARY_FLOAT (32-bit IEEE-754)
    rather than the default NUMBER. A plain ``float`` still binds as NUMBER for
    backwards compatibility; wrap it in ``BinaryFloat`` to force the single-
    precision binary type (e.g. to round-trip ``inf`` / ``nan`` exactly).

    It is a ``float`` subclass, so it behaves like one in arithmetic and
    ``isinstance(x, float)`` checks.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f'BinaryFloat({float.__repr__(self)})'


class BinaryDouble(float):
    """Bind marker: send the value as a native BINARY_DOUBLE (64-bit IEEE-754)
    rather than the default NUMBER. See :class:`BinaryFloat`.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f'BinaryDouble({float.__repr__(self)})'


class IntervalYM:
    """An Oracle ``INTERVAL YEAR TO MONTH`` value.

    There is no stdlib type for a calendar interval (a month is not a fixed
    number of days), so this small class carries the two fields. It is used both
    as the decoded result of an interval-year-to-month column and as a bind
    input. Years and months are normalised on construction so that
    ``abs(months) < 12`` and both fields share the interval's sign, matching how
    the server stores and returns the value.
    """

    __slots__ = ('years', 'months')

    def __init__(self, years: int = 0, months: int = 0):
        total = int(years) * 12 + int(months)
        sign = -1 if total < 0 else 1
        total = abs(total)
        self.years = sign * (total // 12)
        self.months = sign * (total % 12)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IntervalYM):
            return NotImplemented
        return self.years == other.years and self.months == other.months

    def __hash__(self) -> int:
        return hash((self.years, self.months))

    def __repr__(self) -> str:
        return f'IntervalYM(years={self.years}, months={self.months})'


# IntervalYM is defined above, so register its Python-type mapping now that the
# class exists (lets `cursor.var(seerdb.IntervalYM)` resolve).
_PYTYPE_TO_DBTYPE[IntervalYM] = DB_TYPE_INTERVAL_YM


@dataclass(frozen=True)
class BFile:
    """A BFILE column's value: a file on the SERVER's filesystem (#1102).

    A BFILE has no content of its own on the wire -- it names a DIRECTORY object
    and a file in it, and the client asks the server to test, open and read that
    file afterwards. A Mirror backend hands over the two names; the locator is
    built from them, and the FILE_* calls that follow are answered through the
    backend. Whether the file exists is not asked here: a BFILE naming a missing
    directory is a perfectly good value, and only fileexists() / read() fail.
    """

    directory: str
    filename: str


class BcDate:
    """An Oracle DATE or TIMESTAMP before year 1, which no ``datetime`` can hold (#1071).

    Oracle's DATE reaches back to 4712 BC; Python's ``datetime`` starts at year
    1. A Mirror backend that has such a value -- fetched from a real server, or
    loaded from its own database -- hands it over as this, and the Mirror encodes
    it byte for byte like any other date. The year is numbered as Oracle numbers
    it: negative for BC, with no year 0, so -4712 is 4712 BC.

    ``microsecond`` is the TIMESTAMP fraction; a DATE column drops it, as it does
    a ``datetime``'s. A BC ``TIMESTAMP WITH TIME ZONE`` is not covered.
    """

    __slots__ = ('year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond')

    def __init__(
        self,
        year: int,
        month: int,
        day: int,
        hour: int = 0,
        minute: int = 0,
        second: int = 0,
        microsecond: int = 0,
    ):
        if not -4712 <= year <= -1:
            raise ValueError(
                f'year {year} is not before year 1 (-4712 to -1); use a datetime'
            )
        for name, value, low, high in (
            ('month', month, 1, 12),
            ('day', day, 1, 31),
            ('hour', hour, 0, 23),
            ('minute', minute, 0, 59),
            ('second', second, 0, 59),
            ('microsecond', microsecond, 0, 999999),
        ):
            if not low <= value <= high:
                raise ValueError(f'{name} {value} is out of range')
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self.microsecond = microsecond

    def _fields(self) -> tuple:
        return (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.microsecond,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BcDate):
            return NotImplemented
        return self._fields() == other._fields()

    def __hash__(self) -> int:
        return hash(self._fields())

    def __repr__(self) -> str:
        return 'BcDate({}, {}, {}, {}, {}, {}, {})'.format(*self._fields())


class JSON:
    """Bind marker: send the wrapped Python value into a native ``JSON`` column
    (21c+). A bare ``dict`` already binds as JSON automatically; wrap a
    ``list`` / ``str`` / number / ``bool`` / ``None`` in ``JSON`` to bind *it*
    as JSON too (a bare list otherwise means a VECTOR, and bare scalars bind as
    their native SQL types). The value must be JSON-serialisable.

    seerdb serialises the value to JSON text and binds it as a string; the
    server casts it to the column's JSON type (see docs/PROTOCOL.md §17.2).
    """

    __slots__ = ('value',)

    def __init__(self, value: object):
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JSON):
            return NotImplemented
        return self.value == other.value

    def __repr__(self) -> str:
        return f'JSON({self.value!r})'


class RefCursorBind:
    """Base marker for a REF CURSOR bind sentinel.

    The encoder in ``seerdb.common.tns`` emits a REFCURSOR bind when a bind
    value is an instance of this. It lives here in the leaf marker module (not
    in the client) so the codec can recognise the sentinel without importing
    anything from ``seerdb.client`` — keeping ``common`` a self-contained leaf
    that both the client and the Mirror server build on. The client's public
    ``cursor`` sentinel subclasses it.
    """
