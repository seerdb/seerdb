# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Arrow / DataFrame bulk fetch (#162). cursor.fetch_df_all() and
# cursor.fetch_df_batches() return query results as a pyarrow.Table (column
# major) instead of per-row tuples, for fast hand-off to pandas / Polars /
# pyarrow. The rows come from the ordinary fetch buffer; this module just
# reshapes them column-major and maps Oracle types to Arrow.

from __future__ import annotations

import pyarrow as pa

from seerdb.common.tns_consts import (
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_CHAR,
    TNS_TYPE_DATE,
    TNS_TYPE_FLOAT,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VARNUM,
)

_BINARY_TYPES = (TNS_TYPE_RAW, TNS_TYPE_LONGRAW)
_TIMESTAMP_TYPES = (
    TNS_TYPE_DATE,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_TIMESTAMPLTZ,
)
_STRING_TYPES = (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG)
_NUMBER_TYPES = (TNS_TYPE_NUMBER, TNS_TYPE_VARNUM)


def _fallback_type(type_code, scale) -> pa.DataType:
    if type_code in (TNS_TYPE_NUMBER, TNS_TYPE_VARNUM):
        # scale 0 -> integer column; anything else -> floating point.
        return pa.int64() if scale in (0, None) else pa.float64()
    if type_code == TNS_TYPE_BFLOAT:
        return pa.float32()
    if type_code in (TNS_TYPE_BDOUBLE, TNS_TYPE_FLOAT):
        return pa.float64()
    if type_code in _TIMESTAMP_TYPES:
        return pa.timestamp('us')
    if type_code in _BINARY_TYPES:
        return pa.binary()
    return pa.string()


def _explicit_type(type_code, precision, scale):
    # The exact Arrow type for a column whose decoded Python values are known to
    # match it, so pyarrow can skip type inference (#190). Inference is the cost
    # centre of build_table — it scans every value, and on a NUMBER-with-scale
    # (Decimal) column that is by far the slowest step. Returns None when no
    # safe fixed type can be derived (e.g. an unconstrained NUMBER, which
    # legitimately decodes to an int / Decimal mix, or a TZ / LOB / object
    # column), leaving that column to inference.
    if type_code in _NUMBER_TYPES:
        # Only a constrained NUMBER(p, s) has a fixed shape. precision 0 / scale
        # -127 is Oracle's "unconstrained" marker -> infer.
        if not precision or precision <= 0 or precision > 38:
            return None
        if scale and scale > 0:
            # Decimal values; decimal128 needs scale <= precision.
            return pa.decimal128(precision, scale) if scale <= precision else None
        if scale == 0:
            # Integer values; int64 holds up to 18 digits without overflow.
            return pa.int64() if precision <= 18 else None
        return None  # negative scale -> infer
    if type_code == TNS_TYPE_BFLOAT:
        return pa.float32()
    if type_code in (TNS_TYPE_BDOUBLE, TNS_TYPE_FLOAT):
        return pa.float64()
    if type_code in _STRING_TYPES:
        return pa.string()
    if type_code in _BINARY_TYPES:
        return pa.binary()
    # DATE / naive TIMESTAMP decode to naive datetimes; the TZ-aware variants
    # (TIMESTAMPTZ / LTZ) carry a tz, so leave those to inference.
    if type_code in (TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP):
        return pa.timestamp('us')
    return None


def _column_array(values: list, type_code, scale, precision=None) -> pa.Array:
    # Build one Arrow column. Use the exact Oracle-derived type when one is safe
    # (skips pyarrow's per-value inference, #190); otherwise let pyarrow infer
    # from the values, falling back to the type map for an empty / all-NULL
    # column so the schema is still meaningful.
    Explicit = _explicit_type(type_code, precision, scale)
    if Explicit is not None:
        return pa.array(values, type=Explicit)
    if any(v is not None for v in values):
        return pa.array(values)
    return pa.array(values, type=_fallback_type(type_code, scale))


def build_table(rows: list, description: list) -> pa.Table:
    """Build a pyarrow.Table from buffered rows + a PEP 249 description (#162).

    `rows` is a list of per-row sequences (column-major is derived here);
    `description` supplies the column names (index 0), type codes (1),
    precision (4) and scale (5)."""
    Names = [Col[0] for Col in description]
    NumCols = len(Names)
    # Transpose row-major rows into per-column value lists.
    Columns: list[list] = [[] for _ in range(NumCols)]
    for Row in rows:
        for I in range(NumCols):
            Columns[I].append(Row[I] if I < len(Row) else None)
    Arrays = [
        _column_array(
            Columns[I], description[I][1], description[I][5], description[I][4]
        )
        for I in range(NumCols)
    ]
    return pa.table(dict(zip(Names, Arrays))) if Names else pa.table({})


# --- Arrow in: executemany from a DataFrame (#2461) --------------------------
# An object with the Arrow PyCapsule stream interface (pyarrow, pandas, polars,
# ...) as executemany's parameters, as python-oracledb 3.3+ takes it: column i
# binds placeholder i+1, typed by its Arrow type rather than by its values, and
# each record batch is one array execute. The bind type of each Arrow type, as
# python-oracledb's OracleMetadata.from_arrow_schema gives it.


def _arrow_bind_type(typ: pa.DataType):
    from seerdb.common import datatypes as dt

    if pa.types.is_integer(typ) or pa.types.is_decimal(typ):
        return dt.DB_TYPE_NUMBER
    if (
        pa.types.is_string(typ)
        or pa.types.is_null(typ)
        or getattr(pa.types, 'is_string_view', lambda _: False)(typ)
    ):
        return dt.DB_TYPE_VARCHAR
    if pa.types.is_large_string(typ):
        return dt.DB_TYPE_LONG
    if (
        pa.types.is_binary(typ)
        or pa.types.is_fixed_size_binary(typ)
        or getattr(pa.types, 'is_binary_view', lambda _: False)(typ)
    ):
        return dt.DB_TYPE_RAW
    if pa.types.is_large_binary(typ):
        return dt.DB_TYPE_LONG_RAW
    if pa.types.is_float32(typ):
        return dt.DB_TYPE_BINARY_FLOAT
    if pa.types.is_float64(typ):
        return dt.DB_TYPE_BINARY_DOUBLE
    if pa.types.is_boolean(typ):
        return dt.DB_TYPE_BOOLEAN
    if pa.types.is_timestamp(typ):
        return dt.DB_TYPE_TIMESTAMP
    if pa.types.is_date(typ):
        return dt.DB_TYPE_DATE
    if pa.types.is_list(typ) or pa.types.is_fixed_size_list(typ):
        # A dense vector of an element type VECTOR has.
        return dt.DB_TYPE_VECTOR if typ.value_type in _VECTOR_TYPECODES else None
    if pa.types.is_struct(typ):
        return dt.DB_TYPE_VECTOR  # a sparse vector
    if typ == pa.month_day_nano_interval():
        return dt.DB_TYPE_INTERVAL_DS
    return None


# A dense vector's element type, as the array typecode encode_vector writes it.
_VECTOR_TYPECODES = {
    pa.float32(): 'f',
    pa.float64(): 'd',
    pa.int8(): 'b',
    pa.uint8(): 'B',
}


def _vector(values, typecode: str):
    import array

    return None if values is None else array.array(typecode, values)


def _arrow_values(column: pa.Array) -> list:
    # The Python values a column binds, as python-oracledb converts them: an
    # empty string or binary is NULL, as Oracle stores it; a timestamp is its
    # UTC wall time to the microsecond, whatever its zone; an interval's months
    # are ignored.
    import datetime

    typ = column.type
    if pa.types.is_timestamp(typ):
        column = column.cast(pa.timestamp('us'), safe=False)
    elif pa.types.is_date64(typ):
        column = column.cast(pa.timestamp('ms')).cast(pa.timestamp('us'))
    values = column.to_pylist()
    if pa.types.is_date32(typ):
        return [
            None if v is None else datetime.datetime(v.year, v.month, v.day)
            for v in values
        ]
    if (
        pa.types.is_string(typ)
        or pa.types.is_large_string(typ)
        or pa.types.is_binary(typ)
        or pa.types.is_large_binary(typ)
        or pa.types.is_fixed_size_binary(typ)
    ):
        return [None if not v else v for v in values]
    if typ == pa.month_day_nano_interval():
        return [
            None
            if v is None
            else datetime.timedelta(days=v.days, microseconds=v.nanoseconds // 1000)
            for v in values
        ]
    if pa.types.is_list(typ) or pa.types.is_fixed_size_list(typ):
        typecode = _VECTOR_TYPECODES[typ.value_type]
        return [_vector(v, typecode) for v in values]
    if pa.types.is_struct(typ):
        from seerdb.common.vector import SparseVector

        out: list[object] = []
        for v in values:
            if v is None:
                out.append(None)
                continue
            typecode = _VECTOR_TYPECODES.get(typ.field('values').type.value_type, 'd')
            out.append(
                SparseVector(
                    v['num_dimensions'],
                    _vector(v['indices'], 'I'),
                    _vector(v['values'], typecode),
                )
            )
        return out
    return values


def _refuse(typ: pa.DataType) -> None:
    from seerdb.common.exceptions import NotSupportedError

    raise NotSupportedError(
        f'conversion from Apache Arrow type "{typ}" to Oracle Database is not supported'
    )


def arrow_batches(
    source, field_version: int | None = None
) -> list[tuple[list, list[tuple]]]:
    """Each record batch of an Arrow PyCapsule stream as ``(types, rows)``: the
    bind type of each column, by position, and the batch's rows (#2461).

    Every column is checked before any batch is built, so an unsupported type
    is refused before anything is sent."""
    from seerdb.common import datatypes as dt

    try:
        reader = pa.RecordBatchReader.from_stream(source)
        schema, batches = reader.schema, list(reader)
    except AttributeError:  # a pyarrow before from_stream (15)
        table = pa.table(source)
        schema, batches = table.schema, table.to_batches()
    types = [_arrow_bind_type(field.type) for field in schema]
    for field, typ in zip(schema, types):
        if typ is None:
            _refuse(field.type)
    # Below 12.1 a string or binary column is left to its values' own typing, as
    # a plain executemany types it: declared, it goes with the type's 32 KB
    # buffer, which a 9i server takes for a LONG (ORA-01461), and there a LONG
    # must be declared to bind past 4000 bytes.
    from seerdb.common.tns_consts import FIELD_VERSION_12_1

    modern = field_version is None or field_version >= FIELD_VERSION_12_1
    loose = () if modern else (dt.DB_TYPE_VARCHAR, dt.DB_TYPE_RAW)
    types = [None if typ in loose else typ for typ in types]
    out = []
    for batch in batches:
        if batch.num_rows == 0:
            continue
        columns = [_arrow_values(batch.column(i)) for i in range(batch.num_columns)]
        out.append((types, list(zip(*columns))))
    return out
