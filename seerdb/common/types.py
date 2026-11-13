# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Decoders that turn the raw column bytes returned by the wire-level RXD parser
# into Python values. Each top-level function takes the raw `bytes` for one
# column value and returns the typed Python object (or None for NULL).
#
# Algorithms cross-referenced with python-oracledb's decoders.pyx.

import contextvars
import datetime
import struct
import zoneinfo
from decimal import Decimal, InvalidOperation
from typing import cast

from seerdb.common._tzregions import TZ_REGIONS
from seerdb.common.datatypes import BcDate, IntervalYM
from seerdb.common.exceptions import DataError, DateOutOfRangeError
from seerdb.common.tns_consts import (
    AL16UTF16_CHARSET,
    AL32UTF8_CHARSET,
    ISO_LATIN_1_CHARSET,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_DATE,
    TNS_TYPE_INT,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_REF,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
    UTF8_CHARSET,
)

# Oracle stores a TZ offset as (hour + 20, minute + 60); a top bit set on the
# hour byte means the two TZ bytes carry a named-region id instead of an offset.
_TZ_HOUR_OFFSET = 20
_TZ_MINUTE_OFFSET = 60
_TZ_REGION_ID_FLAG = 0x80


def _tz_region_id(HourByte: int, MinuteByte: int) -> int:
    # Named-region id packed across the two TZ bytes (see PROTOCOL.md §11.8 /
    # the named-region note): 7 low bits of the hour byte are the high bits, the
    # top 6 bits of the minute byte are the low bits.
    return ((HourByte & 0x7F) << 6) + (MinuteByte >> 2)


def _region_tzinfo(RegionId: int) -> datetime.tzinfo | None:
    # Resolve an Oracle region id to a zoneinfo zone (offset/DST come from the
    # current IANA tz database, never a frozen Oracle table). Unknown ids or a
    # missing tz database yield None, and the caller falls back to naive UTC.
    Name = TZ_REGIONS.get(RegionId)
    if Name is None:
        return None
    try:
        return zoneinfo.ZoneInfo(Name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):
        return None


_CHARSET_PYTHON_NAME = {
    ISO_LATIN_1_CHARSET: 'iso-8859-1',
    UTF8_CHARSET: 'utf-8',
    AL32UTF8_CHARSET: 'utf-8',
    AL16UTF16_CHARSET: 'utf-16-be',
}


# Oracle 8i is a single-byte-session tier: unlike 9i+, it does NOT negotiate an
# AL32UTF8 session (its DTY declares WE8ISO8859P1), and its national charset is
# also WE8ISO8859P1, not Unicode. So ALL 8i char data — VARCHAR2 / CHAR /
# NVARCHAR2 / NCHAR / LONG — arrives in Latin-1, regardless of csfrm. The 8i row
# decoder sets this flag around its decode so _string_charset picks Latin-1
# instead of the UTF-8 / UTF-16 the modern/9i session would return (#366).
_DECODE_IS_8I = contextvars.ContextVar('decode_is_8i', default=False)


def set_decode_8i(value: bool) -> object:
    return _DECODE_IS_8I.set(value)


def reset_decode_8i(token: object) -> None:
    _DECODE_IS_8I.reset(token)  # type: ignore[arg-type]


# A date before year 1 is valid Oracle data no datetime can hold, so the decoder
# raises DateOutOfRangeError for it, as python-oracledb raises ValueError (#1060).
# The Mirror's passthrough backend is the one caller that must carry such a value
# on rather than refuse it: it relays the rows to a client that decides for
# itself. With this set, a date without a time zone decodes to a BcDate the
# Mirror can encode byte for byte (#1069). Nothing in the public client sets it.
_DECODE_BC_DATES = contextvars.ContextVar('decode_bc_dates', default=False)


def set_decode_bc_dates(value: bool) -> object:
    return _DECODE_BC_DATES.set(value)


def reset_decode_bc_dates(token: object) -> None:
    _DECODE_BC_DATES.reset(token)  # type: ignore[arg-type]


def _string_charset(Column: dict) -> int:
    # Pick the charset a CHAR/VARCHAR2/LONG value arrives in (#174). The driver
    # negotiates an AL32UTF8 session, so the server returns ordinary (csfrm 1)
    # char data as UTF-8 regardless of the database charset (e.g. a 9i
    # WE8ISO8859P1 DB) — decoding by the column's *database* charset would
    # mojibake it. National (csfrm 2) data arrives as AL16UTF16. When csfrm is
    # unknown (older decode paths that don't record it), fall back to the
    # column's reported charset.
    if _DECODE_IS_8I.get():
        # 8i speaks a single-byte (WE8ISO8859P1) session for all char data.
        return ISO_LATIN_1_CHARSET
    Csfrm = Column.get('csfrm')
    if Csfrm == 2:
        return AL16UTF16_CHARSET
    if Csfrm == 1:
        return AL32UTF8_CHARSET
    return Column.get('charset', AL32UTF8_CHARSET)


def decode_number(Data: bytes) -> int | Decimal | None:
    # Oracle NUMBER is a base-100 floating point format. Byte 0 is the biased
    # exponent (with the sign bit in the top bit, *inverted* for negatives);
    # the remaining bytes are base-100 mantissa digits. Negatives carry a
    # trailing 0x66 terminator.
    if not Data:
        return None
    if len(Data) == 1:
        if Data[0] == 0x80:
            return 0
        # -1e126 is the canonical "maximum negative" sentinel; surface it as a
        # Decimal for fidelity.
        return Decimal('-1E126')

    ExpByte = Data[0]
    IsPositive = (ExpByte & 0x80) != 0
    if IsPositive:
        Exponent = (ExpByte & 0x7F) - 65
    else:
        Exponent = ((~ExpByte) & 0x7F) - 65

    Mantissa = Data[1:]
    if not IsPositive and Mantissa and Mantissa[-1] == 0x66:
        Mantissa = Mantissa[:-1]

    # Each mantissa byte is a two-digit base-100 group (00..99).
    Pairs = []
    for B in Mantissa:
        Pairs.append((B - 1) if IsPositive else (101 - B))

    # Build the unsigned decimal string from the digit pairs, then place the
    # decimal point based on the exponent. Exponent N means the first pair
    # represents 100**N, i.e. the integer part has (N + 1) pairs / (2N + 2)
    # digits before the decimal point.
    DigitString = ''.join(f'{P:02d}' for P in Pairs)
    IntegerDigits = (Exponent + 1) * 2

    if IntegerDigits >= len(DigitString):
        # No fractional part; pad trailing zeros and emit as int.
        IntegerPart = DigitString + '0' * (IntegerDigits - len(DigitString))
        FractionPart = ''
    elif IntegerDigits <= 0:
        # Pure fractional; pad leading zeros after the decimal point.
        IntegerPart = '0'
        FractionPart = '0' * (-IntegerDigits) + DigitString
    else:
        IntegerPart = DigitString[:IntegerDigits]
        FractionPart = DigitString[IntegerDigits:]

    IntegerPart = IntegerPart.lstrip('0') or '0'
    FractionPart = FractionPart.rstrip('0')
    Sign = '' if IsPositive else '-'

    try:
        if FractionPart:
            return Decimal(f'{Sign}{IntegerPart}.{FractionPart}')
        return int(f'{Sign}{IntegerPart}')
    except (ValueError, InvalidOperation) as Exc:
        # Malformed mantissa/exponent bytes produce a non-numeric digit string
        # (negative base-100 pairs, an embedded '-'); surface as DataError
        # rather than leaking a raw ValueError / InvalidOperation (#230).
        raise DataError(f'malformed Oracle NUMBER: {Data.hex()}') from Exc


def decode_date(Data: bytes) -> datetime.datetime | BcDate | None:
    # 7 bytes = DATE, 11 bytes adds 4-byte BE nanoseconds, 13 bytes adds a
    # 2-byte timezone offset. Year is split across two centuries-biased bytes.
    if not Data or len(Data) < 7:
        return None

    Year = (Data[0] - 100) * 100 + (Data[1] - 100)
    Month = Data[2]
    Day = Data[3]
    Hour = Data[4] - 1
    Minute = Data[5] - 1
    Second = Data[6] - 1

    Microsecond = 0
    if len(Data) >= 11:
        Nanos = int.from_bytes(Data[7:11], 'big')
        Microsecond = Nanos // 1000

    # For TIMESTAMP WITH TIME ZONE Oracle stores the wall clock in UTC and
    # tags it with the original session offset. To preserve the same instant
    # we build a UTC datetime first, then convert to the tagged offset so the
    # result both compares equal and prints with the original local time.
    try:
        Tz = None
        # A 13-byte frame is always TIMESTAMP WITH TIME ZONE: DATE is 7 bytes,
        # TIMESTAMP 7/11, and TIMESTAMP WITH LOCAL TIME ZONE carries no tz bytes
        # (it is normalised to the DB zone). So the two trailing bytes are always
        # a real zone — do NOT gate on them being non-zero. A region id that is a
        # multiple of 64 encodes its low byte (Data[12]) as 0 (e.g. America/Manaus,
        # Asia/Macao, Europe/Gibraltar); such a value must still resolve to its
        # named zone instead of falling through to a naive UTC wall clock (#304).
        if len(Data) >= 13:
            if Data[11] & _TZ_REGION_ID_FLAG:
                # Named region id: resolve to an IANA zone and let zoneinfo
                # supply the (DST-aware) offset for this instant. Unknown id ->
                # naive UTC.
                Tz = _region_tzinfo(_tz_region_id(Data[11], Data[12]))
            else:
                TzHours = Data[11] - _TZ_HOUR_OFFSET
                TzMinutes = Data[12] - _TZ_MINUTE_OFFSET
                Tz = datetime.timezone(
                    datetime.timedelta(hours=TzHours, minutes=TzMinutes)
                )

        if Tz is None:
            return datetime.datetime(
                Year, Month, Day, Hour, Minute, Second, Microsecond
            )

        Utc = datetime.datetime(
            Year,
            Month,
            Day,
            Hour,
            Minute,
            Second,
            Microsecond,
            tzinfo=datetime.timezone.utc,
        )
        return Utc.astimezone(Tz)
    except (ValueError, OverflowError) as Exc:
        if _is_julian_leap_day(Year, Month, Day, Hour, Minute, Second):
            # Oracle's DATE is Julian before 1582-10-15, so 1500-02-29 is a day
            # it has and Python's Gregorian datetime has not: valid data, like
            # a BC date (#2601). The passthrough carries it on as one.
            if _DECODE_BC_DATES.get() and Tz is None:
                return BcDate(Year, Month, Day, Hour, Minute, Second, Microsecond)
            raise DateOutOfRangeError(
                f'{Exc}: the Oracle date {Year}-{Month:02d}-{Day:02d} is a '
                "Julian leap day, which a Python datetime's Gregorian calendar "
                'does not have'
            ) from Exc
        if _is_bc_date(Year, Month, Day, Hour, Minute, Second):
            if _DECODE_BC_DATES.get() and Tz is None:
                return BcDate(Year, Month, Day, Hour, Minute, Second, Microsecond)
            # A BC date is VALID Oracle data -- DATE runs from 4712 BC -- that
            # Python's datetime cannot hold, since it starts at year 1. Calling
            # it "malformed" told a caller the server sent garbage when it sent
            # a correct value (#1060). Still a DataError, so #230's rule holds,
            # and also a ValueError, which is what python-oracledb raises. The
            # message leads with the same words Python's own rejection uses.
            raise DateOutOfRangeError(
                f'year {Year} is out of range: the Oracle date '
                f'{Year}-{Month:02d}-{Day:02d} is before year 1, the earliest '
                'a Python datetime can represent'
            ) from Exc
        # Out-of-range date/time or TZ-offset fields (bad month/day, an offset
        # beyond +/-24h) make datetime()/timezone() reject; surface as DataError
        # rather than leaking a raw ValueError (#230).
        raise DataError(f'malformed Oracle DATE/TIMESTAMP: {Data.hex()}') from Exc


# Oracle's DATE range starts here: 1 January 4712 BC, written -4712 (#1060).
_ORACLE_MIN_YEAR = -4712


def _is_bc_date(
    Year: int, Month: int, Day: int, Hour: int, Minute: int, Second: int
) -> bool:
    # True for a well-formed date before year 1 -- valid in Oracle, out of range
    # for datetime. Every OTHER field has to be in range too: a corrupt frame
    # can land on a negative year by accident, and must still read as malformed.
    # Oracle has no year 0 (1 BC is followed by AD 1), so it is not included.
    return (
        _ORACLE_MIN_YEAR <= Year <= -1
        and 1 <= Month <= 12
        and 1 <= Day <= 31
        and 0 <= Hour <= 23
        and 0 <= Minute <= 59
        and 0 <= Second <= 59
    )


def _is_julian_leap_day(
    Year: int, Month: int, Day: int, Hour: int, Minute: int, Second: int
) -> bool:
    # True for February 29 of a year that is a leap year in the Julian
    # calendar Oracle keeps before 1582-10-15 but not in the Gregorian one a
    # datetime keeps: 100, 200, 300, 500, ... 1500 (#2601). The time must be in
    # range too, as for a BC date.
    return (
        Month == 2
        and Day == 29
        and 1 <= Year <= 1582
        and Year % 100 == 0
        and Year % 400 != 0
        and 0 <= Hour <= 23
        and 0 <= Minute <= 59
        and 0 <= Second <= 59
    )


def decode_binary_float(Data: bytes) -> float | None:
    # Reverse of the order-preserving transform: a positive value has its sign
    # bit set (clear it), a negative value has every bit flipped (flip back).
    if not Data or len(Data) < 4:
        return None
    if Data[0] & 0x80:
        Raw = bytes([Data[0] & 0x7F]) + Data[1:4]
    else:
        Raw = bytes(B ^ 0xFF for B in Data[:4])
    return struct.unpack('>f', Raw)[0]


def decode_binary_double(Data: bytes) -> float | None:
    if not Data or len(Data) < 8:
        return None
    if Data[0] & 0x80:
        Raw = bytes([Data[0] & 0x7F]) + Data[1:8]
    else:
        Raw = bytes(B ^ 0xFF for B in Data[:8])
    return struct.unpack('>d', Raw)[0]


def decode_interval_ds(Data: bytes) -> datetime.timedelta | None:
    # 4-byte days biased by 2**31, hours / minutes / seconds biased by 60, then
    # 4-byte nanoseconds biased by 2**31. timedelta sums the signed components.
    if not Data or len(Data) < 11:
        return None
    Days = int.from_bytes(Data[0:4], 'big') - 2**31
    Hours = Data[4] - 60
    Minutes = Data[5] - 60
    Seconds = Data[6] - 60
    Nanos = int.from_bytes(Data[7:11], 'big') - 2**31
    try:
        return datetime.timedelta(
            days=Days,
            hours=Hours,
            minutes=Minutes,
            seconds=Seconds,
            microseconds=Nanos // 1000,
        )
    except OverflowError as Exc:
        # Python's timedelta range is slightly narrower than Oracle's on the
        # negative side: timedelta.min is exactly -999_999_999 days 00:00:00,
        # whereas INTERVAL DAY(9) TO SECOND reaches -999_999_999 23:59:59.999999.
        # So the most-negative legal Oracle intervals (and any corrupt / truncated
        # frame) overflow timedelta. Surface a clean DataError rather than leaking
        # the raw OverflowError (python-oracledb leaks it). The positive extreme
        # (+999_999_999 23:59:59.999999) does fit timedelta.max.
        raise DataError(
            f'INTERVAL DAY TO SECOND value out of range (days={Days})'
        ) from Exc


def decode_interval_ym(Data: bytes) -> IntervalYM | None:
    # 4-byte years biased by 2**31, 1-byte months biased by 60.
    if not Data or len(Data) < 5:
        return None
    Years = int.from_bytes(Data[0:4], 'big') - 2**31
    Months = Data[4] - 60
    return IntervalYM(Years, Months)


# Oracle's base64 alphabet for the printable extended ROWID (not RFC 4648).
_ROWID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _rowid_b64(Value: int, NumChars: int) -> str:
    # Big-endian, zero-padded base64 of Value across exactly NumChars digits.
    return ''.join(
        _ROWID_ALPHABET[(Value >> (6 * (NumChars - 1 - I))) & 0x3F]
        for I in range(NumChars)
    )


def rowid_to_string(Obj: int, File: int, Block: int, Slot: int) -> str:
    # Extended ROWID: OOOOOO (data object) FFF (rel file) BBBBBB (block)
    # RRR (slot), e.g. "AAAK6JAAEAAACGPAAA".
    return (
        _rowid_b64(Obj, 6)
        + _rowid_b64(File, 3)
        + _rowid_b64(Block, 6)
        + _rowid_b64(Slot, 3)
    )


def string_to_rowid(Text: str) -> tuple[int, int, int, int]:
    # Inverse of rowid_to_string: parse the 18-char extended ROWID back into its
    # (data object, relative file, block, slot) integers. Each segment is
    # big-endian base64 in Oracle's alphabet — OOOOOO FFF BBBBBB RRR.
    def _seg(Chars: str) -> int:
        Value = 0
        for Char in Chars:
            Value = (Value << 6) | _ROWID_ALPHABET.index(Char)
        return Value

    return (_seg(Text[0:6]), _seg(Text[6:9]), _seg(Text[9:15]), _seg(Text[15:18]))


# A UROWID's leading tag byte: a PHYSICAL rowid, stored in a UROWID column. A
# logical one (an index-organized table's) is tagged 0x02. Both captured from 23ai
# (#1086).
_UROWID_PHYSICAL_TAG = 0x01


def urowid_to_string(Value: bytes) -> str:
    # A universal ROWID's printable form depends on its leading tag byte. A
    # physical rowid (tag 0x01) is the ordinary 18-character extended rowid, from
    # the data object (ub4), partition / relative file (ub2), block (ub4) and slot
    # (ub2) that follow, big-endian -- exactly what the same row's ROWID column
    # prints, and what python-oracledb renders (#1086). Anything else is a logical
    # rowid: "*" + base64 of the bytes after the tag, e.g.
    # b"\x02\x04\x01\x00\x19\x83\x02\xc1\x02\xfe" -> "*BAEAGYMCwQL+".
    # base64 uses the standard alphabet; Oracle's printable form carries no
    # padding.
    import base64

    if len(Value) >= 13 and Value[0] == _UROWID_PHYSICAL_TAG:
        return rowid_to_string(
            int.from_bytes(Value[1:5], 'big'),
            int.from_bytes(Value[5:7], 'big'),
            int.from_bytes(Value[7:11], 'big'),
            int.from_bytes(Value[11:13], 'big'),
        )
    return '*' + base64.b64encode(Value[1:]).decode('ascii').rstrip('=')


def decode_string(Data: bytes, Charset: int = AL32UTF8_CHARSET) -> str | None:
    if not Data:
        return None
    Encoding = _CHARSET_PYTHON_NAME.get(Charset, 'utf-8')
    return Data.decode(Encoding, errors='replace')


def fv2_lob_charset(charset: int | None, csfrm: int | None = None) -> int:
    """The charset a 9i LOB call carries a CLOB's text in (#2383): the session's
    AL32UTF8, which the server converts the content to and from whatever the
    database charset -- the column's charset is the database's, and reading by
    it garbled `é` into `Ã©` on a WE8ISO8859P1 database -- or AL16UTF16 for an
    NCLOB (csfrm 2), which keeps its national form."""
    if csfrm == 2 or charset == AL16UTF16_CHARSET:
        return AL16UTF16_CHARSET
    return AL32UTF8_CHARSET


def fv2_lob_payload(
    Data: str | bytes, is_blob: bool, charset: int | None
) -> tuple[bytes, int]:
    """A 9i LOB write's bytes and its amount (#2259): a BLOB's bytes, or a
    CLOB's text in the session's charset (fv2_lob_charset) -- not the 10g+
    UTF-16 -- counted in characters. Sent in the column's database charset, a
    non-ASCII character was invalid UTF-8 to the server, which then found fewer
    characters than the amount (ORA-22993, #2383)."""
    if is_blob:
        return (cast(bytes, Data), len(Data))
    Text = cast(str, Data)
    Charset = fv2_lob_charset(charset)
    Bytes = Text.encode(_CHARSET_PYTHON_NAME[Charset])
    if Charset == AL16UTF16_CHARSET:
        # UTF-16's characters are its code units: a character past the BMP is
        # two of them. Counted as one, a pooled 11g server process read the
        # rest of the data as a protocol error and died (ORA-03137, #2466).
        return (Bytes, len(Bytes) // 2)
    return (Bytes, len(Text))


def decode_fv2_lob(data_type: int, content: bytes, charset: int) -> str | bytes:
    # Turn raw 9i / 8i LOB content (fetched via TTI_LOBOPS) into a Python value.
    # CLOB / NCLOB (112) is text in `charset` -- NOT the UTF-16BE the modern path
    # uses: on 9i the session's (fv2_lob_charset), on 8i the single-byte
    # database charset the whole 8i session speaks. BLOB (113) stays bytes.
    # Empty content yields "" / b"". (#102)
    if data_type == 112:
        if not content:
            return ''
        return content.decode(
            _CHARSET_PYTHON_NAME.get(charset, 'utf-8'), errors='replace'
        )
    return content or b''


def decode_value(Column: dict, Data: bytes | list | None) -> object:
    # Dispatcher: pick the right decoder based on the column's TNS data type.
    # Unknown types are returned as raw bytes so callers can still see them.
    if Data is None or Data == [] or Data == b'':
        return None
    if isinstance(Data, list):
        return None
    DataType = Column.get('data_type')
    if DataType in (TNS_TYPE_NUMBER, TNS_TYPE_INT):
        # BINARY_INTEGER / PLS_INTEGER (TNS_TYPE_INT) rides the wire as an Oracle
        # NUMBER, not as a native integer -- the same fact the OUT-bind encoder
        # relies on (#888). Left undecoded it surfaced as the raw NUMBER bytes,
        # so `select :1 from dual` on such a bind came back as DB_TYPE_RAW
        # b'\xc1 ' instead of 31 (#826).
        Value = decode_number(Data)
        if DataType == TNS_TYPE_INT and Value is not None:
            # The truncation is the CLIENT's, not the server's: the bytes for
            # `:v := 2.9` are the same NUMBER either way, and it is the declared
            # BINARY_INTEGER that makes the value an integer. Verified by
            # capturing both clients' binds -- byte-identical OACs, and only the
            # decode differs (#1044).
            return int(Value)
        return Value
    if DataType in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG):
        return decode_string(Data, _string_charset(Column))
    if DataType == TNS_TYPE_LONGRAW:
        return bytes(Data)
    if DataType in (
        TNS_TYPE_DATE,
        TNS_TYPE_TIMESTAMP,
        TNS_TYPE_TIMESTAMPTZ,
        TNS_TYPE_TIMESTAMPLTZ,
    ):
        return decode_date(Data)
    if DataType == TNS_TYPE_BFLOAT:
        return decode_binary_float(Data)
    if DataType == TNS_TYPE_BDOUBLE:
        return decode_binary_double(Data)
    if DataType == TNS_TYPE_INTERVALDS:
        return decode_interval_ds(Data)
    if DataType == TNS_TYPE_INTERVALYM:
        return decode_interval_ym(Data)
    if DataType == TNS_TYPE_REF:
        # REF (object reference, #119): an opaque locator. Surface it as a typed
        # DbRef (raw bytes + the referenced type when the describe carried it)
        # rather than bare bytes; dereference in SQL with DEREF(...) to get the
        # object. NULL was already handled above.
        from seerdb.common.dbobject import DbRef

        return DbRef(
            bytes(Data),
            Column.get('type_name'),
            Column.get('type_schema'),
            Column.get('type_oid'),
        )
    if DataType == TNS_TYPE_BOOLEAN:
        # Native SQL BOOLEAN (23ai, #54). NULL is already handled above; a
        # present value's last byte is the truth value: TRUE arrives as
        # `01 01`, FALSE as `00` (verified on 23ai vs python-oracledb).
        return Data[-1] != 0
    return Data
