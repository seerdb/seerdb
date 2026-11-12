# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline round-trip tests for the native scalar bind/fetch types:
# BINARY_FLOAT, BINARY_DOUBLE, INTERVAL DAY TO SECOND, INTERVAL YEAR TO MONTH.
#
# The expected wire bytes are not invented: they were captured from a live
# Oracle XE by selecting columns of each type (the decoder falls through to raw
# bytes for unknown types, so a plain SELECT reveals the on-wire format).

import datetime
import math
import unittest
from decimal import Decimal

from seerdb.common.datatypes import (
    DB_TYPE_BINARY_DOUBLE,
    DB_TYPE_BINARY_FLOAT,
    DB_TYPE_INTERVAL_DS,
    DB_TYPE_INTERVAL_YM,
    DB_TYPE_TIMESTAMP,
    DB_TYPE_TIMESTAMP_TZ,
    BinaryDouble,
    BinaryFloat,
    IntervalYM,
    Var,
)
from seerdb.common.exceptions import DataError
from seerdb.common.tns import (
    _read_iov,
    _read_long_column,
    _read_rowid_column,
    _read_urowid_column,
    decode_dalc,
    decode_ub4,
    encode_sb4,
    encode_token_binary_double,
    encode_token_binary_float,
    encode_token_decimal,
    encode_token_interval_ds,
    encode_token_interval_ym,
    encode_token_num,
    encode_token_oac,
    encode_token_rxd,
    exec_oac_signature,
)
from seerdb.common.tns_consts import (
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
)
from seerdb.common.types import (
    decode_binary_double,
    decode_binary_float,
    decode_date,
    decode_interval_ds,
    decode_interval_ym,
    decode_number,
    decode_value,
    rowid_to_string,
    urowid_to_string,
)


class TestNamedRegionTSTZ(unittest.TestCase):
    # TIMESTAMP WITH TIME ZONE carrying a named region id (top bit of byte 11)
    # resolves via zoneinfo so the offset is DST-correct for the instant
    # (issue #20). Wire bytes captured from XE 11g FROM_TZ(ts, region).

    def test_us_eastern_winter_is_est(self):
        # 2024-01-15 12:00 US/Eastern -> stored 17:00 UTC, -05:00 (EST).
        Data = bytes([120, 124, 1, 15, 18, 1, 1, 0, 0, 0, 0, 137, 144])
        Dt = decode_date(Data)
        self.assertEqual(Dt.utcoffset(), datetime.timedelta(hours=-5))
        self.assertEqual(
            Dt.replace(tzinfo=None), datetime.datetime(2024, 1, 15, 12, 0, 0)
        )

    def test_asia_tokyo(self):
        # 2024-01-15 12:00 Asia/Tokyo -> 03:00 UTC, +09:00 (no DST).
        Data = bytes([120, 124, 1, 15, 4, 1, 1, 0, 0, 0, 0, 132, 44])
        Dt = decode_date(Data)
        self.assertEqual(Dt.utcoffset(), datetime.timedelta(hours=9))
        self.assertEqual(
            Dt.replace(tzinfo=None), datetime.datetime(2024, 1, 15, 12, 0, 0)
        )

    def test_region_id_multiple_of_64_has_zero_low_byte(self):
        # A region id that is a multiple of 64 (America/Manaus = 192) encodes its
        # low tz byte (Data[12]) as 0. The decoder must still resolve the named
        # zone, not fall through to a naive UTC wall clock (#304). Frame captured
        # live from 21c: from_tz(timestamp '2024-06-15 10:00:00','America/Manaus')
        # stores 14:00 UTC (Manaus is UTC-4).
        Data = bytes([120, 124, 6, 15, 15, 1, 1, 0, 0, 0, 0, 131, 0])
        Dt = decode_date(Data)
        self.assertIsNotNone(Dt.tzinfo)
        self.assertEqual(Dt.utcoffset(), datetime.timedelta(hours=-4))
        self.assertEqual(
            Dt.replace(tzinfo=None), datetime.datetime(2024, 6, 15, 10, 0, 0)
        )

    def test_unknown_region_falls_back_to_naive(self):
        # An unmapped region id must not crash — fall back to naive UTC.
        Data = bytes([120, 124, 1, 15, 18, 1, 1, 0, 0, 0, 0, 0xFF, 0xFC])
        Dt = decode_date(Data)
        self.assertIsNone(Dt.tzinfo)


class TestBcDateCarriedOn(unittest.TestCase):
    """The passthrough's switch: a BC date decodes to a value, not an error (#1069).

    The Mirror's passthrough relays rows to a client that decides for itself, so
    it must carry such a date on. The public client never sets the switch.
    """

    MIN_ORACLE_DATE = bytes.fromhex('35580101010101')

    def setUp(self):
        from seerdb.common.types import _DECODE_BC_DATES, set_decode_bc_dates

        token = set_decode_bc_dates(True)
        self.addCleanup(_DECODE_BC_DATES.reset, token)

    def test_a_bc_date_becomes_a_bcdate(self):
        from seerdb.common.datatypes import BcDate

        self.assertEqual(decode_date(self.MIN_ORACLE_DATE), BcDate(-4712, 1, 1))

    def test_a_bc_timestamp_keeps_its_fraction(self):
        from seerdb.common.datatypes import BcDate

        stamp = bytes.fromhex('6438030f0d1f2e075bca00')  # DUMP of a stored column
        self.assertEqual(decode_date(stamp), BcDate(-44, 3, 15, 12, 30, 45, 123456))

    def test_one_with_a_time_zone_still_raises(self):
        # BcDate has no zone (#1071), so it is not invented one.
        from seerdb.common.exceptions import DateOutOfRangeError

        with self.assertRaises(DateOutOfRangeError):
            decode_date(self.MIN_ORACLE_DATE + bytes(4) + bytes([20, 60]))

    def test_a_malformed_date_is_still_malformed(self):
        with self.assertRaises(DataError):
            decode_date(bytes.fromhex('78780d01010101'))  # month 13

    def test_the_switch_is_off_by_default(self):
        import contextvars

        from seerdb.common.exceptions import DateOutOfRangeError

        def fresh():
            with self.assertRaises(DateOutOfRangeError):
                decode_date(self.MIN_ORACLE_DATE)

        contextvars.Context().run(fresh)


class TestBcDate(unittest.TestCase):
    """A BC date is VALID Oracle data that datetime cannot hold (#1060).

    Oracle's DATE runs from 4712 BC; Python's datetime starts at year 1. It used
    to be reported as "malformed", telling a caller the server sent garbage when
    it sent a correct value. It is now a DateOutOfRangeError: still a DataError
    (#230's rule) and also a ValueError, as python-oracledb raises. The cases
    that matter as much are the ones that must STAY malformed.
    """

    # to_date('-4712-01-01', 'SYYYY-MM-DD'), as a live 23ai sends it: century
    # byte 53 and year byte 88 are (53-100)*100 + (88-100) = -4712.
    MIN_ORACLE_DATE = bytes.fromhex('35580101010101')

    def test_the_earliest_oracle_date_is_out_of_range_not_malformed(self):
        from seerdb.common.exceptions import DateOutOfRangeError

        with self.assertRaises(DateOutOfRangeError) as caught:
            decode_date(self.MIN_ORACLE_DATE)
        self.assertNotIn('malformed', str(caught.exception))
        self.assertIn('-4712', str(caught.exception))

    def test_it_is_both_a_data_error_and_a_value_error(self):
        # DataError keeps #230's rule (catchable by DB-API class); ValueError is
        # what the reference client raises and what its suite asserts.
        with self.assertRaises(DataError):
            decode_date(self.MIN_ORACLE_DATE)
        with self.assertRaises(ValueError):
            decode_date(self.MIN_ORACLE_DATE)

    def test_a_bad_month_is_still_malformed(self):
        from seerdb.common.exceptions import DateOutOfRangeError

        # 2024-13-01: a real year with an impossible month is corrupt data.
        with self.assertRaises(DataError) as caught:
            decode_date(bytes([120, 124, 13, 1, 1, 1, 1]))
        self.assertNotIsInstance(caught.exception, DateOutOfRangeError)
        self.assertIn('malformed', str(caught.exception))

    def test_a_bc_year_with_a_bad_field_is_still_malformed(self):
        # A corrupt frame can land on a negative year by accident; the other
        # fields have to be sane before the year alone is believed.
        from seerdb.common.exceptions import DateOutOfRangeError

        with self.assertRaises(DataError) as caught:
            decode_date(bytes([0x35, 0x58, 13, 1, 1, 1, 1]))  # -4712, month 13
        self.assertNotIsInstance(caught.exception, DateOutOfRangeError)

    def test_year_zero_is_malformed(self):
        # Oracle has no year 0 -- 1 BC is followed by AD 1.
        from seerdb.common.exceptions import DateOutOfRangeError

        with self.assertRaises(DataError) as caught:
            decode_date(bytes([100, 100, 1, 1, 1, 1, 1]))
        self.assertNotIsInstance(caught.exception, DateOutOfRangeError)

    def test_a_year_before_the_oracle_minimum_is_malformed(self):
        # -4713 is below Oracle's own floor, so no server sent it.
        from seerdb.common.exceptions import DateOutOfRangeError

        with self.assertRaises(DataError) as caught:
            decode_date(bytes([0x35, 0x57, 1, 1, 1, 1, 1]))
        self.assertNotIsInstance(caught.exception, DateOutOfRangeError)


class TestDecodeUb4(unittest.TestCase):
    # PROTOCOL.md §12.1 variable-length integer.

    def test_zero(self):
        self.assertEqual(decode_ub4(b'\x00rest'), (0, b'rest'))

    def test_one_byte(self):
        self.assertEqual(decode_ub4(b'\x01\x7f'), (127, b''))

    def test_two_bytes(self):
        self.assertEqual(decode_ub4(b'\x02\x01\x00'), (256, b''))

    def test_three_bytes(self):
        self.assertEqual(decode_ub4(b'\x03\x01\x00\x00'), (65536, b''))

    def test_four_bytes(self):
        self.assertEqual(decode_ub4(b'\x04\xff\xff\xff\xff'), (4294967295, b''))

    def test_consumes_only_its_own_bytes(self):
        self.assertEqual(decode_ub4(b'\x02\x01\x00tail'), (256, b'tail'))

    def test_negative_single_byte(self):
        # NUMBER scale -127 arrives as 0x81 0x7f.
        self.assertEqual(decode_ub4(b'\x81\x7f'), (-127, b''))

    def test_length_gt4_consumes_two_bytes(self):
        # A length byte > 4 isn't a real ub4 — it only occurs where
        # decode_token_oer reads a raw ub2 / counter field through here. The
        # contract is to consume exactly two bytes (the ub2 width) so the OER
        # stream stays aligned; the returned value is discarded by those
        # callers. Raising here desyncs ordinary multi-row fetches.
        self.assertEqual(decode_ub4(b'\x07\x00tail'), (0, b'tail'))
        self.assertEqual(decode_ub4(b'\x0a\x01tail'), (-1, b'tail'))

    def test_roundtrip_with_encode_sb4(self):
        for value in (0, 1, 127, 255, 256, 65535, 65536, 16777215, 4294967295):
            self.assertEqual(decode_ub4(encode_sb4(value)), (value, b''))


class TestVarOacTypes(unittest.TestCase):
    # A Var(<type const>) OUT bind must declare the same OAC (type + buffer
    # size) the server would expect for a value of that type (issue #17).

    def test_timestamp(self):
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_TIMESTAMP)),
            encode_token_oac(datetime.datetime(2026, 6, 7, 1, 2, 3, 500000)),
        )

    def test_timestamp_tz(self):
        tz = datetime.datetime(2026, 6, 7, 1, 2, 3, tzinfo=datetime.timezone.utc)
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_TIMESTAMP_TZ)), encode_token_oac(tz)
        )

    def test_binary_float(self):
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_BINARY_FLOAT)),
            encode_token_oac(BinaryFloat(1.0)),
        )

    def test_binary_double(self):
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_BINARY_DOUBLE)),
            encode_token_oac(BinaryDouble(1.0)),
        )

    def test_interval_ds(self):
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_INTERVAL_DS)),
            encode_token_oac(datetime.timedelta(days=1)),
        )

    def test_interval_ym(self):
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_INTERVAL_YM)),
            encode_token_oac(IntervalYM(1, 2)),
        )

    def test_clob_and_blob(self):
        # A declared CLOB / BLOB Var carries the fixed LOB bind OAC -- the same
        # one a temp-LOB locator bind uses (#902). Its type byte is 0x70 / 0x71,
        # and it is identical to encoding a TempLob of that kind. 12.1+ only: 11g
        # has no CREATE_TEMP for the value promotion, so it still raises there.
        from seerdb.common.datatypes import DB_TYPE_BLOB, DB_TYPE_CLOB, TempLob
        from seerdb.common.tns import _ENCODE_FIELD_VERSION
        from seerdb.common.tns_consts import FIELD_VERSION_12_1

        loc = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x00'
        token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
        try:
            clob_oac = encode_token_oac(Var(DB_TYPE_CLOB))
            blob_oac = encode_token_oac(Var(DB_TYPE_BLOB))
            self.assertEqual(clob_oac[0], 0x70)
            self.assertEqual(blob_oac[0], 0x71)
            self.assertEqual(clob_oac, encode_token_oac(TempLob(loc, is_blob=False)))
            self.assertEqual(blob_oac, encode_token_oac(TempLob(loc, is_blob=True)))
        finally:
            _ENCODE_FIELD_VERSION.reset(token)

    def test_python_type_mappings_resolve(self):
        self.assertEqual(Var(datetime.timedelta).dbtype, DB_TYPE_INTERVAL_DS)
        self.assertEqual(Var(IntervalYM).dbtype, DB_TYPE_INTERVAL_YM)


class TestOtherTypeVectors(unittest.TestCase):
    """Known-answer vectors for BINARY_FLOAT/DOUBLE and INTERVAL YM/DS (#439).

    Each row's bytes were produced by ``SELECT dump(cast(<literal> as <type>))``
    against a live Oracle, so they are exactly what Oracle puts on the wire. The
    *choice* of literals covers the same ground as go-ora's other-types test
    table; the Oracle-output bytes are authoritative. Both
    directions are checked: decode (bytes → value) and encode (value → bytes).
    """

    def test_binary_float(self):
        # dump(cast(134.45 as binary_float)) → 195,6,115,51 (Typ=100 Len=4).
        cases = [
            (134.45, bytes([195, 6, 115, 51])),
            (-134.45, bytes([60, 249, 140, 204])),
        ]
        for value, raw in cases:
            self.assertEqual(encode_token_binary_float(value), raw)
            # BINARY_FLOAT is IEEE single, so the decode lands at float32 precision.
            self.assertAlmostEqual(decode_binary_float(raw), value, places=2)

    def test_binary_double(self):
        # dump(cast(134.45 as binary_double)) → 192,96,206,102,102,102,102,102.
        cases = [
            (134.45, bytes([192, 96, 206, 102, 102, 102, 102, 102])),
            (-134.45, bytes([63, 159, 49, 153, 153, 153, 153, 153])),
        ]
        for value, raw in cases:
            self.assertEqual(encode_token_binary_double(value), raw)
            self.assertEqual(decode_binary_double(raw), value)

    def test_interval_year_to_month(self):
        # dump(cast(TO_YMINTERVAL('2021-10') as INTERVAL YEAR TO MONTH)) → 128,0,7,229,70.
        cases = [
            (IntervalYM(2021, 10), bytes([128, 0, 7, 229, 70])),  # +2021-10
            (IntervalYM(-2021, -10), bytes([127, 255, 248, 27, 50])),  # -2021-10
            (IntervalYM(-5, -10), bytes([127, 255, 255, 251, 50])),  # -05-10
            (IntervalYM(-5, -3), bytes([127, 255, 255, 251, 57])),  # -05-03
            (IntervalYM(0, 10), bytes([128, 0, 0, 0, 70])),  # +00-10
            (IntervalYM(0, -3), bytes([128, 0, 0, 0, 57])),  # -00-03
        ]
        for value, raw in cases:
            self.assertEqual(decode_interval_ym(raw), value)
            self.assertEqual(encode_token_interval_ym(value), raw)

    def test_interval_day_to_second(self):
        # dump(cast(TO_DSINTERVAL('2 12:23:34.456') as INTERVAL DAY TO SECOND))
        #   → 128,0,0,2,72,83,94,155,46,2,0.
        td = datetime.timedelta
        cases = [
            (
                td(days=2, hours=12, minutes=23, seconds=34, microseconds=456000),
                bytes([128, 0, 0, 2, 72, 83, 94, 155, 46, 2, 0]),
            ),  # +02 12:23:34.456000
            (
                -td(days=2, hours=12, minutes=23, seconds=34, microseconds=456789),
                bytes([127, 255, 255, 254, 48, 37, 26, 100, 197, 243, 248]),
            ),  # -02 ...456789
            (
                td(hours=10, minutes=20, seconds=30, microseconds=456789),
                bytes([128, 0, 0, 0, 70, 80, 90, 155, 58, 12, 8]),
            ),  # +00 10:20:30.456789
            (
                -td(hours=10, minutes=20, seconds=30, microseconds=456789),
                bytes([128, 0, 0, 0, 50, 40, 30, 100, 197, 243, 248]),
            ),  # -00 10:20:30.456789
            (
                -td(hours=10, minutes=20, seconds=30),
                bytes([128, 0, 0, 0, 50, 40, 30, 128, 0, 0, 0]),
            ),  # -00 10:20:30.000000
        ]
        for value, raw in cases:
            self.assertEqual(decode_interval_ds(raw), value)
            self.assertEqual(encode_token_interval_ds(value), raw)


class TestExecOacSignature(unittest.TestCase):
    # The DML cursor-cache key includes this signature so a cached cursor is
    # only reused for binds matching the OAC it was parsed with. Two binds that
    # would need a differently-sized OAC MUST produce different signatures, or
    # the cached re-execute (which omits the OAC) overflows the frozen bind
    # buffer and the server raises ORA-01461.

    def test_empty_bind(self):
        self.assertEqual(exec_oac_signature([], []), b'')

    def test_same_length_strings_match(self):
        self.assertEqual(
            exec_oac_signature([1, 'abcd'], []), exec_oac_signature([2, 'wxyz'], [])
        )

    def test_different_length_strings_differ(self):
        # "row9" (4 bytes) vs "row10" (5 bytes) — the exact case that tripped
        # ORA-01461 on a cached re-execute.
        self.assertNotEqual(
            exec_oac_signature([9, 'row9'], []), exec_oac_signature([10, 'row10'], [])
        )

    def test_number_value_does_not_affect_signature(self):
        # NUMBER is fixed-width, so a bigger integer keeps the same signature.
        self.assertEqual(
            exec_oac_signature([1], []), exec_oac_signature([999999999], [])
        )

    def test_str_vs_bytes_differ(self):
        self.assertNotEqual(
            exec_oac_signature(['abc'], []), exec_oac_signature([b'abc'], [])
        )

    def test_batch_uses_widest_row(self):
        # Array DML sizes the single OAC to the widest value across all rows,
        # so a batch whose widest string grows gets a different signature.
        narrow = exec_oac_signature([1, 'a'], [[2, 'bb']])
        wide = exec_oac_signature([1, 'a'], [[2, 'bbbbb']])
        self.assertNotEqual(narrow, wide)


class TestDecodeDalc(unittest.TestCase):
    # PROTOCOL.md §12.2 Data with Attached Length Code.

    def test_empty(self):
        self.assertEqual(decode_dalc(b'\x00tail'), ([], b'tail'))

    def test_null_marker(self):
        # 0xFF null marker carries no data; reported like empty.
        self.assertEqual(decode_dalc(b'\xfftail'), ([], b'tail'))

    def test_direct_length(self):
        self.assertEqual(decode_dalc(b'\x03abctail'), (b'abc', b'tail'))

    def test_truncated_raises_dataerror(self):
        # An empty buffer indexes Bytes[0] out of range; must raise DataError,
        # not a raw IndexError (#230). (A short direct-length field slices
        # leniently and returns the partial bytes, which is unchanged.)
        with self.assertRaises(DataError):
            decode_dalc(b'')


class TestMalformedScalarDecode(unittest.TestCase):
    # A malformed column value must raise a domain error (DataError), not a raw
    # ValueError / decimal.InvalidOperation from the underlying parse (#230).

    def test_number_malformed_raises_dataerror(self):
        # Mantissa bytes that yield a non-numeric digit string (base-100 pairs
        # out of the 1..100 range) -- from the SeerODBC fuzz corpus.
        for hx in ('655aff02', '9c00ff'):
            with self.subTest(hx=hx):
                with self.assertRaises(DataError):
                    decode_number(bytes.fromhex(hx))

    def test_date_out_of_range_raises_dataerror(self):
        # 7-byte DATE with month 0 -> datetime() rejects.
        with self.assertRaises(DataError):
            decode_date(bytes.fromhex('787c0001010101'))

    def test_valid_scalars_still_decode(self):
        # Guard against the try/except swallowing valid values.
        self.assertEqual(decode_number(bytes.fromhex('c12b')), 42)
        self.assertEqual(
            decode_date(bytes.fromhex('787c060f010101')),
            datetime.datetime(2024, 6, 15, 0, 0, 0),
        )


class TestEncodeTokenDecimal(unittest.TestCase):
    # Exact base-100 NUMBER encoding for Decimal: every value round-trips through
    # decode_number() unchanged, including precision beyond float's ~15 digits.

    def test_round_trips_exactly(self):
        cases = [
            Decimal('0'),
            Decimal('5'),
            Decimal('-3'),
            Decimal('100'),
            Decimal('1234.5'),
            Decimal('0.005'),
            Decimal('-0.005'),
            Decimal('3.14'),
            Decimal('0.1'),
            Decimal('1E-20'),
            Decimal('1.5E-10'),
            Decimal('-9999999999.9999999999'),
            # Precision beyond float: the old float detour truncated these.
            Decimal('1.2345678901234567890'),
            Decimal('-1.2345678901234567890'),
            Decimal('123456789012345678901234567890'),
            Decimal('9999999999999999999999999999999999999'),
            Decimal('0.30000000000000004'),
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    Decimal(decode_number(encode_token_decimal(value))), value
                )

    def test_high_precision_beats_the_float_path(self):
        # The exact encoder keeps all 19 significant digits where the historical
        # float path lost everything past the 15th.
        value = Decimal('1.234567890123456789')
        self.assertEqual(decode_number(encode_token_decimal(value)), value)
        self.assertNotEqual(decode_number(encode_token_num(float(value))), value)

    def test_zero_is_the_single_byte_form(self):
        self.assertEqual(encode_token_decimal(Decimal('0')), bytes([128]))
        self.assertEqual(encode_token_decimal(Decimal('0.00')), bytes([128]))

    def test_integral_matches_the_int_encoder(self):
        for i in (5, -3, 100, 0, 123456789, -987654321):
            with self.subTest(i=i):
                self.assertEqual(encode_token_decimal(Decimal(i)), encode_token_num(i))

    def test_large_integer_magnitudes_round_trip(self):
        # #304: an integral value >= 10**40 needs more than lnxmin's 20 base-100
        # groups, but is a valid Oracle NUMBER (<= ~1e125, <= 38 significant
        # digits) once trailing-zero groups fold into the exponent. Both the int
        # encoder and the integral-Decimal path used to raise 'LnxMin cannot
        # handle this'; they must now round-trip through decode_number().
        cases = [
            10**40,  # boundary: the first magnitude lnxmin rejects
            10**41,
            10**100,
            10**125,  # Oracle NUMBER maximum magnitude
            -(10**125),
            123 * 10**120,  # a few significant digits at a huge magnitude
            int('9' * 38) * 10**80,  # 38 significant digits, large magnitude
            -(int('9' * 38) * 10**80),
        ]
        for value in cases:
            with self.subTest(value=value):
                # int encoder (plain-int bind path)
                self.assertEqual(decode_number(encode_token_num(value)), value)
                # integral-Decimal path (Decimal bind), byte-identical to it
                self.assertEqual(
                    encode_token_decimal(Decimal(value)), encode_token_num(value)
                )

    def test_non_finite_raises(self):
        for value in (Decimal('NaN'), Decimal('Infinity'), Decimal('-Infinity')):
            with self.subTest(value=value):
                with self.assertRaises(DataError):
                    encode_token_decimal(value)


class TestBinaryFloat(unittest.TestCase):
    def test_encode_positive(self):
        self.assertEqual(
            encode_token_binary_float(BinaryFloat(1.5)), bytes.fromhex('bfc00000')
        )

    def test_encode_negative(self):
        self.assertEqual(
            encode_token_binary_float(BinaryFloat(-2.25)), bytes.fromhex('3fefffff')
        )

    def test_decode_positive(self):
        self.assertEqual(decode_binary_float(bytes.fromhex('bfc00000')), 1.5)

    def test_decode_negative(self):
        self.assertEqual(decode_binary_float(bytes.fromhex('3fefffff')), -2.25)

    def test_decode_empty_is_none(self):
        self.assertIsNone(decode_binary_float(b''))

    def test_roundtrip_inf(self):
        Wire = encode_token_binary_float(BinaryFloat(math.inf))
        self.assertEqual(decode_binary_float(Wire), math.inf)

    def test_roundtrip_neg_inf(self):
        Wire = encode_token_binary_float(BinaryFloat(-math.inf))
        self.assertEqual(decode_binary_float(Wire), -math.inf)

    def test_roundtrip_nan(self):
        Wire = encode_token_binary_float(BinaryFloat(math.nan))
        self.assertTrue(math.isnan(decode_binary_float(Wire)))

    def test_roundtrip_signed_zero(self):
        # -0.0 must survive the order-preserving transform with its sign intact:
        # it maps to distinct wire bytes from +0.0 (captured live on 21c:
        # +0.0 -> 0x80000000, -0.0 -> 0x7fffffff). `==` treats -0.0 == +0.0, so
        # the sign has to be checked with copysign.
        PosWire = encode_token_binary_float(BinaryFloat(0.0))
        NegWire = encode_token_binary_float(BinaryFloat(-0.0))
        self.assertEqual(PosWire, bytes.fromhex('80000000'))
        self.assertEqual(NegWire, bytes.fromhex('7fffffff'))
        self.assertEqual(math.copysign(1.0, decode_binary_float(PosWire)), 1.0)
        self.assertEqual(math.copysign(1.0, decode_binary_float(NegWire)), -1.0)


class TestBinaryDouble(unittest.TestCase):
    def test_encode_positive(self):
        self.assertEqual(
            encode_token_binary_double(BinaryDouble(1.5)),
            bytes.fromhex('bff8000000000000'),
        )

    def test_encode_negative(self):
        self.assertEqual(
            encode_token_binary_double(BinaryDouble(-1234.5678)),
            bytes.fromhex('3f6cb5ba92a30552'),
        )

    def test_decode_positive(self):
        self.assertEqual(decode_binary_double(bytes.fromhex('bff8000000000000')), 1.5)

    def test_decode_negative(self):
        self.assertEqual(
            decode_binary_double(bytes.fromhex('3f6cb5ba92a30552')), -1234.5678
        )

    def test_roundtrip_specials(self):
        for V in (math.inf, -math.inf, 0.0, -0.0):
            self.assertEqual(
                decode_binary_double(encode_token_binary_double(BinaryDouble(V))), V
            )
        self.assertTrue(
            math.isnan(
                decode_binary_double(encode_token_binary_double(BinaryDouble(math.nan)))
            )
        )

    def test_roundtrip_signed_zero(self):
        # The == above cannot distinguish -0.0 from +0.0; assert the sign is
        # actually preserved through the order-preserving transform. Wire bytes
        # captured live on 21c: +0.0 -> 0x80..00, -0.0 -> 0x7f..ff.
        PosWire = encode_token_binary_double(BinaryDouble(0.0))
        NegWire = encode_token_binary_double(BinaryDouble(-0.0))
        self.assertEqual(PosWire, bytes.fromhex('8000000000000000'))
        self.assertEqual(NegWire, bytes.fromhex('7fffffffffffffff'))
        self.assertEqual(math.copysign(1.0, decode_binary_double(PosWire)), 1.0)
        self.assertEqual(math.copysign(1.0, decode_binary_double(NegWire)), -1.0)


class TestIntervalDS(unittest.TestCase):
    def test_encode_positive(self):
        TD = datetime.timedelta(
            days=5, hours=4, minutes=3, seconds=2, microseconds=123456
        )
        self.assertEqual(
            encode_token_interval_ds(TD), bytes.fromhex('80000005403f3e875bca00')
        )

    def test_encode_negative(self):
        self.assertEqual(
            encode_token_interval_ds(datetime.timedelta(seconds=-1.5)),
            bytes.fromhex('800000003c3c3b62329b00'),
        )

    def test_decode_positive(self):
        self.assertEqual(
            decode_interval_ds(bytes.fromhex('80000005403f3e875bca00')),
            datetime.timedelta(
                days=5, hours=4, minutes=3, seconds=2, microseconds=123456
            ),
        )

    def test_decode_negative(self):
        self.assertEqual(
            decode_interval_ds(bytes.fromhex('800000003c3c3b62329b00')),
            datetime.timedelta(seconds=-1.5),
        )

    def test_roundtrip(self):
        for TD in (
            datetime.timedelta(0),
            datetime.timedelta(days=-3, hours=-2),
            datetime.timedelta(days=400, microseconds=999999),
        ):
            self.assertEqual(decode_interval_ds(encode_token_interval_ds(TD)), TD)

    def test_decode_extreme_valid_days(self):
        # +/-999_999_999 days at 00:00:00 sit exactly on timedelta's own limits,
        # so these legal extremes must still decode.
        for Days in (999999999, -999999999):
            Raw = (
                (2**31 + Days).to_bytes(4, 'big')
                + b'\x3c\x3c\x3c'
                + (2**31).to_bytes(4, 'big')
            )
            self.assertEqual(decode_interval_ds(Raw), datetime.timedelta(days=Days))

    def test_decode_most_negative_legal_interval_overflows(self):
        # timedelta.min is exactly -999_999_999 00:00:00, but INTERVAL DAY(9) TO
        # SECOND legally reaches -999_999_999 23:59:59.999999 -- a value a real
        # server CAN send (#304). It overflows timedelta, so it must surface as a
        # clean DataError, not a raw OverflowError. Frame: days=-999_999_999,
        # H=M=S=-59/-23, frac=-999_999_000 ns.
        Raw = (
            (2**31 - 999999999).to_bytes(4, 'big')
            + bytes([60 - 23, 60 - 59, 60 - 59])
            + (2**31 - 999999000).to_bytes(4, 'big')
        )
        with self.assertRaises(DataError):
            decode_interval_ds(Raw)

    def test_decode_out_of_range_raises_dataerror(self):
        # Raw day counts a real server cannot send (beyond DAY(9)) overflow
        # timedelta; a corrupt/truncated frame must surface as DataError, not a
        # raw OverflowError. all-zero -> days=-2**31; all-0xFF -> days~+2**31.
        for Raw in (b'\x00' * 11, b'\xff' * 11):
            with self.subTest(raw=Raw.hex()):
                with self.assertRaises(DataError):
                    decode_interval_ds(Raw)


class TestIntervalYM(unittest.TestCase):
    def test_encode_positive(self):
        self.assertEqual(
            encode_token_interval_ym(IntervalYM(3, 7)), bytes.fromhex('8000000343')
        )

    def test_encode_negative(self):
        self.assertEqual(
            encode_token_interval_ym(IntervalYM(-1, -2)), bytes.fromhex('7fffffff3a')
        )

    def test_decode_positive(self):
        self.assertEqual(
            decode_interval_ym(bytes.fromhex('8000000343')), IntervalYM(3, 7)
        )

    def test_decode_negative(self):
        self.assertEqual(
            decode_interval_ym(bytes.fromhex('7fffffff3a')), IntervalYM(-1, -2)
        )

    def test_normalisation(self):
        self.assertEqual(IntervalYM(0, 14), IntervalYM(1, 2))
        self.assertEqual(IntervalYM(0, -14), IntervalYM(-1, -2))
        iv = IntervalYM(0, 14)
        self.assertEqual((iv.years, iv.months), (1, 2))

    def test_roundtrip(self):
        for iv in (
            IntervalYM(0, 0),
            IntervalYM(2, 0),
            IntervalYM(0, 14),
            IntervalYM(-5, -11),
        ):
            self.assertEqual(decode_interval_ym(encode_token_interval_ym(iv)), iv)


class TestRowid(unittest.TestCase):
    # Bytes captured from a live XE row whose ROWIDTOCHAR was
    # "AAAK6JAAEAAACGPAAA" (obj 44681, file 4, block 8591, slot 0).

    def test_rowid_to_string(self):
        self.assertEqual(rowid_to_string(44681, 4, 8591, 0), 'AAAK6JAAEAAACGPAAA')

    def test_rowid_to_string_slot(self):
        # Slot increments map to the trailing base64 digit.
        self.assertEqual(rowid_to_string(44681, 4, 8591, 4)[-3:], 'AAE')

    def test_read_rowid_column(self):
        # 1-byte present indicator (0x0e) + structured rowid, then a trailing
        # byte that must be left for the next token.
        Wire = bytes.fromhex('0e02ae8901040002218f00') + b'\x08'
        Value, Rest = _read_rowid_column(Wire)
        self.assertEqual(Value, 'AAAK6JAAEAAACGPAAA')
        self.assertEqual(Rest, b'\x08')

    def test_read_rowid_null(self):
        Value, Rest = _read_rowid_column(b'\x00\x04rest')
        self.assertIsNone(Value)
        self.assertEqual(Rest, b'\x04rest')


class TestUrowid(unittest.TestCase):
    # Bytes captured from a live XE index-organized table row whose SELECT
    # ROWID was "*BAEAGYMCwQL+" (type tag 0x02 + 9 rowid bytes carrying the
    # NUMBER primary key c1 02).

    def test_a_physical_rowid_in_a_urowid_column(self):
        # Tag 0x01: the ordinary extended rowid, as the same row's ROWID column
        # prints it and python-oracledb renders it. Bytes captured from 23ai
        # (#1086); seerdb used to render them '*AAH1wQAAAAFa7QAA'.
        self.assertEqual(
            urowid_to_string(bytes.fromhex('010001f5c1000000015aed0000')),
            'AAAfXBAAAAAAVrtAAA',
        )

    def test_urowid_to_string(self):
        self.assertEqual(
            urowid_to_string(bytes.fromhex('02040100198302c102fe')), '*BAEAGYMCwQL+'
        )

    def test_read_urowid_column(self):
        # ub4 num_bytes (0x0a) + 1-byte echo (0x0a) + 10 value bytes, then a
        # trailing NUMBER that must be left for the next column.
        Wire = bytes.fromhex('010a0a02040100198302c102fe') + bytes.fromhex('02c102')
        Value, Rest = _read_urowid_column(Wire)
        self.assertEqual(Value, '*BAEAGYMCwQL+')
        self.assertEqual(Rest, bytes.fromhex('02c102'))

    def test_read_urowid_null(self):
        Value, Rest = _read_urowid_column(b'\x00\x05rest!')
        self.assertIsNone(Value)
        self.assertEqual(Rest, b'\x05rest!')


class TestLong(unittest.TestCase):
    # Bytes captured from live XE rows (value portion + the two trailing ub4
    # indicators), with a trailing 0x04 / NUMBER standing in for the next token
    # so we can assert the reader leaves the stream aligned.

    def test_long_single(self):
        Val, Rest = _read_long_column(bytes.fromhex('fe015a00000004'))
        self.assertEqual(Val, b'Z')
        self.assertEqual(Rest, b'\x04')

    def test_long_then_number(self):
        # 'AB' value, terminator 00, trailer 00 00, then NUMBER 02 c1 02 which
        # must be left intact for the next column.
        Val, Rest = _read_long_column(bytes.fromhex('fe02414200000002c102'))
        self.assertEqual(Val, b'AB')
        self.assertEqual(Rest, bytes.fromhex('02c102'))

    def test_long_multichunk(self):
        # Two chunks "AB" + "CD" then the zero terminator and two ub4 trailers.
        Val, Rest = _read_long_column(bytes.fromhex('fe0241420243440000000a'))
        self.assertEqual(Val, b'ABCD')
        self.assertEqual(Rest, b'\x0a')

    def test_long_null(self):
        # NULL value (0x00) then the two ub4 indicators 81 01 / 02 05 7d, then
        # a following NUMBER 02 c1 64.
        Val, Rest = _read_long_column(bytes.fromhex('00810102057d02c164'))
        self.assertIsNone(Val)
        self.assertEqual(Rest, bytes.fromhex('02c164'))

    def test_decode_value_long_is_str(self):
        from seerdb.common.tns_consts import TNS_TYPE_LONG

        self.assertEqual(decode_value({'data_type': TNS_TYPE_LONG}, b'hi'), 'hi')

    def test_decode_value_longraw_is_bytes(self):
        from seerdb.common.tns_consts import TNS_TYPE_LONGRAW

        Out = decode_value({'data_type': TNS_TYPE_LONGRAW}, b'\xde\xad')
        self.assertEqual(Out, b'\xde\xad')
        self.assertIsInstance(Out, bytes)

    def test_decode_value_binary_integer_is_a_number(self):
        # BINARY_INTEGER / PLS_INTEGER (TNS_TYPE_INT) rides the wire as an
        # Oracle NUMBER -- the same fact the OUT-bind encoder relies on. With no
        # branch of its own it fell through undecoded, so the raw NUMBER bytes
        # surfaced as DB_TYPE_RAW b'\xc1 ' instead of the integer 31 (#826).
        from seerdb.common.tns_consts import TNS_TYPE_INT

        self.assertEqual(decode_value({'data_type': TNS_TYPE_INT}, b'\xc1 '), 31)


class TestPasswordRedaction(unittest.TestCase):
    # The bind/handshake dicts carry the password so the encoders can use it;
    # it must never reach a debug log in clear text (CodeQL
    # py/clear-text-logging-sensitive-data).

    def test_redacted_omits_password(self):
        # Allow-list: the password key is never read, so it is absent from the
        # safe copy; non-secret fields are kept.
        from seerdb.common.tns import _redacted

        out = _redacted({'env': {'user': 'u', 'password': 'secret', 'host': 'h'}})
        self.assertNotIn('password', out['env'])
        self.assertEqual(out['env']['user'], 'u')
        self.assertEqual(out['env']['host'], 'h')

    def test_redacted_drops_auth_secrets(self):
        # The changepassword auth dict (session key + old/new passwords) is
        # dropped wholesale (#21).
        from seerdb.common.tns import _redacted

        out = _redacted(
            {
                'seq': 1,
                'auth': {'conn_key': b'k', 'old_password': 'op', 'new_password': 'np'},
            }
        )
        self.assertEqual(out['auth'], '<redacted>')

    def test_description_debug_log_omits_password(self):
        from seerdb.common.tns import encode_dictionary_description

        d = {
            'env': {
                'user': 'scott',
                'password': 'tiger',
                'host': 'h',
                'port': 1521,
                'sid': '',
                'service_name': 'XE',
                'app_name': 'seerdb',
                'ssl': None,
            },
            'seq': 1,
        }
        with self.assertLogs('seerdb.common.tns', level='DEBUG') as cm:
            encode_dictionary_description(d)
        joined = '\n'.join(cm.output)
        self.assertNotIn('tiger', joined)
        # Non-secret fields are still logged for debuggability.
        self.assertIn('scott', joined)


class TestRefCursor(unittest.TestCase):
    # A TTI_IOV captured from XE 11g for BEGIN pyo_refcur(:1); END; where the
    # proc opens a cursor over SELECT 1 a, 'x' b ... (one OUT REF CURSOR bind).
    WIRE = bytes.fromhex(
        '0b05010100010100000010074c0103010251020000817f0102000000000000'
        '0001010101014100000000608000000101000000000203690101010101010101'
        '420000010100010707787e0606100d040000000000010200080106031a0a6400'
        '010101020000000000040105010401010000000101002f00000000000000000000'
        '00000700010100000000'
    )

    def test_refcursor_iov_parse(self):
        from seerdb.client.cursor import cursor as RefCur
        from seerdb.common.tns import _read_iov

        directions, out_values, _ = _read_iov(self.WIRE, [RefCur()])
        self.assertEqual(directions, [16])  # one OUT bind
        self.assertEqual(len(out_values), 1)
        marker = out_values[0]
        self.assertTrue(marker.get('_refcursor'))
        self.assertIsInstance(marker['cursor_id'], int)
        self.assertGreater(marker['cursor_id'], 0)
        self.assertEqual(
            [c.get('column_name') for c in marker['row_format']], [b'A', b'B']
        )

    def test_scalar_bind_not_treated_as_refcursor(self):
        # Without a REF CURSOR bind, a scalar OUT value stays raw bytes.
        from seerdb.common.tns import _read_iov

        wire = bytes(
            [
                0x0B,
                0x05,
                0x01,
                0x01,
                0x00,
                0x01,
                0x01,
                0x00,
                0x00,
                0x00,
                0x10,
                0x07,
                0x02,
                0xC1,
                0x64,
                0x00,
                0x08,
            ]
        )
        _, out_values, _ = _read_iov(wire, [None])
        self.assertEqual(out_values, [b'\xc1\x64'])


class TestObjectMetadataReply(unittest.TestCase):
    # The object-type metadata call (python-oracledb's dbms_pickler.get_type_shape)
    # comes back as an IOV of OUT binds that must not desync the reader (#888):
    # a BINARY_INTEGER rides as a NUMBER, a REF CURSOR's trailer is a return code,
    # and a describe-zero-length column sends no row bytes.

    def test_binary_integer_out_bind_is_nonempty_number(self):
        # ret_val = 0 (BINARY_INTEGER) must encode as a non-empty NUMBER, else the
        # client reads it as NULL and rejects the metadata call (DPY-2035).
        from seerdb.common.tns import _encode_out_bind_value
        from seerdb.common.tns_consts import TNS_TYPE_INT

        wire = _encode_out_bind_value(0, TNS_TYPE_INT)
        self.assertEqual(wire, bytes([1, 0x80]))  # DALC len 1 + NUMBER 0
        self.assertNotEqual(wire, bytes([0]))  # not the empty (NULL) DALC

    def test_refcursor_out_bind_trailer_keeps_following_bind_in_sync(self):
        # A REF CURSOR OUT bind in the middle of the IOV must be followed by a
        # return code (a single 0x00), not a 0x01 present marker: the reference
        # client reads a ub4 return code after the cursor value, so a 0x01 there
        # is a length-1 integer that swallows the next bind's first byte.
        from seerdb.client.cursor import cursor as RefCur
        from seerdb.common.tns import (
            ColumnMeta,
            RefCursorOutBind,
            ScalarOutBind,
            _read_iov,
            encode_out_bind_response_thin,
        )
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER as _NUM
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR as _VC

        columns = [ColumnMeta(name=b'N', data_type=_NUM, data_length=22, max_size=0)]
        reply = encode_out_bind_response_thin(
            [
                RefCursorOutBind(columns=columns, cursor_id=7),
                ScalarOutBind(value='tail', tns_type=_VC),
            ]
        )
        # Re-read the reply: the second bind must decode as 'tail', proving the
        # REF CURSOR trailer did not steal a byte.
        directions, out_values, _ = _read_iov(reply, [RefCur(), None])
        self.assertEqual(directions, [48, 48])
        self.assertTrue(out_values[0].get('_refcursor'))
        self.assertEqual(out_values[0]['cursor_id'], 7)
        self.assertEqual(out_values[1], b'tail')

    def test_zero_describe_length_column_sends_no_row_bytes(self):
        # A plain-scalar column the describe sizes at zero carries no row bytes
        # (the client reads it as NULL-by-describe); a LOB / LONG keeps its value.
        from seerdb.common.tns import ColumnMeta, _thin_column_value
        from seerdb.common.tns_consts import (
            TNS_TYPE_BLOB,
            TNS_TYPE_LONG,
            TNS_TYPE_VARCHAR,
        )

        null_col = ColumnMeta(
            name=b'X', data_type=TNS_TYPE_VARCHAR, data_length=0, max_size=0
        )
        self.assertEqual(_thin_column_value(None, null_col), b'')
        # LONG keeps a zero describe length yet carries data, so it is NOT skipped.
        long_col = ColumnMeta(
            name=b'L', data_type=TNS_TYPE_LONG, data_length=0, max_size=0
        )
        self.assertNotEqual(_thin_column_value('data', long_col), b'')
        # A BLOB (LOB-class) likewise carries its locator despite the zero length.
        blob_col = ColumnMeta(
            name=b'B', data_type=TNS_TYPE_BLOB, data_length=0, max_size=0
        )
        self.assertNotEqual(_thin_column_value(b'x', blob_col), b'')


class TestVar(unittest.TestCase):
    def test_var_python_type(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

        self.assertEqual(Var(int).dbtype.tns_type, TNS_TYPE_NUMBER)
        self.assertEqual(Var(str).dbtype.tns_type, TNS_TYPE_VARCHAR)

    def test_var_type_constant(self):
        from seerdb.common.datatypes import NUMBER, STRING, Var
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

        self.assertEqual(Var(NUMBER).dbtype.tns_type, TNS_TYPE_NUMBER)
        self.assertEqual(Var(STRING).dbtype.tns_type, TNS_TYPE_VARCHAR)

    def test_var_size_default_and_override(self):
        from seerdb.common.datatypes import Var

        self.assertEqual(Var(int).size, 22)
        self.assertEqual(Var(str).size, 32767)
        self.assertEqual(Var(str, 100).size, 100)

    def test_a_longer_value_grows_the_var_to_its_bytes(self):
        # The size is the bind's announced maximum length, which the server
        # holds the value to (ORA-01461, #2564). It never shrinks.
        from seerdb.common.datatypes import (
            DB_TYPE_LONG,
            DB_TYPE_NVARCHAR,
            DB_TYPE_RAW,
            Var,
        )

        cases = [
            (Var(str, 10), 'é' * 10, 20),  # UTF-8 bytes, not characters
            (Var(str, 10), 'abc', 10),
            (Var(DB_TYPE_NVARCHAR, 4), 'abc', 6),  # UTF-16
            (Var(DB_TYPE_RAW, 2), b'\x00' * 9, 9),
            (Var(DB_TYPE_LONG), 'x' * 40000, 40000),
            (Var(int), 10**30, 22),
        ]
        for var, value, size in cases:
            with self.subTest(var=var):
                var.setvalue(0, value)
                self.assertEqual(var.size, size)
        array = Var(str, 2, is_array=True, num_elements=3)
        array.setvalue(0, ['a', 'bbbbb', 'cc'])
        self.assertEqual(array.size, 5)

    def test_an_array_dmls_oac_is_sized_from_its_largest_declared_row(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import _oac_rep_row

        rows = []
        for text in ('a', 'b' * 150, 'c' * 20):
            var = Var(str, 10)
            var.setvalue(0, text)
            rows.append([1, var])
        self.assertEqual(_oac_rep_row(rows)[1].size, 150)

    def test_var_setget(self):
        from seerdb.common.datatypes import Var

        v = Var(int)
        self.assertIsNone(v.getvalue())
        self.assertFalse(v.has_value)
        v.setvalue(0, 5)
        self.assertEqual(v.getvalue(), 5)
        self.assertTrue(v.has_value)

    def test_var_oac_by_declared_type(self):
        # OAC type comes from the Var's type even when the value is NULL.
        from seerdb.common.datatypes import Var
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

        self.assertEqual(encode_token_oac(Var(int))[0], TNS_TYPE_NUMBER)
        self.assertEqual(encode_token_oac(Var(str))[0], TNS_TYPE_VARCHAR)

    def test_var_rxd_null_when_unseeded(self):
        from seerdb.common.datatypes import Var

        self.assertEqual(encode_token_rxd(Var(int)), bytes([0]))

    def test_var_rxd_seeded_value(self):
        from seerdb.common.datatypes import Var

        v = Var(int)
        v.setvalue(0, 5)
        self.assertEqual(encode_token_rxd(v), encode_token_rxd(5))


class TestIov(unittest.TestCase):
    # TTI_IOV bodies captured from XE 11g. Common header is
    #   0b 05 01 <numreq> 00 01 01 00 00 00  then per-bind direction byte(s),
    # then (if any OUT bind) 07 (RXD) + per-OUT-value [DALC][indicator].
    # A trailing 0x08 (RPA) stands in for the tokens that follow.

    def test_in_only(self):
        # one IN bind (direction 32) -> no values, no RXD.
        wire = bytes(
            [0x0B, 0x05, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x20, 0x08]
        )
        directions, out_values, rest = _read_iov(wire)
        self.assertEqual(directions, [32])
        self.assertEqual(out_values, [])
        self.assertEqual(rest, b'\x08')

    def test_single_out(self):
        # one OUT bind (16) returning NUMBER 99 (c1 64).
        wire = bytes(
            [
                0x0B,
                0x05,
                0x01,
                0x01,
                0x00,
                0x01,
                0x01,
                0x00,
                0x00,
                0x00,
                0x10,
                0x07,
                0x02,
                0xC1,
                0x64,
                0x00,
                0x08,
            ]
        )
        directions, out_values, rest = _read_iov(wire)
        self.assertEqual(directions, [16])
        self.assertEqual(out_values, [b'\xc1\x64'])
        self.assertEqual(rest, b'\x08')

    def test_out_and_inout(self):
        # OUT NUMBER 10 (c1 0b) + IN OUT VARCHAR "hi!".
        wire = bytes(
            [
                0x0B,
                0x05,
                0x01,
                0x02,
                0x00,
                0x01,
                0x01,
                0x00,
                0x00,
                0x00,
                0x10,
                0x30,
                0x07,
                0x02,
                0xC1,
                0x0B,
                0x00,
                0x03,
                0x68,
                0x69,
                0x21,
                0x00,
                0x08,
            ]
        )
        directions, out_values, rest = _read_iov(wire)
        self.assertEqual(directions, [16, 48])
        self.assertEqual(out_values, [b'\xc1\x0b', b'hi!'])
        self.assertEqual(rest, b'\x08')

    # One IN OUT CLOB bind, captured from a live 23ai answering
    #
    #   declare t_Clob clob;
    #   begin
    #       t_Clob := :data;
    #       dbms_lob.copy(:data, t_Clob, 50000);
    #       dbms_lob.writeappend(:data, 5, 'BBBBB');
    #   end;
    #
    # The value is NOT a DALC: it is the LOB column framing (#978) --
    #   01 28        ub4 block length = 40
    #   02 c3 55     ub8 size         = 50005   (50000 + the 5 appended)
    #   02 1f c4     ub4 chunk size   = 8132
    #   28 <40B>     DALC locator
    #   00           per-value return code
    _LOB_LOCATOR = bytes.fromhex(
        '00260001820880030002 2a6500000 0d500000002 036900 0a0000000100'
        '001aab82f10000000100 00'.replace(' ', '')
    )
    _INOUT_LOB_IOV = (
        bytes.fromhex('0b05010100010100000030')
        + bytes.fromhex('07')
        + bytes.fromhex('0128')
        + bytes.fromhex('02c355')
        + bytes.fromhex('021fc4')
        + bytes([len(_LOB_LOCATOR)])
        + _LOB_LOCATOR
        + bytes.fromhex('00')
        + b'\x08'
    )

    def test_inout_lob_var(self):
        # A LOB-class Var bind: the value reads as a LOB carrying the updated
        # locator, and the stream is left on the token that follows. Read as a
        # DALC it took the 0x28 for the whole value and left the rest of the
        # block behind, whose first byte then decoded as "response token 2".
        from seerdb.common.datatypes import DB_TYPE_CLOB
        from seerdb.common.lob import LOB

        directions, out_values, rest = _read_iov(
            self._INOUT_LOB_IOV, [Var(DB_TYPE_CLOB)]
        )
        self.assertEqual(directions, [48])
        self.assertEqual(rest, b'\x08')
        self.assertEqual(len(out_values), 1)
        self.assertIsInstance(out_values[0], LOB)
        self.assertEqual(out_values[0].raw, self._LOB_LOCATOR)

    def test_inout_lob_temp_marker(self):
        # The same bind after the > 32767-byte promotion (#902) replaced the Var
        # with a temp-LOB marker: the marker types the response just as the Var
        # did, so the promoted bind is not read as a DALC either (#978).
        from seerdb.common.datatypes import TempLob
        from seerdb.common.lob import LOB

        _, out_values, rest = _read_iov(
            self._INOUT_LOB_IOV, [TempLob(b'\x00' * 40, False)]
        )
        self.assertEqual(rest, b'\x08')
        self.assertIsInstance(out_values[0], LOB)
        self.assertEqual(out_values[0].raw, self._LOB_LOCATOR)

    def test_out_lob_null(self):
        # A LOB OUT bind the block left NULL: a single 0x00 block, then the
        # return code. Nothing to build a LOB from.
        from seerdb.common.datatypes import DB_TYPE_BLOB

        wire = bytes.fromhex('0b0501010001010000001007') + b'\x00\x00' + b'\x08'
        _, out_values, rest = _read_iov(wire, [Var(DB_TYPE_BLOB)])
        self.assertEqual(out_values, [None])
        self.assertEqual(rest, b'\x08')


class TestBindDispatch(unittest.TestCase):
    # The RXD value bytes carry a 1-byte length prefix; the OAC descriptor
    # leads with the data-type code. Confirm each Python type dispatches to the
    # right wire type.

    def test_binary_float_dispatch(self):
        self.assertEqual(encode_token_rxd(BinaryFloat(1.5))[0], 4)
        self.assertEqual(encode_token_oac(BinaryFloat(1.5))[0], TNS_TYPE_BFLOAT)

    def test_binary_double_dispatch(self):
        self.assertEqual(encode_token_rxd(BinaryDouble(1.5))[0], 8)
        self.assertEqual(encode_token_oac(BinaryDouble(1.5))[0], TNS_TYPE_BDOUBLE)

    def test_timedelta_dispatch(self):
        TD = datetime.timedelta(days=1)
        self.assertEqual(encode_token_rxd(TD)[0], 11)
        self.assertEqual(encode_token_oac(TD)[0], TNS_TYPE_INTERVALDS)

    def test_intervalym_dispatch(self):
        self.assertEqual(encode_token_rxd(IntervalYM(1, 0))[0], 5)
        self.assertEqual(encode_token_oac(IntervalYM(1, 0))[0], TNS_TYPE_INTERVALYM)

    def test_nonfinite_plain_float_autoroutes_to_bdouble(self):
        # A plain float (no wrapper) that is inf/nan must bind as BINARY_DOUBLE
        # rather than crashing the base-100 NUMBER encoder.
        for V in (math.inf, -math.inf, math.nan):
            self.assertEqual(encode_token_rxd(V)[0], 8)
            self.assertEqual(encode_token_oac(V)[0], TNS_TYPE_BDOUBLE)

    def test_finite_plain_float_stays_number(self):
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER

        self.assertEqual(encode_token_oac(1.5)[0], TNS_TYPE_NUMBER)


class TestCharsetAwareDecode(unittest.TestCase):
    """String decode picks the charset by csfrm, not the column's DB charset
    (#174): the driver negotiates an AL32UTF8 session, so the server returns
    ordinary (csfrm 1) char data as UTF-8 regardless of the DB charset, and
    national (csfrm 2) data as AL16UTF16."""

    def test_csfrm1_decodes_as_utf8_not_db_charset(self):
        from seerdb.common.tns_consts import ISO_LATIN_1_CHARSET, TNS_TYPE_VARCHAR

        # A 9i column on a WE8ISO8859P1 (id 31) DB reports charset 31, but the
        # server sends the value in the AL32UTF8 session charset. 'é' = c3 a9
        # (UTF-8) must decode to 'é', not iso-8859-1 'Ã©'.
        Col = {
            'data_type': TNS_TYPE_VARCHAR,
            'charset': ISO_LATIN_1_CHARSET,
            'csfrm': 1,
        }
        self.assertEqual(decode_value(Col, b'caf\xc3\xa9'), 'café')

    def test_csfrm2_decodes_as_al16utf16(self):
        from seerdb.common.tns_consts import AL16UTF16_CHARSET, TNS_TYPE_VARCHAR

        # National (csfrm 2) data arrives as UTF-16BE. 'AÄ' = 0041 00c4.
        Col = {'data_type': TNS_TYPE_VARCHAR, 'charset': AL16UTF16_CHARSET, 'csfrm': 2}
        self.assertEqual(decode_value(Col, b'\x00A\x00\xc4'), 'AÄ')

    def test_missing_csfrm_falls_back_to_column_charset(self):
        from seerdb.common.tns_consts import ISO_LATIN_1_CHARSET, TNS_TYPE_VARCHAR

        # Decode paths that don't record csfrm keep the old column-charset
        # behaviour (no KeyError, no surprise re-interpretation).
        Col = {'data_type': TNS_TYPE_VARCHAR, 'charset': ISO_LATIN_1_CHARSET}
        self.assertEqual(decode_value(Col, b'caf\xe9'), 'café')


if __name__ == '__main__':
    unittest.main()


class TestMixedPrecisionBatch(unittest.TestCase):
    """One declared type per temporal column of an array bind (#1098).

    The type is chosen per value -- DATE without a sub-second part, TIMESTAMP
    with one -- but an array bind has a single OAC per column. A mixed batch
    was declared by one row and the server answered ORA-01483. Only the
    declaration widens: a whole-second row keeps the 7-byte form, which a
    TIMESTAMP descriptor takes (#1805).
    """

    PLAIN = datetime.datetime(2020, 2, 29)
    FRAC = datetime.datetime(2020, 2, 29, 23, 59, 59, 123456)

    def _widen(self, rows):
        from seerdb.common.tns import _widen_batch_datetimes

        return _widen_batch_datetimes(rows)

    def test_a_mixed_column_is_declared_timestamp(self):
        from seerdb.common.tns import encode_token_oac

        rows = self._widen([[1, self.PLAIN], [2, self.FRAC]])
        # The descriptor says TIMESTAMP for either row's value.
        self.assertEqual(
            {encode_token_oac(r[1]) for r in rows},
            {encode_token_oac(self.FRAC)},
        )

    def test_a_whole_second_row_keeps_the_7_byte_form(self):
        from seerdb.common.tns import encode_token_rxd

        rows = self._widen([[1, self.PLAIN], [2, self.FRAC]])
        # 1-byte length + 7 bytes, then 1 + the 11-byte TIMESTAMP form, as
        # python-oracledb sends a TIMESTAMP batch (#1805).
        self.assertEqual([len(encode_token_rxd(r[1])) for r in rows], [8, 12])

    def test_the_values_are_unchanged(self):
        rows = self._widen([[1, self.PLAIN], [2, self.FRAC]])
        self.assertEqual([r[1] for r in rows], [self.PLAIN, self.FRAC])

    def test_an_unmixed_column_is_left_alone(self):
        from seerdb.common.tns import encode_token_rxd

        for same in (
            [[1, self.PLAIN], [2, self.PLAIN]],
            [[1, self.FRAC], [2, self.FRAC]],
        ):
            rows = self._widen(same)
            self.assertEqual(rows, same)
            self.assertEqual(len({len(encode_token_rxd(r[1])) for r in rows}), 1)

    def test_an_aware_column_is_left_alone(self):
        # Widening an aware value would mean inventing a zone for the others.
        aware = self.PLAIN.replace(tzinfo=datetime.timezone.utc)
        rows = [[1, aware], [2, self.FRAC]]
        self.assertEqual(self._widen(rows), rows)

    def test_a_single_row_is_left_alone(self):
        rows = [[1, self.PLAIN]]
        self.assertEqual(self._widen(rows), rows)


class TestDeclaredTemporalBindWidth(unittest.TestCase):
    # A bind declared TIMESTAMP [WITH LOCAL TIME ZONE] goes out in the 7-byte DATE
    # form when it has no fractional seconds, and in the 11-byte form when it has
    # some, as python-oracledb sends it (#1337). DATE is always 7 bytes and WITH
    # TIME ZONE always 13.

    MIDNIGHT = datetime.datetime(2022, 6, 12)
    FRACTION = datetime.datetime(2022, 6, 12, 0, 0, 0, 500)

    def _width(self, value, data_type):
        from seerdb.common.tns import _declared_value_bytes

        encoded = _declared_value_bytes(value, data_type)
        assert encoded is not None
        return encoded[0]  # the one-byte length prefix

    def test_no_fraction_goes_out_as_a_date(self):
        for data_type in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ):
            self.assertEqual(self._width(self.MIDNIGHT, data_type), 7)

    def test_a_fraction_keeps_the_timestamp_form(self):
        for data_type in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ):
            self.assertEqual(self._width(self.FRACTION, data_type), 11)

    def test_date_and_time_zone_widths_are_unchanged(self):
        self.assertEqual(self._width(self.FRACTION, TNS_TYPE_DATE), 7)
        self.assertEqual(self._width(self.MIDNIGHT, TNS_TYPE_TIMESTAMPTZ), 13)
