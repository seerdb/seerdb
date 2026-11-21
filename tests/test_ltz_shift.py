# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""TIMESTAMP WITH LOCAL TIME ZONE as OCI hands it out (#2762).

An LTZ value arrives as the wall clock in DBTIMEZONE; OCI 23.26 returns it as the
session's wall clock, fetched or OUT, a region's DST following the date.
Measured 2026-11-21 on 23ai at session Europe/Berlin, DBTIMEZONE +00:00.
"""

import datetime

from seerdb.client._conn_logic import _ConnectionLogic, _zone_tzinfo
from seerdb.common.dbobject import DbObject
from seerdb.common.tns import _encode_temporal
from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ
from seerdb.common.types import DbZoneDatetime, decode_value

_JULY = DbZoneDatetime(2024, 7, 1, 10, 0, 0, 250000)
_JANUARY = DbZoneDatetime(2024, 1, 15, 10, 0)


def _session(database: str, session: str, shift: bool = True) -> _ConnectionLogic:
    conn = _ConnectionLogic()
    conn._ltz_shift = shift
    conn._ltz_set_zones([(database, session)])
    return conn


def test_an_ltz_cell_decodes_marked_and_a_timestamp_does_not():
    wire = _encode_temporal(
        datetime.datetime(2024, 7, 1, 10, 0, 0, 250000), TNS_TYPE_TIMESTAMPLTZ
    )
    ltz = decode_value({'data_type': TNS_TYPE_TIMESTAMPLTZ}, wire)
    plain = decode_value({'data_type': TNS_TYPE_TIMESTAMP}, wire)
    assert type(ltz) is DbZoneDatetime
    assert type(plain) is datetime.datetime
    assert ltz == plain


def test_a_region_s_dst_follows_the_date():
    conn = _session('+00:00', 'Europe/Berlin')
    assert conn._ltz_value([_JULY, _JANUARY, None, 7]) == [
        datetime.datetime(2024, 7, 1, 12, 0, 0, 250000),
        datetime.datetime(2024, 1, 15, 11, 0),
        None,
        7,
    ]
    assert type(conn._ltz_value(_JULY)) is datetime.datetime


def test_offsets_on_both_sides():
    # 9.2's database at -08:00, a session at +01:00: nine hours apart.
    conn = _session('-08:00', '+01:00')
    assert conn._ltz_value((_JULY,)) == (
        datetime.datetime(2024, 7, 1, 19, 0, 0, 250000),
    )


def test_9_2_s_trailing_space_and_any_case_are_read():
    assert _zone_tzinfo('Europe/London ') == _zone_tzinfo('Europe/London')
    assert _zone_tzinfo('EUROPE/LONDON') is not None
    assert _zone_tzinfo('-05:30').utcoffset(None) == datetime.timedelta(
        hours=-5, minutes=-30
    )
    assert _zone_tzinfo('Nowhere/X') is None
    assert _zone_tzinfo(None) is None


def test_an_unknown_zone_leaves_the_value_unshifted():
    conn = _session('+00:00', 'Nowhere/X')
    assert conn._ltz_value(_JULY) == datetime.datetime(2024, 7, 1, 10, 0, 0, 250000)


def test_shifting_off_relays_the_value_as_it_arrived():
    # The passthrough Mirror's upstream sessions: the Mirror's client shifts.
    conn = _session('+00:00', 'Europe/Berlin', shift=False)
    value = conn._ltz_value(_JULY)
    assert value == datetime.datetime(2024, 7, 1, 10, 0, 0, 250000)
    assert type(value) is datetime.datetime


def test_an_object_s_attribute_and_a_collection_s_element_are_shifted():
    conn = _session('+00:00', 'Europe/Berlin')
    obj = DbObject('T', [('ID', 1), ('TS', _JULY)])
    tab = DbObject('TAB', elements=[_JULY, None])
    nested = DbObject('OUTER', [('INNER', DbObject('T', [('TS', _JANUARY)]))])
    assert conn._ltz_present([obj]) and conn._ltz_present(tab)
    conn._ltz_value([obj, tab, nested])
    assert obj.TS == datetime.datetime(2024, 7, 1, 12, 0, 0, 250000)
    assert tab.aslist() == [datetime.datetime(2024, 7, 1, 12, 0, 0, 250000), None]
    assert nested.INNER.TS == datetime.datetime(2024, 1, 15, 11, 0)
    assert not conn._ltz_present([obj, tab, nested])


def test_an_alter_session_of_the_zone_has_the_zones_read_again():
    conn = _session('+00:00', 'Europe/Berlin')
    conn._ltz_note_statement('SELECT 1 FROM dual')
    assert not conn._ltz_needs_zones()
    conn._ltz_note_statement("alter session set time_zone = '-05:00'")
    assert conn._ltz_needs_zones()


def test_a_shift_past_the_calendar_s_end_keeps_the_value():
    conn = _session('+00:00', '+05:00')
    last = DbZoneDatetime(9999, 12, 31, 23, 0)
    assert conn._ltz_value(last) == datetime.datetime(9999, 12, 31, 23, 0)
