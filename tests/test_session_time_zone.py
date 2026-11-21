# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The session time zone a login sets from ``ORA_SDTZ`` (#2760).

Each expectation is what OCI 23.26 (thick python-oracledb) sent to 23ai as
``AUTH_ALTER_SESSION``, measured 2026-11-21 with the OS zone at Asia/Kolkata.
"""

from unittest import mock

import pytest

from seerdb.common import tns
from seerdb.common.tns import _local_tz_clause, _session_time_zone

_OS = "'+05:30'"


@pytest.fixture(autouse=True)
def _os_zone_is_kolkata(monkeypatch):
    monkeypatch.setattr(tns, '_os_offset', lambda: _OS)


@pytest.mark.parametrize(
    ('value', 'sent'),
    [
        # Offsets go as written, sign optional, from -15:59 to +15:00.
        ('+5:00', "'+5:00'"),
        ('5:00', "'5:00'"),
        ('-0:30', "'-0:30'"),
        ('+15:00', "'+15:00'"),
        ('+14:00', "'+14:00'"),
        ('-12:00', "'-12:00'"),
        ('-15:00', "'-15:00'"),
        ('-15:59', "'-15:59'"),
        # Regions go as written, checked in any case, after trimming.
        ('Europe/Moscow', "'Europe/Moscow'"),
        ('europe/moscow', "'europe/moscow'"),
        (' Europe/Moscow', "'Europe/Moscow'"),
        ('UTC', "'UTC'"),
        ('utc', "'utc'"),
        ('EST', "'EST'"),
        # The database's zone: OCI sends it as a number; this client names it.
        ('DB_TZ', 'DBTIMEZONE'),
        ('db_tz', 'DBTIMEZONE'),
        # Everything else is the OS offset.
        (None, _OS),
        ('', _OS),
        ('OS_TZ', _OS),
        ('os_tz', _OS),
        ('Os_Tz', _OS),
        ('LOCAL', _OS),
        ('Nowhere/X', _OS),
        ('+16:00', _OS),
        ('+15:59', _OS),
        ('-16:00', _OS),
        ('+24:00', _OS),
        ('+05:61', _OS),
        ('+00:60', _OS),
        ('+5', _OS),
        ('05:00:00', _OS),
        ("Europe/Moscow'", _OS),
    ],
)
def test_ora_sdtz_is_sent_as_oci_sends_it(value, sent):
    assert _session_time_zone(value) == sent


def test_the_login_clause_reads_ora_sdtz():
    with mock.patch.dict('os.environ', {'ORA_SDTZ': 'Europe/Moscow'}):
        assert _local_tz_clause() == b"ALTER SESSION SET TIME_ZONE='Europe/Moscow'\x00"
    with mock.patch.dict('os.environ', {'ORA_SDTZ': 'DB_TZ'}):
        assert _local_tz_clause() == b'ALTER SESSION SET TIME_ZONE=DBTIMEZONE\x00'


def test_without_ora_sdtz_the_login_sends_the_os_offset():
    with mock.patch.dict('os.environ', clear=False) as env:
        env.pop('ORA_SDTZ', None)
        assert _local_tz_clause() == f'ALTER SESSION SET TIME_ZONE={_OS}\x00'.encode()
