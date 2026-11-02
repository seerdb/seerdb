# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The per-session feature table (#2395): one verdict per feature, per band."""

from __future__ import annotations

import pytest

from seerdb.common.features import Carry, Features, session_features
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_18_1_EXT_1,
    FIELD_VERSION_23_4,
)

BANDS = {
    '10.2': FIELD_VERSION_10_2,
    '11.2': FIELD_VERSION_11_2,
    '12.1': FIELD_VERSION_12_1,
    '12.2-19c': FIELD_VERSION_18_1_EXT_1,
    '23ai': FIELD_VERSION_23_4,
}

# What each feature is carried as, per band; each change that maps or refuses
# one edits its row here.
MAPPED_BELOW_23AI = {band: Carry.MAPPED for band in BANDS} | {'23ai': Carry.NATIVE}
EXPECTED = {
    # 23ai sends a BOOLEAN as a NUMBER below field version 17 (#2416).
    'boolean': MAPPED_BELOW_23AI,
    # And a JSON column as a BLOB of its text below field version 14 (#2417).
    'json': MAPPED_BELOW_23AI,
    # And a VECTOR as a CLOB of its text below field version 7 (#2418).
    'vector': dict.fromkeys(BANDS, Carry.NATIVE)
    | {'10.2': Carry.MAPPED, '11.2': Carry.MAPPED},
    # And refuses an implicit result below field version 7 (#2419).
    'implicit_results': dict.fromkeys(BANDS, Carry.NATIVE)
    | {'10.2': Carry.REFUSED, '11.2': Carry.REFUSED},
}


@pytest.mark.parametrize('oci', [False, True], ids=['thin', 'sqlplus'])
@pytest.mark.parametrize('band', BANDS)
@pytest.mark.parametrize('feature', EXPECTED)
def test_each_feature_has_one_verdict_per_band(
    feature: str, band: str, oci: bool
) -> None:
    table = session_features(BANDS[band], oci=oci, client_field_version=BANDS[band])
    assert getattr(table, feature) is EXPECTED[feature][band]


def test_a_session_that_never_logged_in_gets_the_newest_forms() -> None:
    # The codec's defaults: what a direct call into an encoder sees.
    assert Features() == Features(
        oci_lob_12c=False, oci_tstz_local=True, oci_full_release=True
    )
    assert all(getattr(Features(), feature) is Carry.NATIVE for feature in EXPECTED)


def test_a_thin_session_takes_no_sqlplus_forms() -> None:
    # The sqlplus cell and release choices come from a sqlplus's capability
    # block; a thin session keeps the defaults whatever it is told.
    table = session_features(
        FIELD_VERSION_11_2, client_field_version=FIELD_VERSION_11_2, lob_12c=True
    )
    default = Features()
    assert (table.oci_lob_12c, table.oci_tstz_local, table.oci_full_release) == (
        default.oci_lob_12c,
        default.oci_tstz_local,
        default.oci_full_release,
    )


@pytest.mark.parametrize(
    ('client', 'boolean'),
    [
        (FIELD_VERSION_11_2, Carry.MAPPED),
        (27, Carry.NATIVE),  # sqlplus 23.26
        (None, Carry.NATIVE),  # a block that can't be read keeps the newer forms
    ],
)
def test_a_sqlplus_gets_the_23ai_types_by_its_own_version(
    client: int | None, boolean: Carry
) -> None:
    # The Mirror speaks 12.1's dialect to every sqlplus from 12.1 on, so the
    # session's version says nothing about the types: 23ai sends sqlplus 23.26
    # a native BOOLEAN and sqlplus 11.2 a NUMBER (#2416), and JSON likewise
    # (#2417).
    table = session_features(
        FIELD_VERSION_18_1_EXT_1, oci=True, client_field_version=client
    )
    assert table.boolean is boolean
    assert table.json is boolean


@pytest.mark.parametrize(
    ('client', 'json'),
    [(13, Carry.MAPPED), (14, Carry.NATIVE), (16, Carry.NATIVE)],
)
def test_json_is_native_from_field_version_14(client: int, json: Carry) -> None:
    # 23ai sends a JSON column as a BLOB to a client at field version 13 and
    # as JSON from 14 (20.1), measured; BOOLEAN only from 17.
    assert session_features(client).json is json
    assert session_features(client).boolean is Carry.MAPPED


@pytest.mark.parametrize(
    ('client', 'tstz_local', 'full_release'),
    [
        (FIELD_VERSION_10_2, False, False),
        (FIELD_VERSION_11_2, False, False),
        (FIELD_VERSION_12_1, True, False),
        (FIELD_VERSION_18_1_EXT_1, True, True),
        (None, True, True),  # a block that can't be read keeps the newer forms
    ],
)
def test_a_sqlplus_reads_the_forms_its_own_version_names(
    client: int | None, tstz_local: bool, full_release: bool
) -> None:
    table = session_features(FIELD_VERSION_11_2, oci=True, client_field_version=client)
    assert (table.oci_tstz_local, table.oci_full_release) == (tstz_local, full_release)
