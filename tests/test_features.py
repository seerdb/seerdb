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

# What each feature is carried as, per band. Today every one goes out native
# at every band; each change that maps or refuses one edits its row here.
EXPECTED = {
    'boolean': dict.fromkeys(BANDS, Carry.NATIVE),
    'json': dict.fromkeys(BANDS, Carry.NATIVE),
    'vector': dict.fromkeys(BANDS, Carry.NATIVE),
    'implicit_results': dict.fromkeys(BANDS, Carry.NATIVE),
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
    assert table == Features()


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
