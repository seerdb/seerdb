# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""The messages the Mirror's session writes and reads through common's schemas
(#2773): the TNS markers, the pipeline-end status and the BFILE locator field."""

from seerdb.common.tns import (
    _LOB_LOCATOR_REPLY_FROM_THIN,
    decode_marker_type,
    encode_lob_locator_field,
    encode_marker_body,
    encode_pipeline_end_status_thin,
    is_prefixed_locator,
)
from seerdb.common.tns_consts import (
    TNS_MARKER_TYPE_BREAK,
    TNS_MARKER_TYPE_INTERRUPT,
    TNS_MARKER_TYPE_RESET,
    TTI_RPA,
)


def test_markers_are_the_bodies_a_live_server_exchanges() -> None:
    # Captured from 23ai: a client's interrupt and reset, the server's reset.
    assert encode_marker_body(TNS_MARKER_TYPE_INTERRUPT) == bytes.fromhex('010003')
    assert encode_marker_body(TNS_MARKER_TYPE_RESET) == bytes.fromhex('010002')
    assert encode_marker_body(TNS_MARKER_TYPE_BREAK) == bytes.fromhex('010001')


def test_a_marker_s_type_reads_back() -> None:
    for marker_type in (
        TNS_MARKER_TYPE_BREAK,
        TNS_MARKER_TYPE_RESET,
        TNS_MARKER_TYPE_INTERRUPT,
    ):
        assert decode_marker_type(encode_marker_body(marker_type)) == marker_type
    # A body too short to carry a type carries none.
    for short in (b'', b'\x01', b'\x01\x00'):
        assert decode_marker_type(short) == 0


def test_the_pipeline_end_status_is_a_live_23ai_s() -> None:
    assert encode_pipeline_end_status_thin() == bytes.fromhex('09010100')


def test_a_locator_field_is_the_locator_behind_its_length() -> None:
    locator = bytes(range(40))
    field = encode_lob_locator_field(locator)
    assert field == b'\x00\x28' + locator
    assert is_prefixed_locator(field)
    # A LOBOPS reply's head is the RPA token and the same field.
    (values, rest) = _LOB_LOCATOR_REPLY_FROM_THIN(bytes([TTI_RPA]) + field + b'\x08')
    assert values['locator'] == locator
    assert rest == b'\x08'
