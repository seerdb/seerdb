# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The handshake messages both sides speak, through one schema each (#2773):
what one side writes, the other reads back, and a capture reads and writes
back to its own bytes."""

from __future__ import annotations

import handshake_11g as fx

from seerdb.common import tns
from seerdb.common.tns import (
    capability_arrays,
    decode_connect_head,
    decode_dty_request_head,
    decode_token_pro,
    encode_dictionary_dty,
    encode_dictionary_login,
    encode_oci_dty_tz_reply,
    encode_refuse_body,
    encode_token_pro,
)
from seerdb.common.tns_consts import AL32UTF8_CHARSET
from seerdb.server import handshake as h

_ENV = {
    'host': 'h',
    'port': 1,
    'user': 'u',
    'password': 'p',
    'sid': 'XE',
    'app_name': 'a',
}


def test_the_mirror_reads_the_connect_the_client_writes() -> None:
    body = encode_dictionary_login({'type': 0, 'env': _ENV, 'sdu': 8192})
    head = decode_connect_head(body)
    assert (head['version'], head['lowest_version'], head['options']) == (
        319,
        300,
        0x0401,
    )
    assert (head['sdu16'], head['tdu16'], head['byte_order']) == (8192, 8192, 1)
    assert head['data_offset'] == 74
    assert head['data_length'] == len(body) - 66
    (rest, descriptor) = tns._CONNECT_REST_FROM_THIN(body[20:])
    assert (rest['sdu'], rest['tdu'], rest['flags0'], rest['flags1']) == (
        8192,
        8192,
        1,
        1,
    )
    assert (rest['connect_flags1'], rest['connect_flags2']) == (0, 1)
    assert descriptor.startswith(b'(DESCRIPTION=')
    request = h.parse_connect(body)
    assert (request.protocol_version, request.sdu) == (319, 8192)


def test_a_captured_connect_head_writes_back_to_its_bytes() -> None:
    # sqlplus 11.2's CONNECT (tests/handshake_11g.py).
    body = fx.CONNECT[8:]
    head = decode_connect_head(body)
    assert tns._CONNECT_HEAD_THIN(head) == body[:20]
    assert body[head['data_offset'] - 8 :].startswith(b'(DESCRIPTION=')


def test_a_refuse_reads_back() -> None:
    text = b'(DESCRIPTION=(ERR=12514))'
    body = encode_refuse_body(0x22, 0, text)
    assert body == b'\x22\x00' + len(text).to_bytes(2, 'big') + text
    assert tns._REFUSE_FROM_THIN(body)[0]['data'] == text


def test_the_client_reads_the_pro_reply_the_mirror_writes() -> None:
    for oci in (False, True):
        reply = h.build_caps_block_reply(12, oci=oci)
        pro = decode_token_pro(reply)
        assert pro['charset_id'] == AL32UTF8_CHARSET
        assert pro['banner'] == b'x86_64/Linux 2.4.xx'
        (fields, rest) = tns._PRO_FROM_THIN(reply)
        assert rest == b''
        again = encode_token_pro(
            fields['server_version'],
            fields['banner'],
            fields['charset_id'],
            fields['server_flags'],
            b''.join(e['element'] for e in fields['charset_elements']),
            fields['fdo'],
            fields['compile_caps'],
            fields['runtime_caps'],
        )
        assert again == reply


def test_the_captured_pro_reply_writes_back_to_its_bytes() -> None:
    # 11g's own PRO reply, behind its 10-byte DATA header.
    reply = fx.PRO_SERVER[10:]
    (fields, rest) = tns._PRO_FROM_THIN(reply)
    again = encode_token_pro(
        fields['server_version'],
        fields['banner'],
        fields['charset_id'],
        fields['server_flags'],
        b''.join(e['element'] for e in fields['charset_elements']),
        fields['fdo'],
        fields['compile_caps'],
        fields['runtime_caps'],
    )
    assert again + rest == reply


def test_the_mirror_reads_the_dty_head_the_client_writes() -> None:
    for fv in (6, 12, 24):
        (compile_caps, runtime_caps) = capability_arrays(fv)
        dty = encode_dictionary_dty({'type': 0, 'field_version': fv, 'req': 'AL32UTF8'})
        head = decode_dty_request_head(dty)
        assert head is not None
        assert head[0]['compile_caps'] == compile_caps
        assert head[0]['runtime_caps'] == runtime_caps
        assert head[0]['charset'] == head[0]['ncharset'] == AL32UTF8_CHARSET
        assert h.client_field_version(dty) == fv


def test_a_dty_cut_before_its_runtime_caps_keeps_its_compile_caps() -> None:
    dty = encode_dictionary_dty({'type': 0, 'field_version': 12, 'req': 'AL32UTF8'})
    cut = dty[: 7 + dty[6]]
    head = decode_dty_request_head(cut)
    assert head is not None
    assert 'runtime_caps' not in head[0]
    assert h.client_field_version(cut) == 12
    # Unreadable as sqlplus's request, so the 11.2 form of the reply.
    assert h.client_sends_tz_file_version(cut) is True
    assert decode_dty_request_head(b'\x01' + dty[1:]) is None


def test_the_oci_type_reply_with_and_without_the_tz_file_version() -> None:
    assert encode_oci_dty_tz_reply(0, 0, 0, 14) == bytes.fromhex(
        '02800000003c3c3c800000000000000e'
    )
    assert encode_oci_dty_tz_reply(1, -30, 0, None) == bytes.fromhex(
        '02800000003d1e3c80000000'
    )
