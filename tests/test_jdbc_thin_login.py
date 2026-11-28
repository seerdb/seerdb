# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""JDBC thin 11.2 (ojdbc6) logging in to the Mirror (#2854).

ojdbc6 opens with a `deadbeef` ANO container, as sqlplus does, but stamped
with its release; it sends the DB session time-zone block in its DTY, as
sqlplus does, but a type table behind it too; and it reads on past each
reply to its status. The Mirror took it for sqlplus, then answered it short.
Checked against ojdbc6 11.2.0.3's login to 11.2.0.2, captured.
"""

from __future__ import annotations

import os
import struct

from seerdb.common.tns import (
    _ENCODE_FIELD_VERSION,
    _ENCODE_OER_SEQ,
    _SERVER_DTY_TABLE,
    encode_dty_reply_body,
    encode_result,
    encode_version_reply,
)
from seerdb.common.tns_consts import (
    CCAP_UB2_DTY,
    FIELD_VERSION_11_2,
    RCAP_TZ,
    TTI_OER,
    VERSION_11_2_0_2,
)
from seerdb.server.handshake import (
    build_dty_type_reply,
    is_ano_negotiation,
    opens_with_oci_ano,
)
from seerdb.server.identity import IDENTITY_11_2
from tests.replay import parse_hexdump

_CAPTURES = os.path.join(os.path.dirname(__file__), 'captures')


def _capture(name: str) -> bytes:
    with open(os.path.join(_CAPTURES, name)) as f:
        return parse_hexdump(f.read())


def _ub2_table_end(reply: bytes, start: int) -> int:
    # Walk a DTY reply's table in UB2 entries -- type, conversion, representation
    # and flags -- to its UB2 zero; return the offset just past it.
    offset = start
    while True:
        (data_type,) = struct.unpack_from('>H', reply, offset)
        if data_type == 0:
            return offset + 2
        (conversion,) = struct.unpack_from('>H', reply, offset + 2)
        offset += 4 if conversion == 0 else 8


def test_ojdbc6s_ano_is_a_thin_clients() -> None:
    # Its container is stamped 10.2, where sqlplus's is stamped zero and
    # python-oracledb's 11.2.0.2: a thin client's ANO, negotiated as such. Taken
    # for sqlplus's, it got sqlplus's type reply and hung.
    ano = _capture('jdbc6_ano_request_11g.hexdump')
    assert ano[6:10] == bytes.fromhex('0a200000')
    assert is_ano_negotiation(ano)
    assert not opens_with_oci_ano(ano)
    sqlplus = ano[:6] + bytes(4) + ano[10:]
    assert opens_with_oci_ano(sqlplus)
    assert not is_ano_negotiation(sqlplus)
    oracledb = ano[:6] + bytes.fromhex('0b200200') + ano[10:]
    assert is_ano_negotiation(oracledb)
    assert not opens_with_oci_ano(oracledb)


def test_the_dty_reply_is_11gs_form_for_ojdbc6() -> None:
    # ojdbc6 sets RCAP_TZ and CCAP_UB2_DTY at field version 11.2: 11.2.0.2
    # answers it with its time-zone block and timezone-file version, then the
    # table in UB2 entries. The Mirror's table is its own, but the frame is
    # 11.2.0.2's: the same 16 bytes ahead of the table, and a UB2 table that
    # ends the reply.
    request = _capture('jdbc6_dty_request_11g.hexdump')
    real = _capture('jdbc6_dty_reply_11g.hexdump')
    assert _ub2_table_end(real, 16) == len(real)
    reply = build_dty_type_reply(FIELD_VERSION_11_2, request)
    assert reply[:16] == real[:16]
    assert _ub2_table_end(reply, 16) == len(reply)


def test_a_dty_without_them_keeps_the_11g_reply() -> None:
    # A thin client that sets neither -- seerdb's own and python-oracledb's
    # below 12.1 -- gets the narrow 11g table, as before.
    request = bytearray(_capture('jdbc6_dty_request_11g.hexdump'))
    compile_length = request[6]
    request[7 + CCAP_UB2_DTY] = 0
    request[7 + compile_length + 1 + RCAP_TZ] = 0
    reply = build_dty_type_reply(FIELD_VERSION_11_2, bytes(request))
    assert reply == encode_dty_reply_body(_SERVER_DTY_TABLE)


def test_the_version_call_is_answered_as_11_2_0_2_answers_it() -> None:
    # ojdbc6 asks for the server's release once after its login (03 3b), and
    # the Mirror refused the call (ORA-03115), which closed the connection.
    real = _capture('jdbc6_version_reply_11g.hexdump')
    token = _ENCODE_OER_SEQ.set(3)  # the capture's end-to-end sequence
    try:
        reply = encode_version_reply(IDENTITY_11_2.banner, VERSION_11_2_0_2)
    finally:
        _ENCODE_OER_SEQ.reset(token)
    assert reply == real


def test_the_auth_result_below_12_1_ends_in_a_status() -> None:
    # 11.2.0.2 closes its auth result with a status, and ojdbc6 waits for it;
    # its proof is the 48-byte padded one (96 hex characters).
    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        result = encode_result(bytes(24))
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    assert bytes([TTI_OER]) in result[-40:]
    assert b'AUTH_SVR_RESPONSE\x01\x60\x60' in result
