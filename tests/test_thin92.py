# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""9.2 over thin OALL8 (#2768): ojdbc6 11.2's caps, then 10g's thin path.

9.2 answers that path in 10g's forms without what 10.1 added. The replies here
are 9.2.0.4's to seerdb itself, captured 2026-11-21: the status without its
end-to-end sequence, the describe column without its position, the describe
without its trailing flags, the return parameters without the registration.
Each is decoded as the session does, at field version 10.2 against a server
that advertised 9.2's.
"""

import datetime

from seerdb.common.tns import (
    _DECODE_CALL_STATUS,
    _THIN92_COMPILE_CAPS,
    DictionaryType,
    capability_arrays,
    decode_packet,
    encode_dictionary_exec,
)
from seerdb.common.tns_consts import (
    CCAP_FIELD_VERSION,
    FIELD_VERSION_9_2,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
)

# SELECT CAST(7 AS NUMBER(5,2)) AAA, CAST('ab' AS VARCHAR2(10)) BB, SYSDATE C,
# CAST('q' AS CHAR(3)) DDDD FROM dual: the describe, the row, ORA-01403.
_QUERY = bytes.fromhex(
    '101d18bbc39fb00a785d000000000000787e0b15172421d42d070002000000012a01044b02'
    '0000000116000000000000000103010303414141000001800000010a00000000011f01010a'
    '0102010202424200000c000000010100000000000000010101010143000060800000010300'
    '000000011f0101030104010404444444440000010707787e0b151724210602010400016400'
    '00000702c10802616207787e0b1517242103712020040101010102057b00000101016c0300'
    '0120000000000000000000000700010100000000194f52412d30313430333a206e6f206461'
    '746120666f756e640a'
)
# INSERT INTO t VALUES (5): the return parameters, then the status with the
# transaction bit and the row's rowid.
_INSERT = bytes.fromhex(
    '0801050402c7520d000103010100000004010201010000000103010c0200000000000306d0'
    '8f01010002b8da00000009000101010d0d010006d08f00010000b8da0000000000'
)
# COMMIT's reply: the call status, READONLY + ENDED, and no sequence.
_COMMIT = bytes.fromhex('090105')


def _decode(data: bytes) -> tuple[tuple, list]:
    status: list = []
    token = _DECODE_CALL_STATUS.set(status)
    try:
        return (
            decode_packet(
                data, (None, None, []), FIELD_VERSION_10_2, FIELD_VERSION_9_2
            ),
            status,
        )
    finally:
        _DECODE_CALL_STATUS.reset(token)


def test_a_query_reads_its_describe_and_its_row():
    (out, status) = _decode(_QUERY)
    columns = out[3][1]
    assert [(c['column_name'], c['data_type']) for c in columns] == [
        (b'AAA', 2),
        (b'BB', 1),
        (b'C', 12),
        (b'DDDD', 96),
    ]
    assert [c['charset'] for c in columns] == [0, 31, 0, 31]
    (row,) = out[4]
    assert row[:2] == [7, 'ab'] and row[3] == 'q  '
    assert isinstance(row[2], datetime.datetime)
    assert status == [1, 1403]


def test_a_dml_reply_reads_its_status_and_rowid():
    (out, status) = _decode(_INSERT)
    assert out[1] == 0  # no error
    assert out[6] == 'AABtCPAABAAALjaAAA'
    # Call status 2: a transaction is open.
    assert status == [2, 0]


def test_a_commit_s_status_has_no_sequence():
    (_, status) = _decode(_COMMIT)
    assert status == [5, 0]


def test_the_same_bytes_read_as_10g_s_do_not_parse():
    # The 9.2 forms are taken only for a 9.2 server: read at 10g's, the COMMIT
    # status runs short where the sequence would be, and keeps no status.
    status: list = []
    token = _DECODE_CALL_STATUS.set(status)
    try:
        decode_packet(_COMMIT, (None, None, []), FIELD_VERSION_10_2, FIELD_VERSION_10_2)
    finally:
        _DECODE_CALL_STATUS.reset(token)
    assert status == []


def test_the_caps_are_ojdbc6_s_to_9_2():
    # 11.2's, except LOGON_TYPES 0 and the last two compile bytes.
    (compile_caps, _) = capability_arrays(FIELD_VERSION_11_2)
    differ = [
        i for i, (a, b) in enumerate(zip(compile_caps, _THIN92_COMPILE_CAPS)) if a != b
    ]
    assert len(_THIN92_COMPILE_CAPS) == len(compile_caps) == 38
    assert differ == [4, 36, 37]
    assert _THIN92_COMPILE_CAPS[CCAP_FIELD_VERSION] == FIELD_VERSION_11_2


def test_the_execute_goes_from_the_define_count_to_the_sql():
    # 10g's OALL8 has `00 00 01` and a server-version field before the SQL; 9.2
    # answers that ORA-03120, and ojdbc6 sends neither.
    query = {
        'type': 'select',
        'auto': 1,
        'fetch': 15,
        'server_version': 11,
        'cursor': 0,
        'query': "SELECT 'x' FROM dual",
        'bind': [],
        'batch': [],
        'def': [],
    }

    def execute(server: int) -> bytes:
        return encode_dictionary_exec(
            {
                'type': DictionaryType.exec,
                'query': query,
                'seq': 5,
                'field_version': FIELD_VERSION_10_2,
                'server_field_version': server,
            }
        )

    sql = b"SELECT 'x' FROM dual"
    (thin92, tenth) = (execute(FIELD_VERSION_9_2), execute(FIELD_VERSION_10_2))
    # The same head; 10g's has the block before the SQL, 9.2's goes straight on.
    head = thin92.index(sql)
    assert thin92[:head] == tenth[:head]
    assert tenth[head:].index(sql) > 0 and tenth.endswith(thin92[head + len(sql) :])
