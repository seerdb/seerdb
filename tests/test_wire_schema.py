# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""One message schema, two serialisations (#2064): the messages written from a
schema keep their wire bytes, in both dialects, and decode back."""

from __future__ import annotations

import contextlib
import random
from collections.abc import Iterator

import pytest

from seerdb.common import tns, wire_schema

FIELD_VERSIONS = (6, 7, 24)  # 11g, 12.1, 23ai
LENGTHS = (0, 1, 63, 64, 65, 252, 253, 254, 255, 256, 510, 511, 3026, 70000)
CODECS = (tns._THIN, tns._OCI)


@contextlib.contextmanager
def _field_version(version: int) -> Iterator[None]:
    tokens = (
        tns._ENCODE_FIELD_VERSION.set(version),
        tns._DECODE_FIELD_VERSION.set(version),
    )
    try:
        yield
    finally:
        tns._ENCODE_FIELD_VERSION.reset(tokens[0])
        tns._DECODE_FIELD_VERSION.reset(tokens[1])


def test_the_live_captures_are_written_as_they_were() -> None:
    # 23ai's logoff reply, 18c's answer to sqlplus's ping after a cancel, and
    # 23ai's SYNC reporting transaction priority `low`.
    assert tns.encode_logoff_status_thin() == bytes.fromhex('090101001d')
    assert tns.encode_ping_status_oci(0xFA2F) == bytes.fromhex('09010000002ffa')
    assert tns.encode_sync_piggyback([(204, 'low')]) == bytes.fromhex(
        '17050101100101160103036c6f770001cc00'
    )


def test_a_long_value_is_chunked_as_each_dialect_reads_it() -> None:
    # 253 bytes: thin's 64-byte chunks with a ub1 length below 12.1 and a
    # variable-width one from it; OCI's 255-byte chunks with a ub1 length.
    data = bytes(253)
    with _field_version(6):
        assert tns._bytes_with_length(data) == (
            b'\xfe' + (b'\x40' + bytes(64)) * 3 + b'\x3d' + bytes(61) + b'\x00'
        )
    with _field_version(7):
        assert tns._bytes_with_length(data) == (
            b'\xfe' + (b'\x01\x40' + bytes(64)) * 3 + b'\x01\x3d' + bytes(61) + b'\x00'
        )
    assert tns._oci_value_bytes(data) == b'\xfe\xfd' + data + b'\x00'


@pytest.mark.parametrize('version', FIELD_VERSIONS)
@pytest.mark.parametrize('length', LENGTHS)
def test_values_and_lob_data_decode_back(version: int, length: int) -> None:
    data = random.Random(length).randbytes(length)
    with _field_version(version):
        for codec in CODECS:
            for schema in ((('value', 'v'),), tns._LOB_DATA):
                key = schema[-1][1]
                wire = wire_schema.compile_encoder(schema, codec)({key: data})
                decode = wire_schema.compile_decoder(schema, codec)
                assert decode(wire + b'rest') == ({key: data}, b'rest')


@pytest.mark.parametrize('version', FIELD_VERSIONS)
def test_sync_decodes_back_in_both_dialects(version: int) -> None:
    pairs = [(0x10, 'AMERICAN'), (7, ''), (0x23, 'x' * 300)]
    with _field_version(version):
        for codec, slot in ((tns._THIN, 'text'), (tns._OCI, 'binary')):
            fields = tns._sync_fields(pairs, slot)
            wire = wire_schema.compile_encoder(tns._SYNC, codec)(fields)
            assert wire_schema.compile_decoder(tns._SYNC, codec)(wire) == (
                fields,
                b'',
            )


def test_an_oci_sync_value_past_255_bytes_is_chunked() -> None:
    # A bare ub1 length couldn't frame it, and raised (#2064).
    wire = tns.encode_sync_piggyback_oci([(1, 'y' * 300)])
    (fields, rest) = wire_schema.compile_decoder(tns._SYNC, tns._OCI)(wire)
    assert rest == b''
    assert fields['pairs'][0]['binary'] == b'y' * 300


def test_sta_decodes_back_in_both_dialects() -> None:
    values = {'call_status': 5, 'sequence': 0xFA2F}
    for codec in CODECS:
        wire = wire_schema.compile_encoder(tns._STA, codec)(values)
        assert wire_schema.compile_decoder(tns._STA, codec)(wire) == (values, b'')


def test_an_unknown_field_kind_is_refused() -> None:
    with pytest.raises(ValueError, match='unknown field kind'):
        wire_schema.compile_encoder((('ub3', 'x'),), tns._THIN)


def test_a_decode_hands_each_field_a_view_of_the_message() -> None:
    # GHSA-jhv3-6267-8qhw: each field read the rest of the message as a copy,
    # so a message of many small items took time in the square of its size --
    # an OCI AUTH of 1 MiB about 4 s, before its client had authenticated.
    # Every primitive is now handed a view of the message itself, and the
    # values it reads are bytes of their own.
    seen: list[memoryview] = []

    class _Recording:
        name = 'oci'

        def __getattr__(self, name: str):
            read = getattr(tns._OCI, name)
            if not name.startswith('read_'):
                return read

            def recorded(data):
                seen.append(data)
                return read(data)

            return recorded

    schema = (
        ('const', b'\x03'),
        ('n4', 'count'),
        ('each', 'pairs', 'count', (('n4', 'key'), ('value', 'value'))),
    )
    pairs = [{'key': i, 'value': bytes([i % 251]) * (i % 7)} for i in range(500)]
    data = wire_schema.compile_encoder(schema, tns._OCI)(
        {'count': len(pairs), 'pairs': pairs}
    )
    (values, rest) = wire_schema.compile_decoder(schema, _Recording())(
        data + b'tail', None
    )
    assert [(p['key'], p['value']) for p in values['pairs']] == [
        (p['key'], p['value']) for p in pairs
    ]
    assert all(type(p['value']) is bytes for p in values['pairs'])
    assert rest == b'tail' and type(rest) is bytes
    # The count, then each pair's two fields: every one a view of one message.
    assert len(seen) == 1 + 2 * len(pairs)
    assert all(isinstance(view, memoryview) for view in seen)
    assert len({id(view.obj) for view in seen}) == 1


@pytest.mark.parametrize('version', (6, 24))
def test_fetch_and_exec_by_cursor_decode_back_in_both_dialects(version: int) -> None:
    # Thin sends a call's token number from 23ai, OCI never (#2064).
    fetch = {'seq': 15, 'cursor': 2, 'rows': 15}
    execute = {
        'function': 4,
        'seq': 8,
        'cursor': 3,
        'iterations': 1,
        'options': 0x20,
        'options_2': 0,
    }
    with _field_version(version):
        for codec in CODECS:
            token = 0 if codec is tns._THIN and version >= 24 else None
            for schema, fields in ((tns._FETCH, fetch), (tns._EXEC_BY_CURSOR, execute)):
                values = fields | {'token_number': token}
                wire = wire_schema.compile_encoder(schema, codec)(values)
                decode = wire_schema.compile_decoder(schema, codec)
                assert decode(wire + b'rest') == (values, b'rest')


def test_an_oci_fetch_is_the_thin_fields_at_fixed_width() -> None:
    # Live 11g / 18c: `03 05 0f 02 00 00 00 0f 00 00 00` asks cursor 2 for 15 rows.
    wire = bytes.fromhex('03050f020000000f000000')
    assert tns.parse_fetch_oci(wire) == 15
    with _field_version(6):
        assert tns.encode_dictionary_fetch(
            {'seq': 15, 'cursor': 2, 'fetch': 15, 'field_version': 6}
        ) == bytes.fromhex('03050f0102010f')


@pytest.mark.parametrize('version', FIELD_VERSIONS)
@pytest.mark.parametrize(
    'content', (None, b'', b'x', bytes(252), bytes(253), bytes(600))
)
def test_a_long_cell_decodes_back_in_both_dialects(
    version: int, content: bytes | None
) -> None:
    # Thin's trailer has two indicators, OCI's one (#2064).
    with _field_version(version):
        for codec in CODECS:
            values = {'content': content, 'actual_length': 0, 'return_code': 0}
            if codec is tns._OCI:
                del values['return_code']
            wire = wire_schema.compile_encoder(tns._LONG_CELL, codec)(values)
            decode = wire_schema.compile_decoder(tns._LONG_CELL, codec)
            assert decode(wire) == (values, b'')


def test_the_describe_trailer_is_the_same_fields_in_both_dialects() -> None:
    # OCI's 33 bytes: a lead byte, the 7-byte date in the two-length form, four
    # ub4 flags and the query key's ub4 length; sqlplus 10.2's 29 lack the key.
    # A LOB describe sets the second flag (#405).
    with _field_version(24):
        oci = tns._describe_trailer(oci=True)
        assert oci == b'\x00\x07\x00\x00\x00\x07' + bytes(7) + bytes(16) + bytes(4)
        assert tns._describe_trailer(oci=False) == bytes(6)
        lob = tns._describe_trailer(oci=True, mdbz=8168)
        assert lob[17:21] == (8168).to_bytes(4, 'little')
    with _field_version(4):
        assert len(tns._describe_trailer(oci=True)) == 29
        assert tns._describe_trailer(oci=False) == bytes(5)


def test_a_ref_cursor_value_is_one_schema_with_its_dialects_lead() -> None:
    values = {'lead': 1, 'describe': b'D', 'cursor': 300, 'return_code': 0}
    assert tns._REFCURSOR_OUT_THIN(values) == b'\x01D\x02\x01\x2c\x00'
    values['lead'] = 0x4C
    assert tns._REFCURSOR_OUT_OCI(values) == b'\x4cD\x2c\x01\x00\x00\x00\x00'


def _columns() -> list:
    from seerdb.common.tns_consts import (
        TNS_TYPE_ADT,
        TNS_TYPE_CHAR,
        TNS_TYPE_NUMBER,
        TNS_TYPE_VARCHAR,
    )

    column = tns.ColumnMeta
    return [
        column(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        column(name=b'NAME', data_type=TNS_TYPE_VARCHAR, data_length=80, max_size=20),
        column(
            name=b'NC',
            data_type=TNS_TYPE_CHAR,
            data_length=10,
            max_size=5,
            csfrm=2,
            charset=2000,
        ),
        column(
            name=b'XML',
            data_type=TNS_TYPE_ADT,
            data_length=0,
            max_size=0,
            type_schema=b'SYS',
            type_name=b'XMLTYPE',
        ),
    ]


@pytest.mark.parametrize('version', (6, 7, 8, 11, 17))
def test_a_describe_column_decodes_back_in_both_dialects(version: int) -> None:
    # One schema, _DCB_COLUMN, reads what each dialect's encoder writes; the
    # flags its `when`s test aren't on the wire, so the reader is given them,
    # as the encoder was (#2064).
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        FIELD_VERSION_12_2,
        FIELD_VERSION_23_1,
    )

    with _field_version(version):
        for col in _columns():
            thin = tns._encode_dcb_column(col, 3)
            given = {
                'has_oaccolid': version >= FIELD_VERSION_12_2,
                'has_uds': version >= FIELD_VERSION_11_2,
                'has_domain': version >= FIELD_VERSION_23_1,
                'has_vector': False,
            }
            decode = wire_schema.compile_decoder(tns._DCB_COLUMN, tns._THIN)
            (fields, rest) = decode(thin, given)
            assert rest == b''
            assert (fields['position'], fields['name']) == (3, col.name)
            assert fields['charset'] == col.charset
            oci = tns._encode_dcb_column_oci(col, 3, first=True)
            typed = tns.oci_is_xmltype(col)
            given = {
                'oci_12c': version >= 7,
                'oci_plain': not typed,
                'has_oaccolid': not typed,
                'has_uds': version >= FIELD_VERSION_11_2,
            }
            decode = wire_schema.compile_decoder(tns._DCB_COLUMN, tns._OCI)
            (fields, rest) = decode(oci, given)
            assert rest == b''
            assert fields['name'] == col.name
            assert fields.get('type_name', b'') == (col.type_name if typed else b'')


def test_an_oci_column_is_48_bytes_ahead_of_its_name_and_8_more_from_12c() -> None:
    # The 11g block ahead of the name is 48 bytes, 56 from the 12c band, and a
    # typed column's is 6 bytes longer: its type id and version, without the
    # zero runs a plain column has (#265, #1282, #2050).
    plain, typed = _columns()[0], _columns()[3]
    for version, ahead in ((6, 48), (7, 56)):
        with _field_version(version):
            for col, extra in ((plain, 0), (typed, 6)):
                block = tns._encode_dcb_column_oci(col, 1, first=False)
                name_at = block.index(bytes([len(col.name)]) + col.name)
                assert name_at == ahead + extra


def test_a_rowid_cell_is_one_schema_in_both_dialects() -> None:
    # Thin: the present indicator and five fields, one unused. OCI: the length
    # 16 and four ub4s -- sqlplus 23.26 against a live 18c (#2017).
    rowid = 'AABAomAAMAAAACLAEr'  # object 264742, file 12, block 139, row 299
    assert tns.encode_rowid_value(rowid, tns._OCI) == bytes.fromhex(
        '10260a04000c0000008b0000002b010000'
    )
    assert tns.encode_rowid_value(rowid) == bytes.fromhex(
        '0a0304 0a26010c0001 8b02 012b'.replace(' ', '')
    )


@pytest.mark.parametrize('version', (6, 7))
def test_text_is_framed_as_each_dialect_frames_it(version: int) -> None:
    # The same up to 252 bytes; past them, OCI's 255-byte chunks with ub1
    # lengths, which sqlplus reads (#2053).
    with _field_version(version):
        for size in (0, 64, 65, 252):
            assert tns._OCI.chr(b'x' * size) == tns._THIN.chr(b'x' * size)
        assert tns._OCI.chr(b'x' * 300) == (
            b'\xfe\xff' + b'x' * 255 + b'\x2d' + b'x' * 45 + b'\x00'
        )


@pytest.mark.parametrize('metadata', (False, True))
def test_a_lob_cell_is_one_schema_in_both_dialects(metadata: bool) -> None:
    # The locator's length, the size and chunk size a client may read, then the
    # locator as a value (#405, #853, #1287).
    values = {
        'locator_length': 6,
        'has_metadata': metadata,
        'size': 3000,
        'chunk_size': 8132,
        'locator': b'\x00locat',
    }
    for codec in CODECS:
        wire = wire_schema.compile_encoder(tns._LOB_CELL, codec)(values)
        decode = wire_schema.compile_decoder(tns._LOB_CELL, codec)
        (fields, rest) = decode(wire, {'has_metadata': metadata})
        assert rest == b''
        assert fields['locator'] == values['locator']
        assert (fields.get('size'), fields.get('chunk_size')) == (
            (3000, 8132) if metadata else (None, None)
        )


def test_an_oci_lob_cell_reads_as_its_captured_lengths() -> None:
    # NULL is the length at zero, all four bytes; a value is 106, then -- to an
    # 11.2 client -- the locator's ub1 length 106 and its zero byte, which a
    # capture reads as a ub2 106 (#405, #1287).
    assert tns.encode_lob_locator_oci(None, True) == bytes(4)
    cell = tns.encode_lob_locator_oci('abc', True)
    assert cell[:6] == bytes.fromhex('6a000000 6a00'.replace(' ', ''))
    assert len(cell) == 4 + 1 + 106


def test_an_object_frame_ends_the_same_way_in_both_dialects() -> None:
    # Each dialect's own head, then the image's length, the TOP_LEVEL flags and
    # the image -- none for a NULL (#116, #2050).
    image = b'\x84\x01\x05\x00\x00'
    thin = tns._encode_object_frame(b'', image)
    (fields, rest) = wire_schema.compile_decoder(tns._OBJECT_FRAME, tns._THIN)(
        thin, {'has_image': True}
    )
    assert rest == b''
    assert (fields['image_length'], fields['flags'], fields['image']) == (5, 1, image)
    with _field_version(7):
        oci = tns._oci_object_frame(bytes(16), image)
        assert oci.endswith(b'\x05\x00\x00\x00' + b'\x01\x00' + b'\x05' + image)
        null = tns._oci_object_frame(bytes(16), None)
        assert null.endswith(b'\x00\x00\x00\x00' + b'\x01\x00')


@pytest.mark.parametrize('version', (6, 24))
def test_close_cursors_is_one_schema_in_both_dialects(version: int) -> None:
    # Thin's pointer flag and variable-width count, OCI's indicator and ub8
    # count, each closed cursor's id; the call behind it untouched (#191, #1517).
    call = bytes.fromhex('035e0799')
    live = bytes.fromhex('116911fe' + 'ff' * 7 + '02' + '00' * 7 + '0300000001000000')
    assert tns.strip_oci_piggyback(live + call) == call
    with _field_version(version):
        thin = tns.encode_close_cursors_piggyback(0x11, version, [3, 1])
        assert tns.skip_close_cursors_piggyback(thin + call) == call
        (fields, _rest) = tns._CLOSE_CURSORS_FROM_OCI(live)
        assert [c['cursor'] for c in fields['cursors']] == [3, 1]


def test_an_oci_lobops_read_is_thins_fields_at_fixed_width() -> None:
    # sqlplus 23.26 against 11g and Mirror-over-PG, and 10.2, whose pointers hold
    # addresses: the 135-byte head, the 106-byte locator, the ub8 amount
    # (#405, #1287, #2123).
    import sys

    sys.path.insert(0, 'tests')
    from test_server_query import _OCI_LOBOPS_READ_NARROW, _OCI_LOBOPS_READ_TWO_CLOBS
    from test_server_session import _OCI_LOB_READ_10_2

    for body, offset, amount in (
        (_OCI_LOBOPS_READ_TWO_CLOBS, 1, 7),
        (_OCI_LOBOPS_READ_NARROW, 51, 50),
        (_OCI_LOB_READ_10_2, 1, 80),
    ):
        (read, rest) = tns._LOBOPS_READ_FROM_OCI(body)
        assert rest == b''
        assert (read['operation'], read['source_length']) == (2, 106)
        assert (read['source_offset'], read['amount']) == (offset, amount)
        assert read['locator'][1:4] == b'\x68\x00\x01'


def test_a_truncated_thin_lobops_says_read_more() -> None:
    # A request spanning packets is parsed short first: Truncated, not a crash.
    with pytest.raises(tns.Truncated):
        tns.parse_lobops_request(b'\x03\x60\x01')


@pytest.mark.parametrize('version', (6, 7, 24))
def test_an_error_message_is_framed_by_each_dialects_value(version: int) -> None:
    # Thin's message is its codec's value, absent on success from 12.1; OCI's is
    # its own -- the 333-byte message a live 11g sends sqlplus (#734, #1520).
    message = b'x' * 333
    with _field_version(version):
        assert tns._oer_message(20001, message) == tns._THIN.value(message)
        assert tns._oer_message(0, b'') == (b'' if version >= 7 else b'\x00')
    assert tns._oci_error_text(message) == (
        b'\xfe\xff' + message[:255] + b'\x4e' + message[255:] + b'\x00'
    )


def test_an_oci_login_request_is_thins_fields_at_fixed_width() -> None:
    # sqlplus 11.2's and 10.2's OSESSKEY and 11.2's AUTH: 8-byte pointers (10.2
    # writes addresses), ub4 lengths declared at three times the characters, a
    # ub8 pair count, the user as a value (#265, #1764).
    import sys

    sys.path.insert(0, 'tests')
    from test_server_auth import _OCI_AUTH_SEEDED, _OCI_OSESSKEY_10_2

    head = tns.decode_auth_oci_head(_OCI_OSESSKEY_10_2)
    assert (head['subtype'], head['user'], head['user_length']) == (0x76, b'pyo', 9)
    assert all(head[f'pointer_{n}'] for n in (1, 2, 3, 4))
    fields = tns.decode_auth_oci(_OCI_AUTH_SEEDED)
    assert (fields['subtype'], fields['user'], fields['pair_count']) == (
        0x73,
        b'pyo',
        len(fields['pairs']),
    )
    keys = {pair.get('key'): pair for pair in fields['pairs']}
    assert keys[b'AUTH_SESSKEY']['key_length'] == 3 * len(b'AUTH_SESSKEY')
    assert len(keys[b'AUTH_SESSKEY']['value']) == 96  # 48 bytes as hex


@pytest.mark.parametrize('codec', CODECS)
def test_pad_derive_and_n1_decode_back(codec: wire_schema.Codec) -> None:
    # Zeros the other side ignores, a flag worked out from a field read before
    # it, and a byte that thin writes as a universal number.
    schema: wire_schema.Schema = (
        ('u8', 'kind'),
        ('derive', 'big', lambda v: v['kind'] > 1),
        ('when', 'big', (('pad', 3),)),
        ('n1', 'scale'),
    )
    encode = wire_schema.compile_encoder(schema, codec)
    decode = wire_schema.compile_decoder(schema, codec)
    for kind, scale in ((1, 0), (2, 127)):
        wire = encode({'kind': kind, 'big': kind > 1, 'scale': scale})
        assert wire.count(b'\x00') >= (3 if kind > 1 else 0)
        (fields, rest) = decode(wire + b'tail')
        assert (fields['kind'], fields['big'], fields['scale'], rest) == (
            kind,
            kind > 1,
            scale,
            b'tail',
        )
    with pytest.raises(IndexError):
        decode(bytes([2, 0]))


@pytest.mark.parametrize(
    ('name', 'version', 'size'), (('23_26', 11, 49), ('11_2', 6, 41))
)
def test_an_oci_bind_descriptor_is_thins_fields_at_fixed_width(
    name: str, version: int, size: int
) -> None:
    # sqlplus 23.26 and 11.2 binding six variables: 41 bytes each before 12c,
    # 49 from it; the declared length is the buffer, three bytes a character
    # (two for NCHAR), and the form tells the national pair; NUMBER has none
    # (#2064).
    import sys

    sys.path.insert(0, 'tests')
    import test_server_query

    request = getattr(test_server_query, f'_OCI_SIX_BINDS_{name}')
    row = request.index(b'\x07\x03abc')
    rest = request[row - 6 * size : row]
    found = []
    while rest:
        (oac, rest) = tns._OAC_FROM_OCI(rest, {'oci_12c': version >= 7})
        found.append((oac['data_type'], oac['max_length'], oac['csfrm']))
        assert oac['lead'] == 1
    assert found == [
        (1, 21, 1),
        (1, 12000, 1),
        (96, 39, 1),
        (96, 10, 2),
        (1, 18, 2),
        (2, 22, 0),
    ]


@pytest.mark.parametrize('version', (4, 6, 7, 11, 24))  # 10.2 to 23ai
def test_an_oci_describe_reads_back_by_its_own_schema(version: int) -> None:
    # Every column of sqlplus's describe, an XMLTYPE among them, decodes back
    # at each field version the Mirror speaks to sqlplus in (#265, #1764, #2050).
    columns = [
        tns.ColumnMeta(
            name=b'DUMMY',
            data_type=tns.TNS_TYPE_VARCHAR,
            data_length=1,
            max_size=1,
            charset=873,
            csfrm=1,
        ),
        tns.ColumnMeta(
            name=b'DOC',
            data_type=tns.TNS_TYPE_ADT,
            data_length=0,
            max_size=0,
            type_schema=b'SYS',
            type_name=b'XMLTYPE',
        ),
        tns.ColumnMeta(
            name=b'N',
            data_type=tns.TNS_TYPE_NUMBER,
            data_length=22,
            max_size=22,
            precision=5,
            scale=-127,
        ),
    ]
    with _field_version(version):
        back = tns._decode_describe_oci(tns.encode_describe_oci(columns))
    assert [c['name'] for c in back] == [b'DUMMY', b'DOC', b'N']
    assert [c['lead'] for c in back] == [1, 0, 1]
    assert back[0]['charset'] == 873
    assert back[1]['type_name'] == b'XMLTYPE'
    assert (back[2]['precision'], back[2]['scale']) == (5, -127)


@pytest.mark.parametrize('version', (6, 7, 24))
def test_an_oci_oer_decodes_back_at_each_width(version: int) -> None:
    # The OCI OER every status ends on: 136 bytes to 11g, 144 from 12.1, which
    # repeats the error number and adds the row count (#1282, #2064).
    with _field_version(version):
        oer = tns.encode_oci_oer(5, sequence=0x1234, error_code=942, rowcount=9)
    wide = version >= 7
    assert len(oer) == (144 if wide else 136)
    (fields, rest) = tns._OCI_OER_FROM_OCI(
        oer, {'oci_12c': wide, 'oci_pre12c': not wide}
    )
    assert rest == b''
    assert (fields['status'], fields['sequence'], fields['error_code']) == (
        5,
        0x1234,
        942,
    )
    assert fields['marker'] == bytes.fromhex('20f6310a')
    if wide:
        assert (fields['ext_error_code'], fields['rowcount']) == (942, 9)


def test_cstr_and_le2_round_trip_in_both_dialects() -> None:
    # The two codec-independent kinds the TTI_PRO reply needs (_PRO): a
    # NUL-terminated string and a little-endian ub2, both the same bytes
    # whatever the dialect.
    schema: wire_schema.Schema = (('cstr', 'banner'), ('le2', 'charset'))
    for codec in CODECS:
        encode = wire_schema.compile_encoder(schema, codec)
        decode = wire_schema.compile_decoder(schema, codec)
        wire = encode({'banner': b'x86_64/Linux', 'charset': 873})
        assert wire == b'x86_64/Linux\x00\x69\x03'  # 873 == 0x0369, little-endian
        assert decode(wire + b'rest') == (
            {'banner': b'x86_64/Linux', 'charset': 873},
            b'rest',
        )
