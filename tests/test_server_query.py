# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query-path parsing."""

from __future__ import annotations

import array
import datetime

import pytest

from seerdb.common.datatypes import IntervalYM, Var
from seerdb.common.exceptions import DataError, InterfaceError
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_OCI_CALL_SEQ,
    ColumnMeta,
    _decode_describe_body,
    _skip_chunked_bytes,
    decode_packet,
    describe_wire_length,
    encode_describe,
    encode_rows,
    parse_exec,
    parse_exec_oci,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_18_1_EXT_1,
    TNS_EOCS_FLAGS_TXN_IN_PROGRESS,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_JSON,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REF,
    TNS_TYPE_RID,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
    TTI_DCB,
    TTI_LOB,
    TTI_STA,
    VERSION_11_2_0_2,
)


@pytest.fixture(autouse=True)
def _pin_field_versions():
    # These tests build and decode 11g-format responses. BOTH the encode and the
    # decode paths pick their wire format from a field-version ContextVar
    # (_ENCODE_FIELD_VERSION / _DECODE_FIELD_VERSION), which in production is
    # established at the top of each encode/decode operation. The tests call the
    # low-level encoders (encode_rows, encode_describe) directly, so they must
    # establish those themselves — otherwise a version left behind by an earlier
    # test (e.g. a 23ai encode) flips the chunk framing and the decode fails with
    # "truncated DALC field". Pin both to 11.2 per test and restore after, so this
    # module is immune to and free of cross-test field-version leakage.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION

    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    dec = _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        yield
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)


def _decode_describe(payload: bytes) -> list[dict]:
    # Decode a describe block with the client's own 11g decoder.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    assert payload[0] == TTI_DCB
    columns, rest = _decode_describe_body(_skip_chunked_bytes(payload[1:]))
    assert rest == b'', 'describe did not consume cleanly'
    return columns


def _decode_response(response: bytes) -> tuple[list, list]:
    # Decode a full describe+rows+status response with the client's decoder.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    done, acc = decode_packet(response, (0, [], []))
    assert done
    return acc[1], acc[2]  # columns, rows


# A real 11g OALL8 execute for `select * from dual`, captured from seerdb 11.2
# through tools/capture_proxy.py (the TTC payload after the DATA prefix).
_DUAL_EXEC = bytes.fromhex(
    '035e070280210001011201010d000004ffffffff010f047fffffff00000000000000000000'
    '0001000000000073656c656374202a2066726f6d206475616c010100000000000001010000'
    '000000'
)


def test_a_10g_describe_has_no_11g_fields() -> None:
    # 10g's describe has no per-column `uds flags` and no `dcbqcky` query-cache
    # key after the four flags; both are 11g additions (#84). Encoded with them,
    # a 10g client read the key's length byte as its first row token (#814).
    from seerdb.common.tns_consts import FIELD_VERSION_10_2

    cols = [
        ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        ColumnMeta(name=b'S', data_type=TNS_TYPE_VARCHAR, data_length=5, max_size=5),
    ]
    with _at_field_version(FIELD_VERSION_11_2):
        at_11g = encode_describe(cols)
    with _at_field_version(FIELD_VERSION_10_2):
        at_10g = encode_describe(cols)
        response = encode_describe(cols) + encode_rows([(1, 'abc')], cols)
        done, acc = decode_packet(response + bytes([TTI_STA]), (0, [], []))
    # One ub4 per column and one empty bytes-with-length (a single 0 byte) less.
    assert len(at_11g) - len(at_10g) == len(cols) + 1
    assert done
    assert [c['column_name'] for c in acc[1]] == [b'N', b'S']
    assert acc[2] == [[1, 'abc']]


def test_parse_real_dual_exec() -> None:
    req = parse_exec(_DUAL_EXEC)
    assert req.sql == 'select * from dual'
    assert req.cursor == 0
    assert req.bind_count == 0
    assert req.fetch == 15


def test_non_exec_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_exec(b'\x06\x00not an exec')


def _at_field_version(version: int):
    # Pin both codec contextvars to `version` for one round-trip (the Mirror's
    # session loop does the same per request), restoring 11g afterwards.
    from contextlib import contextmanager

    from seerdb.common.tns import _ENCODE_FIELD_VERSION

    @contextmanager
    def pinned():
        d_tok, e_tok = (
            _DECODE_FIELD_VERSION.set(version),
            _ENCODE_FIELD_VERSION.set(version),
        )
        try:
            yield
        finally:
            _DECODE_FIELD_VERSION.reset(d_tok)
            _ENCODE_FIELD_VERSION.reset(e_tok)

    return pinned()


def _client_exec_request(
    version: int,
    sql: str,
    binds: list,
    *,
    batch: list | None = None,
    return_binds=None,
    kind: str = 'select',
) -> bytes:
    # The real client's OALL8 encoder, at the given field version.
    from seerdb.common.tns import encode_dictionary_exec

    return encode_dictionary_exec(
        {
            'field_version': version,
            'seq': 3,
            'query': {
                'type': kind,
                'auto': 0,
                'fetch': 15,
                'server_version': 0,
                'cursor': 0,
                'query': sql,
                'bind': binds,
                'batch': batch or [],
                'def': [],
                'batcherrors': None,
                'arraydmlrowcounts': None,
                'return_binds': return_binds,
                'scrollable': False,
                'scroll': None,
            },
        }
    )


def test_lob_column_locator_carries_metadata_and_reads_back_either_form() -> None:
    # A CLOB / BLOB column value is `ub4 locator length | ub8 size | ub4 chunk
    # size | length-prefixed locator`. The Mirror used to emit only the length
    # and the locator, so the reference thin client -- whose LOB reader reads
    # those two middle fields unconditionally -- took the locator's own length
    # prefix for the size and died with DPY-5002 (#853).
    #
    # A live 23ai sends the metadata form to that client and the BARE form to
    # seerdb, for the same row on the same settings; the switch is not known
    # (compile caps, runtime caps, DTY table, executes and prefetch were all
    # compared and are identical). So the Mirror always sends the metadata form,
    # which the stricter reader demands, and the reader below takes either.
    from seerdb.common.tns import (
        _read_lob_column,
        encode_lob_locator_thin,
    )

    # Both captured live from 23ai, the same 3000-byte BLOB column, one per
    # client. They must yield the same 114-byte locator.
    meta = bytes.fromhex(
        '0172020bb8021f7c7200700002010c02800001000000010000003eccc3000210'
        '0700021006000200020000000016000000000000016aa7323e00000000000000'
        '00000000001aab82f1000000000000deadbeef00010022000000000169b40b00'
        '000000000000000000000000000000000000021298000472ae0000'
    )
    bare = bytes.fromhex(
        '01727200700002010c02800001000000010000003eccc3000210070002100600'
        '0200020000000016000000000000016aa732410000000000000000000000001a'
        'ab82f1000000000000deadbeef00010022000000000169b40e00000000000000'
        '000000000000000000000000021298000472ae0000'
    )
    from_meta, meta_tail = _read_lob_column(meta)
    from_bare, bare_tail = _read_lob_column(bare)
    # Each yields the whole locator and consumes its value exactly. The two are
    # not byte-equal: they were captured on different sessions, and a locator
    # carries session-specific fields -- what matters is that the metadata in
    # front of one does not eat into it.
    assert from_meta is not None and from_bare is not None
    assert len(from_meta) == len(from_bare) == 114
    assert from_meta[:17] == from_bare[:17]  # the stable structural prefix
    assert meta_tail == b'' and bare_tail == b''

    # What the Mirror emits for a CLOB / BLOB: the metadata form, with the
    # value's own size, read back to the same locator.
    emitted = encode_lob_locator_thin(3000, with_metadata=True)
    assert emitted[:8].hex(' ') == '01 26 02 0b b8 02 1f 7c'  # len 38, size 3000
    locator, tail = _read_lob_column(emitted)
    assert locator is not None and len(locator) == 38 and tail == b''

    # JSON and VECTOR are read by different client paths (read_oson /
    # read_vector), so they keep the bare form and must still decode.
    plain = encode_lob_locator_thin()
    assert plain[:2].hex(' ') == '01 26'
    locator, tail = _read_lob_column(plain)
    assert locator is not None and len(locator) == 38 and tail == b''


def test_prefetched_vector_row_keeps_its_image_instead_of_reading_it() -> None:
    # The Mirror always serves a JSON / VECTOR column in the PREFETCHED framing
    # (image inline, locator behind it), because that is what the reference
    # client reads -- a real 23ai sends seerdb the bare locator instead, and
    # seerdb read the content over TTI_LOBOPS. Given the prefetched form it kept
    # doing that, and the locator behind the image resolves to nothing to fetch:
    # read() came back empty and the decoder rejected it as "not a VECTOR image"
    # (#959). The image in the row IS the content, so keep it on the LOB.
    import array

    from seerdb.common.tns_consts import TNS_TYPE_JSON, TNS_TYPE_VECTOR

    col = ColumnMeta(
        name=b'V',
        data_type=TNS_TYPE_VECTOR,
        data_length=8200,
        max_size=8200,
        vector_format=4,  # INT8
    )
    value = array.array('b', [1, -2, 3, -4])
    response = (
        encode_describe([col]) + encode_rows([(value,)], [col]) + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    (lob,) = rows[0]
    # No connection is attached, so a LOB that still wanted a round trip raises
    # InterfaceError here -- which is what master does. Reading must be answered
    # from the row itself.
    assert lob.read() == value

    # The same for a native JSON column, whose image the Mirror prefetches too.
    jcol = ColumnMeta(
        name=b'J', data_type=TNS_TYPE_JSON, data_length=8200, max_size=8200
    )
    doc = {'a': 1, 'b': ['x', True, None]}
    response = (
        encode_describe([jcol]) + encode_rows([(doc,)], [jcol]) + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    (jlob,) = rows[0]
    assert jlob.read() == doc


def test_row_codec_debug_logging_reports_the_framing_it_chose(caplog) -> None:
    # The row codec's debug lines are a diagnostic tool, so they are pinned:
    # they must fire, must not raise, and must report the fields the encoder and
    # decoder actually branch on. Every mid-row desync this codebase has had was
    # an encoder and a decoder disagreeing about one of them (#887/#826/#959),
    # and reconstructing that took throwaway print statements each time.
    import array
    import logging

    from seerdb.common.tns_consts import TNS_TYPE_VECTOR

    col = ColumnMeta(
        name=b'V',
        data_type=TNS_TYPE_VECTOR,
        data_length=8200,
        max_size=8200,
        vector_format=4,  # INT8
    )
    with caplog.at_level(logging.DEBUG, logger='seerdb.common.tns'):
        response = (
            encode_describe([col])
            + encode_rows([(array.array('b', [1, -2, 3, -4]),)], [col])
            + bytes([TTI_STA])
        )
        _decode_response(response)
    lines = [r.getMessage() for r in caplog.records]
    encoded = [m for m in lines if m.startswith('row encode:')]
    decoded = [m for m in lines if m.startswith('row decode LOB:')]
    assert encoded and decoded
    assert 'type=127' in encoded[0]
    # The prefetched form: an image was found, and the locator behind it is the
    # one num_bytes announced -- not the image's length reported twice.
    assert 'want_inline=True' in decoded[0]
    assert 'image=21' in decoded[0]
    assert 'num_bytes=38' in decoded[0] and 'locator=38' in decoded[0]


def test_an_xmltype_column_is_served_as_a_document_not_an_object() -> None:
    # XMLType describes as an ADT (type 109, SYS.XMLTYPE) but its VALUE is a
    # document, and every client surfaces it as a string -- so a backend hands
    # the Mirror a `str` for that column. Encoding it as an object asked the
    # `str` for its `_dbtype`, which is not an ORA error but an AttributeError:
    # the Mirror answered with an internal fault and the client's connection
    # died (DPY-4011). It rides the ordinary object frame with an XML image
    # inside (#826).
    from seerdb.common.dbobject import ObjectImage, decode_xmltype
    from seerdb.common.tns_consts import TNS_TYPE_ADT

    col = ColumnMeta(
        name=b'X',
        data_type=TNS_TYPE_ADT,
        data_length=2000,
        max_size=2000,
        type_schema=b'SYS',
        type_name=b'XMLTYPE',
        type_oid=b'\x01' * 16,
    )
    doc = '<IntCol>5</IntCol>'
    response = encode_describe([col]) + encode_rows([(doc,)], [col]) + bytes([TTI_STA])
    _, rows = _decode_response(response)
    (image,) = rows[0]
    assert isinstance(image, ObjectImage)
    assert image.type_name == 'XMLTYPE'
    # The image is an XMLType document, which is what the cursor layer decodes
    # when it sees that type name.
    assert decode_xmltype(image.image)[1] == doc


def test_a_dml_status_carries_the_last_rowid() -> None:
    # The client reads cursor.lastrowid from the OER's four rowid fields. The
    # Mirror used to write them as zero, so lastrowid was always None (#1077).
    # The rowid is one 23ai handed out; the client's own decoder reads it back.
    from seerdb.common.tns import decode_token_oer, encode_status

    rowid = 'AAAs/uAAAAAAWFFADg'
    reply = encode_status(1, rowid=rowid)
    assert decode_token_oer(reply, (None, None, []))[6] == rowid
    # No rowid, or a logical UROWID the physical fields cannot hold: none.
    for nothing in (None, '*BAMAAJ4CwQL+', 'not-a-rowid'):
        assert (
            decode_token_oer(encode_status(1, rowid=nothing), (None, None, []))[6]
            is None
        )


def test_a_described_column_carries_its_domain_and_annotations() -> None:
    # A 23ai column's domain and annotation map ride the describe; the Mirror
    # wrote them empty (#1082). The client's own column reader reads them back.
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        _ENCODE_FIELD_VERSION,
        ColumnMeta,
        _decode_dcb_column,
        _encode_dcb_column,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_23_4, TNS_TYPE_NUMBER

    col = ColumnMeta(
        name=b'AGE',
        data_type=TNS_TYPE_NUMBER,
        data_length=22,
        max_size=22,
        precision=3,
        domain_schema=b'PYO',
        domain_name=b'PYO_SIMPLE_DOMAIN',
        annotations=((b'ANNO_1', b'first annotation'), (b'ANNO_3', b'')),
    )
    plain = ColumnMeta(
        name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
    )
    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_4)
    dec = _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_4)
    try:
        (decoded, rest) = _decode_dcb_column(_encode_dcb_column(col, 2) + b'TAIL')
        (bare, _) = _decode_dcb_column(_encode_dcb_column(plain, 1))
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)
    assert (decoded['domain_schema'], decoded['domain_name']) == (
        b'PYO',
        b'PYO_SIMPLE_DOMAIN',
    )
    assert decoded['annotations'] == {b'ANNO_1': b'first annotation', b'ANNO_3': b''}
    assert rest == b'TAIL'  # nothing left unread, so the row stream stays in sync
    assert (bare['domain_schema'], bare['annotations']) == (None, None)


def test_a_described_column_grows_at_the_field_versions_23ai_sends_its_tail() -> None:
    # Measured against 23ai: a column's describe carries nothing after its
    # domain through field version 19, the annotation count from 20 (23.1 EXT
    # 3), and the vector descriptor too from 24 (23.4). Both went out from 18,
    # which a client at 18 to 23 could not read.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, ColumnMeta, _encode_dcb_column
    from seerdb.common.tns_consts import TNS_TYPE_DATE

    col = ColumnMeta(
        name=b'SYSDATE', data_type=TNS_TYPE_DATE, data_length=7, max_size=7
    )

    def size(field_version: int) -> int:
        token = _ENCODE_FIELD_VERSION.set(field_version)
        try:
            return len(_encode_dcb_column(col, 1))
        finally:
            _ENCODE_FIELD_VERSION.reset(token)

    growth = {fv: size(fv) - size(17) for fv in range(17, 25)}
    assert growth == {17: 0, 18: 0, 19: 0, 20: 1, 21: 1, 22: 1, 23: 1, 24: 4}


# 23ai's reply to `select b from t` for a BOOLEAN column holding TRUE and
# FALSE, to the thin client at field version 6 (11.2): the describe, the two
# rows and ORA-01403. Captured live (#2416).
_BOOLEAN_AT_11_2 = bytes.fromhex(
    '1017f71aa1e49e06482ffb7f5e1aa4b6a55a787e0b02140c370116010159020000000116'
    '0000000000000001010101014200000000010707787e0b02140c380101021fe8010a010a'
    '00062201010001640000000702c10207018008010604016bbb0c00010501010000000000'
    '04010202c1de010202057b00000105010e03000000000003024a3b0204000003013d6401'
    '0100000a00010100000000194f52412d30313430333a206e6f206461746120666f756e64'
    '0a'
)


def _at_11_2(func, *args):
    # Run an encoder or decoder as an 11.2 thin session's, in a copied context.
    import contextvars

    from seerdb.common.features import _SESSION_FEATURES, session_features
    from seerdb.common.tns import _DECODE_FIELD_VERSION, _ENCODE_FIELD_VERSION
    from seerdb.common.tns_consts import FIELD_VERSION_11_2

    def run():
        _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
        _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
        _SESSION_FEATURES.set(session_features(FIELD_VERSION_11_2))
        return func(*args)

    return contextvars.copy_context().run(run)


def test_a_boolean_reaches_an_older_client_as_23ai_sends_it() -> None:
    # Below field version 17 a BOOLEAN goes out as 23ai sends it: described as
    # a NUMBER with length 22, precision 0, scale 0 and no charset, and each
    # value as the NUMBER 1 or 0 (#2416). The Mirror sent type 252, which
    # sqlplus 10.2 and 11.2 refused with ORA-03115.
    from seerdb.common.tns import (
        ColumnMeta,
        _decode_dcb_column,
        _encode_dcb_column,
        _thin_column_value,
        decode_packet,
    )
    from seerdb.common.tns_consts import TNS_TYPE_BOOLEAN

    col = ColumnMeta(name=b'B', data_type=TNS_TYPE_BOOLEAN, data_length=1, max_size=1)
    live = _at_11_2(decode_packet, _BOOLEAN_AT_11_2, (None, None, []), 6)
    (served, _) = _at_11_2(_decode_dcb_column, _at_11_2(_encode_dcb_column, col, 1))
    fields = ('data_type', 'data_length', 'precision', 'data_scale', 'charset', 'csfrm')
    assert [served[f] for f in fields] == [live[3][1][0][f] for f in fields]
    assert live[4] == [[1], [0]]
    # Each cell as 23ai wrote it, byte for byte.
    for value in (True, False):
        cell = _at_11_2(_thin_column_value, value, col)
        assert cell in _BOOLEAN_AT_11_2
    assert _at_11_2(_thin_column_value, True, col) == bytes.fromhex('02c102')
    assert _at_11_2(_thin_column_value, False, col) == bytes.fromhex('0180')
    assert _at_11_2(_thin_column_value, None, col) == b'\x00'


def test_a_boolean_stays_native_for_a_23ai_client() -> None:
    from seerdb.common.features import _SESSION_FEATURES, session_features
    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        ColumnMeta,
        _encode_dcb_column,
        _thin_column_value,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_23_4, TNS_TYPE_BOOLEAN

    col = ColumnMeta(name=b'B', data_type=TNS_TYPE_BOOLEAN, data_length=1, max_size=1)
    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_4)
    features = _SESSION_FEATURES.set(session_features(FIELD_VERSION_23_4))
    try:
        assert _encode_dcb_column(col, 1)[0] == TNS_TYPE_BOOLEAN
        assert _thin_column_value(True, col) != bytes.fromhex('02c102')
    finally:
        _SESSION_FEATURES.reset(features)
        _ENCODE_FIELD_VERSION.reset(enc)


def test_a_urowid_is_served_with_the_tag_its_kind_carries() -> None:
    # The tag byte tells a client what the rowid is: 0x02 logical, 0x01 physical,
    # both captured from 23ai. Every value used to go out tagged 0x01, so
    # python-oracledb read an IOT's logical rowid as a physical one (#1087).
    from seerdb.common.tns import encode_sb4, encode_urowid_value

    # A logical rowid: 0x02 + the '*' body's bytes (an IOT row, captured).
    logical = encode_urowid_value('*BAEAGYMCwQL+')
    assert logical.endswith(bytes.fromhex('02040100198302c102fe'))
    # A physical rowid in a UROWID column: 0x01 + object / file / block / slot,
    # big-endian (captured: the ROWID column of the same row printed the same).
    physical = encode_urowid_value('AAAfXBAAAAAAVrtAAA')
    assert physical.endswith(bytes.fromhex('010001f5c1000000015aed0000'))
    assert encode_urowid_value(None) == encode_sb4(0)


def test_a_cut_array_dml_says_truncated_so_the_request_can_grow() -> None:
    # A request bigger than one packet arrives in pieces and the Mirror grows it
    # only while the parser says Truncated. A DALC cut at a row boundary used to
    # raise a bare DataError, and an array DML cut between rows parsed "fine"
    # with rows missing -- so a 4000-row executemany was refused as unparsable
    # and a 10000-row one desynced the session (#1097).
    from seerdb.common.exceptions import Truncated
    from seerdb.common.tns import decode_dalc, parse_exec

    with pytest.raises(Truncated):
        decode_dalc(b'')
    with pytest.raises(Truncated):
        decode_dalc(bytes([4, 1, 2]))  # promises 4 bytes, 2 left

    # A 3-row array DML from the real client encoder, then the same bytes cut at
    # the second row's boundary -- what a Mirror sees when the request spans
    # packets.
    from seerdb.common.tns_consts import FIELD_VERSION_23_1, TTI_RXD

    rows = [[1, 'a'], [2, 'b'], [3, 'c']]
    with _at_field_version(FIELD_VERSION_23_1):
        full = _client_exec_request(
            FIELD_VERSION_23_1,
            'insert into t values (:1, :2)',
            rows[0],
            batch=rows[1:],
            kind='change',
        )
        request = parse_exec(full)
        assert len(request.bind_rows) == 3 and request.iterations == 3
        second_row = full.index(bytes([TTI_RXD]), full.index(bytes([TTI_RXD])) + 1)
        with pytest.raises(Truncated):
            parse_exec(full[:second_row])


def test_a_json_column_defined_as_text_is_served_as_oracle_renders_it() -> None:
    # A client whose output type handler asks for a JSON column as character data
    # gets the document as compact JSON TEXT, not the OSON image (#1106). The
    # expected string is what 23ai sent for this document through a str redefine.
    from dataclasses import replace

    from seerdb.common.tns import (
        _INLINE_LONG_FROM,
        ColumnMeta,
        _thin_column_value,
        json_as_text,
    )
    from seerdb.common.tns_consts import (
        TNS_TYPE_CHAR,
        TNS_TYPE_JSON,
        TNS_TYPE_LONG,
        TNS_TYPE_VARCHAR,
    )

    document = {'name': 'John', 'city': 'Delhi'}
    assert json_as_text(document) == '{"name":"John","city":"Delhi"}'
    assert _INLINE_LONG_FROM[TNS_TYPE_JSON] == frozenset(
        {TNS_TYPE_CHAR, TNS_TYPE_VARCHAR, TNS_TYPE_LONG}
    )
    col = ColumnMeta(name=b'J', data_type=TNS_TYPE_JSON, data_length=8200, max_size=0)
    inline = _thin_column_value(document, replace(col, inline_long_csfrm=1))
    assert b'{"name":"John","city":"Delhi"}' in inline
    # Without the define it is still the OSON image.
    assert inline != _thin_column_value(document, col)


def test_a_plsql_reply_reports_the_directions_the_server_gave() -> None:
    # The Mirror used to mark every bind of a PL/SQL block OUT and return each
    # value, because the wire carries no direction on the way in. A backend that
    # asked a real server knows better, and an IN bind then carries NO value --
    # which matters most for a LONG-declared bind, whose echoed value the client
    # cannot read in that position (#1064).
    from seerdb.common.tns import ScalarOutBind, encode_out_bind_response_thin
    from seerdb.common.tns_consts import (
        TNS_BIND_DIR_INPUT,
        TNS_BIND_DIR_INPUT_OUTPUT,
        TNS_BIND_DIR_OUTPUT,
        TNS_TYPE_VARCHAR,
    )

    binds: list = [
        ScalarOutBind(value='in-value', tns_type=TNS_TYPE_VARCHAR, csfrm=1),
        ScalarOutBind(value='out-value', tns_type=TNS_TYPE_VARCHAR, csfrm=1),
    ]
    told = encode_out_bind_response_thin(
        binds, (TNS_BIND_DIR_INPUT, TNS_BIND_DIR_OUTPUT)
    )
    assert bytes([TNS_BIND_DIR_INPUT, TNS_BIND_DIR_OUTPUT]) in told
    assert b'out-value' in told
    assert b'in-value' not in told  # an IN bind carries no value back

    # Without directions every bind is reported IN OUT and returns its value,
    # which is what a backend that cannot know keeps doing. Not OUT: a client
    # re-executing the block sends no value for a pure-OUT bind (#1363).
    untold = encode_out_bind_response_thin(binds)
    assert bytes([TNS_BIND_DIR_INPUT_OUTPUT, TNS_BIND_DIR_INPUT_OUTPUT]) in untold
    assert b'in-value' in untold and b'out-value' in untold


def test_a_vector_defined_as_text_is_served_as_oracle_renders_it() -> None:
    # A client whose output type handler asks for a VECTOR column as character
    # data gets the TEXT form inline, not the binary image (#1107). The expected
    # strings are what 23ai sent for these exact vectors, read back through a
    # LONG redefine.
    import array

    from seerdb.common.tns import _INLINE_LONG_FROM, vector_as_text
    from seerdb.common.tns_consts import (
        TNS_TYPE_CHAR,
        TNS_TYPE_LONG,
        TNS_TYPE_VARCHAR,
        TNS_TYPE_VECTOR,
    )
    from seerdb.common.vector import SparseVector

    assert (
        vector_as_text(
            SparseVector(
                16, array.array('I', [1, 3, 5]), array.array('f', [1.0, 0.0, 5.0])
            )
        )
        == '[16,[1,3,5],[1.0E+000,0,5.0E+000]]'
    )
    assert (
        vector_as_text(
            SparseVector(
                16, array.array('I', [1, 3, 5]), array.array('d', [1.5, 0.25, 0.5])
            )
        )
        == '[16,[1,3,5],[1.5E+000,2.5E-001,5.0E-001]]'
    )
    assert vector_as_text(array.array('d', [1.5, -2.0, 3.25])) == (
        '[1.5E+000,-2.0E+000,3.25E+000]'
    )
    # An INT8 vector prints as integers, and an exact zero prints bare.
    assert vector_as_text(array.array('b', [1, 2, 3])) == '[1,2,3]'
    assert vector_as_text(array.array('d', [0.0, 1.0])) == '[0,1.0E+000]'
    # The redefine itself has to be allowed, or the define is ignored and the
    # image goes out under a character variable.
    assert _INLINE_LONG_FROM[TNS_TYPE_VECTOR] == frozenset(
        {TNS_TYPE_CHAR, TNS_TYPE_VARCHAR, TNS_TYPE_LONG}
    )


def test_a_vector_column_defined_as_text_encodes_inline() -> None:
    # End to end through the row encoder: with the define marked, the cell is an
    # inline LONG carrying the text, not a prefetched image.
    import array
    from dataclasses import replace

    from seerdb.common.tns import ColumnMeta, _thin_column_value
    from seerdb.common.tns_consts import TNS_TYPE_VECTOR

    col = ColumnMeta(name=b'V', data_type=TNS_TYPE_VECTOR, data_length=8200, max_size=0)
    value = array.array('b', [1, 2, 3])
    inline = _thin_column_value(value, replace(col, inline_long_csfrm=1))
    assert b'[1,2,3]' in inline
    assert inline != _thin_column_value(value, col)


def test_encode_status_with_rowcounts_is_the_return_parameters_block() -> None:
    # The arraydmlrowcounts status carries the counts in the execute's
    # return-parameters block (TTI_RPA), laid out as a real server lays it out
    # and the reference client reads it (#859): four leading words -- al8o4l
    # count, al8txl length, key/value pairs, registration length -- all empty,
    # then `ub4 rows | rows x ub8`, then the ordinary status OER. A first cut
    # framed the counts as a private `ub4 zero | ub4 count | count x ub4`.
    # seerdb's own decoder accepted both shapes, which is how it passed its own
    # suite; the reference client read the four words by name, took the count
    # for the al8txl length, and parsed the values as key/value pairs until it
    # died (DPY-5002).
    from seerdb.common.tns import (
        TTI_RPA,
        decode_ub4,
        encode_status,
        encode_status_with_rowcounts,
    )

    counts = [1, 1, 2, 0]
    reply = encode_status_with_rowcounts(4, counts, cursor_id=9)
    # Byte-exact: four empty words, the row count, one value per iteration (a
    # zero is a single 00 byte), then the status.
    assert reply == bytes.fromhex(
        '08 00 00 00 00 01 04 01 01 01 01 01 02 00'
    ) + encode_status(4, cursor_id=9)
    # Walked the way the reference reader walks it, field by field.
    rest = reply[1:]
    words = []
    for _ in range(4):
        word, rest = decode_ub4(rest)
        words.append(word)
    assert words == [0, 0, 0, 0]
    rows, rest = decode_ub4(rest)
    assert rows == len(counts)
    got = []
    for _ in range(rows):
        value, rest = decode_ub4(rest)
        got.append(value)
    assert got == counts
    assert rest == encode_status(4, cursor_id=9)
    # (seerdb's own client reading this block back is covered live: the
    # arraydmlrowcounts cases of test_integration run through the passthrough
    # Mirror on every 12c+ tier.)
    # A bare status (no request) is unchanged -- it does not lead with the RPA.
    assert encode_status(5, cursor_id=9)[0] != TTI_RPA


@pytest.mark.parametrize('version', [17, 24])  # 23ai (legacy handshake / fast-auth)
def test_parse_tpc_switch_reads_sessionless_begin_resume_suspend(version: int) -> None:
    # A sessionless begin / resume / suspend rides as a TPC switch (TTI_FUN 103);
    # the parser is the inverse of the client's encoder at the negotiated version
    # (which adds a token slot above 23ai), recovering the operation, the flags
    # that separate a new begin from a resume, the timeout and the transaction id.
    from seerdb.common.tns import encode_tpc_switch, parse_tpc_switch
    from seerdb.common.tns_consts import (
        TNS_TPC_SESSIONLESS_FORMAT_ID,
        TNS_TPC_TXN_DETACH,
        TNS_TPC_TXN_START,
        TPC_BEGIN_NEW,
        TPC_BEGIN_RESUME,
        TPC_TXN_FLAGS_SESSIONLESS,
    )

    xid = (TNS_TPC_SESSIONLESS_FORMAT_ID, b'sl-1', b'')
    begin = encode_tpc_switch(
        7,
        version,
        TNS_TPC_TXN_START,
        xid,
        TPC_BEGIN_NEW | TPC_TXN_FLAGS_SESSIONLESS,
        60,
        None,
    )
    op, flags, timeout, txn = parse_tpc_switch(begin, version)
    assert op == TNS_TPC_TXN_START and not (flags & TPC_BEGIN_RESUME)
    assert timeout == 60 and txn == b'sl-1'

    resume = encode_tpc_switch(
        7,
        version,
        TNS_TPC_TXN_START,
        xid,
        TPC_BEGIN_RESUME | TPC_TXN_FLAGS_SESSIONLESS,
        30,
        None,
    )
    op, flags, timeout, txn = parse_tpc_switch(resume, version)
    assert op == TNS_TPC_TXN_START and flags & TPC_BEGIN_RESUME
    assert timeout == 30 and txn == b'sl-1'

    suspend = encode_tpc_switch(
        7,
        version,
        TNS_TPC_TXN_DETACH,
        None,
        TPC_TXN_FLAGS_SESSIONLESS,
        0,
        None,
    )
    op, _flags, _timeout, txn = parse_tpc_switch(suspend, version)
    assert op == TNS_TPC_TXN_DETACH and txn == b''


@pytest.mark.parametrize('version', [8, 12, 16, 17, 24])  # 12.2, 19c, 21c, 23ai, fv24
def test_parse_exec_reads_the_12c_request_layout(version: int) -> None:
    # From 12.2 the client's OALL8 replaces the marker + server-version slot with
    # a registration / array-DML / SQL-signature block, length-prefixes the SQL,
    # and appends an oaccolid to each bind OAC; the parser follows the session's
    # field version. The 11g layout stays byte-identical (the default suites).
    with _at_field_version(version):
        request = parse_exec(
            _client_exec_request(version, 'select :b, :n from dual', ['abc', 42])
        )
    assert request.sql == 'select :b, :n from dual'
    assert request.binds == ['abc', 42]
    with _at_field_version(version):
        plain = parse_exec(_client_exec_request(version, 'select 1 from dual', []))
    assert plain.sql == 'select 1 from dual'
    assert plain.binds == []


@pytest.mark.parametrize('version', [6, 8, 17])  # 11.2, 12.2, 23ai
def test_parse_exec_skips_the_binds_a_returning_clause_fills(version: int) -> None:
    # A `RETURNING ... INTO` bind is described like any other but carries NO value
    # in the row data -- the server fills it from the affected rows. Reading one
    # anyway consumed the next value as this one's tail, and everything after it
    # was misread (#689). The parsed row keeps a None in that position so it stays
    # aligned with bind_meta, which does describe every bind.
    sql = 'insert into t (v) values (:1) returning id into :2'
    receiver = Var(int)
    with _at_field_version(version):
        request = parse_exec(
            _client_exec_request(
                version,
                sql,
                ['abc', receiver],
                return_binds=frozenset({1}),
                kind='change',
            )
        )
    assert request.sql == sql
    assert request.return_binds == frozenset({1})
    assert request.binds == ['abc', None]
    # Every bind is still described, receiver included.
    assert len(request.bind_meta) == 2


@pytest.mark.parametrize('version', [6, 17])
def test_parse_exec_skips_the_returning_bind_in_every_iteration(version: int) -> None:
    # The same rule per iteration of an array execute: one value each, none for
    # the receiver, and the rows must not slide into one another.
    sql = 'insert into t (v) values (:1) returning id into :2'
    receiver = Var(int)
    rows = [['a', receiver], ['bb', receiver], ['ccc', receiver]]
    with _at_field_version(version):
        request = parse_exec(
            _client_exec_request(
                version,
                sql,
                rows[0],
                batch=rows[1:],
                return_binds=frozenset({1}),
                kind='change',
            )
        )
    assert request.bind_rows == [['a', None], ['bb', None], ['ccc', None]]


@pytest.mark.parametrize('version', [6, 17])
def test_parse_exec_reports_the_execute_iteration_count(version: int) -> None:
    # A RETURNING statement whose only bind is filled by the clause (an empty
    # INSERT) sends no RXD row, so bind_rows is empty -- but the al8i4 iteration
    # count still says how many times it runs, which is the only record the server
    # has (#33). A plain execute is 1; a 3-row array batch is 3.
    receiver = Var(int)
    with _at_field_version(version):
        single = parse_exec(
            _client_exec_request(
                version,
                'insert into t (id) values (s.nextval) returning id into :1',
                [receiver],
                return_binds=frozenset({0}),
                kind='change',
            )
        )
        array = parse_exec(
            _client_exec_request(
                version,
                'insert into t (id) values (s.nextval) returning id into :1',
                [receiver],
                batch=[[receiver], [receiver]],
                return_binds=frozenset({0}),
                kind='change',
            )
        )
    # No input value rides in either message, so the row data is empty...
    assert single.bind_rows == [] and array.bind_rows == []
    # ...but the iteration count survives: one, then three (1 + 2 batch rows).
    assert single.iterations == 1
    assert array.iterations == 3


def test_a_query_reexecutes_once_however_many_rows_it_prefetches() -> None:
    # al8i4[1] carries the execute iteration count for a DML, but for a QUERY it
    # carries the number of rows to prefetch -- and al8i4[7] is the is-query flag
    # that tells the two apart. The reference client writes its fetch array size
    # (arraysize, 100 by default) there whenever it re-executes a cursor it
    # already holds, so reading it as an iteration count turned a plain
    # re-executed SELECT into a 100-iteration array DML: the query never ran and
    # the client got a row count where it expected rows (#826).
    from seerdb.common.tns import _DECODE_FIELD_VERSION
    from seerdb.server.session import _skip_piggybacks

    # Byte-for-byte off a live capture (fv24): a close-cursors piggyback, then
    # the OALL8 re-executing cursor 2 with no SQL, no binds and al8i4 =
    # [0, 100, 0, 0, 0, 0, 0, 1, ...] -- 100 prefetch rows, is-query set.
    captured = bytes.fromhex(
        '116908000101010103035e09000280200102000001010d0000000164047fffff'
        'ff00000000000000000000000100000000000000000000000000000000016400'
        '00000000010100028000000000'
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_exec(_skip_piggybacks(captured))
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert (request.sql, request.cursor, request.bind_count) == ('', 2, 0)
    assert request.fetch == 100  # it does want a hundred rows back...
    assert request.iterations == 1  # ...from ONE execution of the statement


def test_returning_response_round_trips_to_the_client_decoder() -> None:
    # The reply carries one record per iteration, values grouped by bind. Decode
    # it with the client's own reader to prove the two agree (#689).
    from seerdb.common.tns import (
        decode_packet,
        encode_returning_response,
        set_decode_return_binds,
    )

    blob = encode_returning_response(
        4, [[(1,), (2,)], [], [(3,)], [(4,)]], [TNS_TYPE_NUMBER]
    )
    set_decode_return_binds([1])
    try:
        decoded = decode_packet(blob, (None, None, []))
    finally:
        set_decode_return_binds(None)
    records = [row for row in decoded[4] if isinstance(row, dict)]
    # Four iterations, in order, including the one that matched nothing -- it
    # keeps its place so the client's positions stay aligned.
    assert [len(r['return_values'][0]) for r in records] == [2, 0, 1, 1]


def test_returned_object_round_trips_to_the_client_decoder() -> None:
    # `RETURNING ObjectCol INTO :b`. The value carries the OBJECT frame a column
    # uses, not a DALC: encoded as a DALC it was asked for a scalar wire form a
    # DbObject has none of, and the Mirror answered ORA-03115 "no wire encoding
    # for a column value of type DbObject" (#826).
    #
    # Encoded here and read back with the CLIENT's own decoder, because a
    # round trip through our own encoder alone would prove only that it agrees
    # with itself.
    from seerdb.common.dbobject import DbObject, DbObjectType, ObjectImage
    from seerdb.common.tns import (
        decode_packet,
        encode_returning_response,
        set_decode_return_binds,
    )
    from seerdb.common.tns_consts import TNS_TYPE_ADT, TNS_TYPE_VARCHAR

    typ = DbObjectType(
        'PYO',
        'UDT_OBJECT',
        b'\x02' * 16,
        1,
        [{'name': 'NAME', 'data_type': TNS_TYPE_VARCHAR}],
    )
    obj = DbObject('UDT_OBJECT', [('NAME', 'Alice')], dbtype=typ)
    blob = encode_returning_response(1, [[(obj,)]], [TNS_TYPE_ADT])
    set_decode_return_binds([0], {0: TNS_TYPE_ADT})
    try:
        decoded = decode_packet(blob, (None, None, []))
    finally:
        set_decode_return_binds(None)
    (record,) = [row for row in decoded[4] if isinstance(row, dict)]
    (value,) = record['return_values'][0]
    assert isinstance(value, ObjectImage)
    assert b'Alice' in value.image


def test_session_state_reply_matches_the_captured_server_bytes() -> None:
    # `alter session set current_schema = X` does not just succeed: the server
    # reports the new value back, and that reply is the ONLY place a client
    # learns it -- `connection.current_schema` never queries for it. Answering
    # with a bare status left the attribute stale for the whole session (#973).
    #
    # Ground truth: the reply a live 23ai sent for `... = PYO`, captured whole.
    # The generated block must reproduce it byte for byte up to the status,
    # which is generated separately (hardcoding the captured one froze its
    # sequence number and the client waited for a reply that never matched).
    from seerdb.common.tns import encode_session_state_response

    captured = bytes.fromhex(
        '080106'
        + '0401b6ff73'
        + '00'
        + '0102'
        + '0102'
        + '00'
        + '00'
        + '000000'
        + '1705010110'
        + '010216'
        + '0103'
        + '03'
        + '50594f'
        + '0001a8000104040000008801a900'
    )
    assert encode_session_state_response('PYO') == captured


def test_session_state_reply_reports_an_edition_under_its_own_key() -> None:
    # EDITION is the same mechanism as CURRENT_SCHEMA under a different key
    # (0x01 vs 0x02) and with a different trailing entry (0xac vs 0xa8/0xa9) --
    # both captured by altering that one attribute on a live 23ai. Ground truth
    # is the server's own reply for `alter session set edition = PYTHONEDITION`,
    # minus the two per-session counters it carries (the SCN-ish word and the
    # sequence), which are session bookkeeping rather than payload (#973).
    from seerdb.common.tns import _STATE_KEY_EDITION, encode_session_state_response

    captured = bytes.fromhex(
        '080106'
        + '0401b70ce4'
        + '00'
        + '0101'
        + '0102'
        + '00'
        + '00'
        + '000000'
        + '1705010110'
        + '010116'
        + '010d'
        + '0d'
        + '505954484f4e45444954494f4e'
        + '0001ac00'
    )
    # The two per-session counters are parameters, so the capture's own values
    # can be supplied and the whole block demanded byte for byte.
    assert (
        encode_session_state_response(
            'PYTHONEDITION', key=_STATE_KEY_EDITION, scn=0x01B70CE4, seq=1
        )
        == captured
    )


def test_session_state_reply_carries_the_name_at_any_length() -> None:
    # Two length fields precede the name and BOTH scale -- the ub4 and the DALC
    # repeat it, the same double-length shape the SET_SCHEMA piggyback uses in
    # the other direction. A one-byte assumption would pass for short names and
    # corrupt long ones.
    from seerdb.common.tns import encode_session_state_response

    for name in ('PYO', 'PYTHONTEST', 'PYTHONTESTPROXY'):
        block = encode_session_state_response(name)
        encoded = name.encode()
        assert bytes([len(encoded), len(encoded)]) + encoded in block
        # and the value is upper-cased, as the server reports it
        assert encode_session_state_response(name.lower()) == block


@pytest.mark.parametrize('version', [8, 17, 24])
def test_describe_decodes_back_at_a_12c_field_version(version: int) -> None:
    # The describe column gains a one-byte scale and an oaccolid at 12.2, and the
    # SQL-domain schema + name at 23ai; the client's own decoder at that version
    # must read the Mirror's block cleanly.
    cols = [
        ColumnMeta(
            name=b'ID',
            data_type=TNS_TYPE_NUMBER,
            data_length=22,
            max_size=22,
            precision=5,
            scale=-2,
            null_ok=0,
        ),
        ColumnMeta(
            name=b'NAME', data_type=TNS_TYPE_VARCHAR, data_length=30, max_size=30
        ),
    ]
    with _at_field_version(version):
        payload = encode_describe(cols)
        assert payload[0] == TTI_DCB
        decoded, rest = _decode_describe_body(_skip_chunked_bytes(payload[1:]))
    assert rest == b''
    assert [c['column_name'] for c in decoded] == [b'ID', b'NAME']
    assert decoded[0]['data_scale'] == -2  # the 12c single signed scale byte
    assert decoded[0]['null_ok'] == 0
    assert decoded[1]['max_size'] == 30


@pytest.mark.parametrize('version', [6, 8, 14, 17])  # 11.2, 12.2, 20.1, 23ai
def test_long_error_message_decodes_back_at_every_field_version(version: int) -> None:
    # A message over 252 bytes is chunked, and an 11g client reads single-byte
    # chunk lengths where a 12.2+ one reads ub4 ones; the Mirror's error reply
    # has to be framed for the version the session negotiated (#734). The
    # batch-error messages ride the same framing.
    from seerdb.common.tns import (
        decode_token_oer,
        encode_batch_errors_status,
        encode_error,
    )

    message = 'ORA-00900: ' + ' '.join(['a long explanation'] * 20)  # > 252 bytes
    assert len(message.encode()) > 252
    with _at_field_version(version):
        error = decode_token_oer(encode_error(900, message), (0, [], []))
        batch = decode_token_oer(
            encode_batch_errors_status(1, [(0, 1, message), (2, 900, 'short')]),
            (0, [], []),
        )
    assert error[1] == 900 and error[5] == message
    assert [e['message'] for e in batch[7]] == [message, 'short']


def test_the_status_encoder_raises_the_warn_bit() -> None:
    # The Mirror's side of the compilation warning (#995): a status OER with the
    # bit set, decoded back through the client's own reader. Everything else
    # about the reply is identical -- the call SUCCEEDED -- so a test that only
    # compared lengths or error codes would pass either way.
    from seerdb.common.tns import decode_token_oer, encode_status
    from seerdb.common.tns_consts import TNS_OER_WARN_COMPILATION_ERROR

    plain = encode_status(3, cursor_id=7)
    warned = encode_status(3, cursor_id=7, compilation_warning=True)
    assert len(plain) == len(warned)
    assert decode_token_oer(plain, (0, [], []))[10] == 0
    decoded = decode_token_oer(warned, (0, [], []))
    assert decoded[10] & TNS_OER_WARN_COMPILATION_ERROR
    # and the warning rides ALONGSIDE an ordinary success: same code, rowcount,
    # cursor id.
    assert decoded[1] == 0
    assert decoded[2] == 7


def test_an_error_carries_what_the_call_managed() -> None:
    # An executemany whose batch aborts part-way really did apply the earlier
    # rows, and the count rides in the SAME OER field a success reports its own
    # count in. encode_error hard-coded 0 there, so a client asking what
    # happened was told nothing did (#998).
    from seerdb.common.tns import decode_token_oer, encode_error

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    plain = decode_token_oer(encode_error(1, 'ORA-00001: dup'), (0, [], []))
    assert plain[1] == 1
    assert plain[3][0] == 0  # nothing applied

    partial = decode_token_oer(
        encode_error(1, 'ORA-00001: dup', rowcount=3), (0, [], [])
    )
    # The count rides ALONGSIDE the error, not instead of it.
    assert partial[1] == 1
    assert partial[5] == 'ORA-00001: dup'
    assert partial[3][0] == 3


def test_the_oer_warn_bit_survives_the_decode() -> None:
    # Bit 0x20 of the OER's warn byte says the call CREATED a PL/SQL object that
    # compiled with errors. The call SUCCEEDED, so nothing else in the reply
    # differs -- the decoder used to skip that byte with its five neighbours,
    # and the condition vanished (#993). Built by patching the encoder's own
    # status frame, so the offset is the one the encoder actually writes.
    from seerdb.common.tns import decode_token_oer, encode_status
    from seerdb.common.tns_consts import TNS_OER_WARN_COMPILATION_ERROR

    clean = encode_status(0)
    decoded = decode_token_oer(clean, (0, [], []))
    assert decoded[10] == 0

    # The warn byte is the 6th of the six single-byte fields; find that run by
    # the sql_type byte the encoder leads it with, which is 0 for a status.
    warned = bytearray(clean)
    index = _oer_warn_byte_index(bytes(clean))
    warned[index] = TNS_OER_WARN_COMPILATION_ERROR
    decoded = decode_token_oer(bytes(warned), (0, [], []))
    assert decoded[10] & TNS_OER_WARN_COMPILATION_ERROR
    # and nothing else moved: same error code, same rowcount.
    assert decoded[1] == 0


def _oer_warn_byte_index(status: bytes) -> int:
    # Walk the OER the way the decoder does, and report where the warn byte sits.
    # Computed rather than hardcoded: a hardcoded offset would still pass if the
    # encoder's field order changed underneath it.
    from seerdb.common.tns import decode_ub4

    rest = status[1:]  # the TTI_OER token
    for _ in range(8):  # call_status, seq, rowcount, err, arr1, arr2, cursor, pos
        (_, rest) = decode_ub4(rest)
    return len(status) - len(rest) + 5


@pytest.mark.parametrize('version', [8, 14, 17])  # 12.2, 20.1, 23ai
def test_oer_decodes_back_at_a_12c_field_version(version: int) -> None:
    # A 12.1+ client reads an extended error number + rowcount ahead of the
    # message, and a 20.1+ client a SQL type + checksum too; the status, error
    # and end-of-fetch OERs all carry them under that version.
    from seerdb.common.tns import (
        _terminator,
        decode_token_oer,
        encode_error,
        encode_status,
    )

    with _at_field_version(version):
        status = decode_token_oer(encode_status(7, cursor_id=3), (0, [], []))
        error = decode_token_oer(
            encode_error(942, 'ORA-00942: table or view does not exist'), (0, [], [])
        )
        eof = decode_token_oer(_terminator(0, more=False), (0, [], []))
    assert status[1] == 0 and status[2] == 3 and status[3][0] == 7
    assert error[1] == 942 and 'ORA-00942' in error[5]
    assert eof[1] == 1403


def test_a_mirror_presenting_23ai_writes_the_oer_tail_to_a_lower_session() -> None:
    # A real 23ai ends the OER with a SQL type and a checksum even to a client
    # that negotiated 12.2, and the client reads them by the server's release.
    # A Mirror presenting 23ai has to do the same, or the two disagree on where
    # the message starts (#1145).
    from seerdb.common.tns import (
        _DECODE_SERVER_FIELD_VERSION,
        _ENCODE_SERVER_FIELD_VERSION,
        decode_token_oer,
        encode_error,
    )

    with _at_field_version(8):
        e_tok = _ENCODE_SERVER_FIELD_VERSION.set(24)
        d_tok = _DECODE_SERVER_FIELD_VERSION.set(24)
        try:
            error = decode_token_oer(
                encode_error(942, 'ORA-00942: table or view does not exist'),
                (0, [], []),
            )
        finally:
            _ENCODE_SERVER_FIELD_VERSION.reset(e_tok)
            _DECODE_SERVER_FIELD_VERSION.reset(d_tok)
    assert error[1] == 942
    assert error[5] == 'ORA-00942: table or view does not exist'


def test_describe_roundtrips_to_the_dual_column() -> None:
    # The DUMMY VARCHAR2(1) column of DUAL, encoded then decoded by the client.
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
        ]
    )
    (col,) = _decode_describe(payload)
    assert col['column_name'] == b'DUMMY'
    assert col['data_type'] == TNS_TYPE_VARCHAR
    assert col['data_length'] == 1
    assert col['max_size'] == 1
    assert col['charset'] == 873
    assert col['null_ok'] == 1


def test_describe_roundtrips_the_json_and_oson_flags() -> None:
    # The uds-flags bits that tell a client a column is native JSON, or a BLOB /
    # CLOB holding an OSON image it should decode rather than surface as a raw
    # LOB (#826). A plain column carries neither; the Mirror used to emit a zero
    # flags word for every column, so an OSON column read back as a LOB.
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'PLAIN', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            ),
            ColumnMeta(
                name=b'OSONCOL',
                data_type=TNS_TYPE_BLOB,
                data_length=4000,
                max_size=4000,
                is_oson=True,
            ),
            ColumnMeta(
                name=b'JSONCOL',
                data_type=TNS_TYPE_JSON,
                data_length=4000,
                max_size=4000,
                is_json=True,
            ),
        ]
    )
    plain, oson, native = _decode_describe(payload)
    assert (plain['is_json'], plain['is_oson']) == (False, False)
    assert (oson['is_json'], oson['is_oson']) == (False, True)
    assert (native['is_json'], native['is_oson']) == (True, False)


def test_oson_column_value_rides_inline_and_queues_no_lob() -> None:
    # A client re-types an is_oson column to LONG RAW and runs decode_oson over
    # the bytes, so the value belongs in the row itself: a LOB locator there is
    # read as LONG RAW and desyncs the row, and a LOB-queue entry would shift
    # every later LOB's position (#826).
    from seerdb.common.oson import encode_oson
    from seerdb.common.tns import encode_long_value_thin, oci_lob_contents

    image = encode_oson({'id': 6901, 'value': 'string 6901'})
    col = ColumnMeta(
        name=b'OSONCOL',
        data_type=TNS_TYPE_BLOB,
        data_length=4000,
        max_size=4000,
        is_oson=True,
    )
    assert oci_lob_contents([col], [(image,)]) == []
    assert encode_long_value_thin(image) in encode_rows([(image,)], [col])


def test_a_type_change_to_clob_keeps_the_column_inline() -> None:
    # Re-executing a cached cursor whose column turned from VARCHAR into a CLOB:
    # a real server reports the new LOB type but keeps sending the value the way
    # the client's variable still reads it -- inline as LONG, no locator and no
    # LOB read (#826). The reverse pairing (CLOB -> VARCHAR) is an ordinary
    # re-describe and must not be marked.
    from seerdb.common.tns import inline_long_after_type_change

    was_varchar = ColumnMeta(
        name=b'VALUE', data_type=TNS_TYPE_VARCHAR, data_length=15, max_size=15
    )
    now_clob = ColumnMeta(
        name=b'VALUE', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0
    )
    (adjusted,) = inline_long_after_type_change([now_clob], [was_varchar])
    assert adjusted.data_type == TNS_TYPE_CLOB  # the describe still says CLOB
    assert adjusted.inline_long_csfrm == was_varchar.csfrm
    # ... and it stays inline on every later re-execute, because the client's
    # variable is LONG from now on.
    (again,) = inline_long_after_type_change([now_clob], [adjusted])
    assert again.inline_long_csfrm == was_varchar.csfrm
    assert inline_long_after_type_change([was_varchar], [now_clob]) == [was_varchar]
    # A BLOB pairs with RAW, never with a character type.
    now_blob = ColumnMeta(
        name=b'VALUE', data_type=TNS_TYPE_BLOB, data_length=4000, max_size=0
    )
    assert inline_long_after_type_change([now_blob], [was_varchar]) == [now_blob]
    was_raw = ColumnMeta(
        name=b'VALUE', data_type=TNS_TYPE_RAW, data_length=15, max_size=15
    )
    assert (
        inline_long_after_type_change([now_blob], [was_raw])[0].inline_long_csfrm
        == was_raw.csfrm
    )


def test_an_inlined_clob_carries_the_previous_charset_form() -> None:
    # The charset form comes from the describe being REPLACED, not from the CLOB
    # that replaced it: a column that was NVARCHAR2 keeps arriving as UTF-16BE
    # even though the new CLOB describes itself as csfrm 1 (#826). Reading the
    # server's own csfrm handed the client half a character per byte.
    from seerdb.common.tns import (
        _CSFRM_NCHAR,
        encode_long_value_thin,
        inline_long_after_type_change,
        oci_lob_contents,
    )

    was_nvarchar = ColumnMeta(
        name=b'VALUE',
        data_type=TNS_TYPE_VARCHAR,
        data_length=30,
        max_size=30,
        csfrm=_CSFRM_NCHAR,
    )
    now_clob = ColumnMeta(
        name=b'VALUE', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0
    )
    (adjusted,) = inline_long_after_type_change([now_clob], [was_nvarchar])
    assert adjusted.inline_long_csfrm == _CSFRM_NCHAR
    row = encode_rows([('clob_4603',)], [adjusted])
    assert encode_long_value_thin('clob_4603'.encode('utf-16-be')) in row
    # An inlined column queues no LOB content -- the client issues no read for it.
    assert oci_lob_contents([adjusted], [('clob_4603',)]) == []


def test_a_define_execute_carries_one_oac_per_column() -> None:
    # A client fetching a LOB as string / bytes reads the describe, then
    # re-executes with the DEFINE option and one OAC per column saying what it
    # wants. Those OACs sit exactly where a bind's would and share its layout, so
    # the bind decoder reads them -- the Mirror used to skip the count and never
    # look (#826).
    from seerdb.common.tns import _DECODE_FIELD_VERSION
    from seerdb.common.tns_consts import TNS_TYPE_LONG

    # Byte-for-byte off a live capture (fv24): cursor 2, no SQL, no binds, one
    # define, options 0x8010 (NOT_PLSQL | DEFINE). The define asks for LONG (8)
    # in the database charset form -- this is an outputtypehandler fetching a
    # CLOB column as a string.
    captured = bytes.fromhex(
        '035e06000280100102000001010d0000000102047fffffff0000000000000001'
        '0101000001000000000000000000000000000000000102000000000001010000'
        '00000008010000047fffffff00000000020369010000'
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_exec(captured)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert (request.sql, request.cursor, request.bind_count) == ('', 2, 0)
    assert request.define_types == [(TNS_TYPE_LONG, 1)]


def test_a_define_of_a_lob_as_a_string_keeps_the_column_inline() -> None:
    # Given LONG (RAW) in a define, a real server sends the LOB's value inline in
    # the row rather than a locator, which is why such a client issues no LOB
    # read at all. A define that does not re-type the column leaves it alone
    # (#826).
    from seerdb.common.tns import inline_long_for_defines
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TNS_TYPE_LONGRAW

    clob = ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0)
    blob = ColumnMeta(name=b'B', data_type=TNS_TYPE_BLOB, data_length=4000, max_size=0)
    marked = inline_long_for_defines(
        [clob, blob], [(TNS_TYPE_LONG, 1), (TNS_TYPE_LONGRAW, 0)]
    )
    assert [col.inline_long_csfrm for col in marked] == [1, 0]
    # Defined as the LOBs they are: nothing changes, the locators stand.
    assert inline_long_for_defines(
        [clob, blob], [(TNS_TYPE_CLOB, 1), (TNS_TYPE_BLOB, 0)]
    ) == [clob, blob]
    # A CLOB pairs with the character types only, never with LONG RAW.
    assert inline_long_for_defines([clob], [(TNS_TYPE_LONGRAW, 0)]) == [clob]
    # An execute that carries no defines leaves every column alone.
    assert inline_long_for_defines([clob, blob], []) == [clob, blob]


def test_multiple_columns_and_not_null_roundtrip() -> None:
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'ID',
                data_type=TNS_TYPE_NUMBER,
                data_length=22,
                max_size=22,
                null_ok=0,
            ),
            ColumnMeta(
                name=b'NAME', data_type=TNS_TYPE_VARCHAR, data_length=30, max_size=30
            ),
        ]
    )
    cols = _decode_describe(payload)
    assert [c['column_name'] for c in cols] == [b'ID', b'NAME']
    assert cols[0]['data_type'] == TNS_TYPE_NUMBER
    assert cols[0]['null_ok'] == 0  # NOT NULL
    assert cols[1]['max_size'] == 30


def test_describe_fills_in_the_length_a_backend_cannot_report() -> None:
    # A zero buffer length is not a free "unknown": the client reads it as "this
    # column sends nothing at all" and its row decoder then consumes the wrong
    # bytes. A backend often cannot supply one -- the PEP 249 description tuple
    # reports no size for a temporal, interval or REF column -- so the describe
    # fills in what a real server reports (#690).
    #
    # The values are measured against live 10g, 11g, 21c and 23ai; the odd-looking
    # ones are what Oracle sends.
    expected = {
        TNS_TYPE_NUMBER: 22,
        TNS_TYPE_DATE: 1,
        TNS_TYPE_TIMESTAMP: 11,
        TNS_TYPE_TIMESTAMPTZ: 1,
        TNS_TYPE_TIMESTAMPLTZ: 11,
        TNS_TYPE_INTERVALYM: 1,
        TNS_TYPE_INTERVALDS: 1,
        TNS_TYPE_BFLOAT: 1,
        TNS_TYPE_BDOUBLE: 1,
        TNS_TYPE_REF: 2000,
        TNS_TYPE_CLOB: 4000,
        TNS_TYPE_BLOB: 4000,
        # A zero here made the client skip the column's byte entirely (#740).
        TNS_TYPE_BOOLEAN: 1,
        # A native JSON column measures the same 8200 a VECTOR does, and a zero
        # cost the same: the client read no bytes for it and took the OSON image
        # the row carries for the next message (#826).
        TNS_TYPE_JSON: 8200,
    }
    for data_type, length in expected.items():
        column = ColumnMeta(name=b'C', data_type=data_type, data_length=0, max_size=0)
        assert describe_wire_length(column) == length, data_type


def test_describe_keeps_a_length_the_backend_did_report() -> None:
    column = ColumnMeta(
        name=b'C', data_type=TNS_TYPE_TIMESTAMP, data_length=7, max_size=0
    )
    assert describe_wire_length(column) == 7


def test_describe_leaves_a_truthful_zero_alone() -> None:
    # `SELECT NULL AS x` describes a character column of zero length, and that
    # zero is true: the column really does carry no bytes. Filling one in there
    # would undo the fix for #682.
    for data_type in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_RAW):
        column = ColumnMeta(name=b'X', data_type=data_type, data_length=0, max_size=0)
        assert describe_wire_length(column) == 0, data_type


def test_an_interval_column_survives_the_round_trip() -> None:
    # End to end through the codec: a describe built from a backend that reported
    # no length, then a row decoded against it. Before #690 the decoder read the
    # column as always-NULL, consumed nothing, and desynced on the next token.
    from seerdb.common.tns import decode_packet, encode_query_response

    column = ColumnMeta(
        name=b'IVY', data_type=TNS_TYPE_INTERVALYM, data_length=0, max_size=0
    )
    blob = encode_query_response([column], [(IntervalYM(1, 6),)])
    decoded = decode_packet(blob, (None, None, []))
    assert decoded[4] == [[IntervalYM(1, 6)]]


def test_describe_carries_number_precision_and_scale() -> None:
    # A NUMBER(p, s) column's precision/scale must survive the describe so the
    # client can surface them in cursor.description (fields 4 and 5).
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'AMT',
                data_type=TNS_TYPE_NUMBER,
                data_length=22,
                max_size=22,
                precision=10,
                scale=2,
            )
        ]
    )
    col = _decode_describe(payload)[0]
    assert col['precision'] == 10
    assert col['data_scale'] == 2


def test_describe_carries_negative_scale() -> None:
    # A plain NUMBER (no declared scale) reports scale -127 on 11g, encoded as a
    # signed variable-length int (0x81 0x7f). The describe must survive it — a
    # real Oracle backend hits this on every unscaled NUMBER column.
    payload = encode_describe(
        [
            ColumnMeta(
                name=b'N',
                data_type=TNS_TYPE_NUMBER,
                data_length=22,
                max_size=22,
                precision=0,
                scale=-127,
            )
        ]
    )
    col = _decode_describe(payload)[0]
    assert col['data_scale'] == -127


def test_encode_rows_dual() -> None:
    col = ColumnMeta(
        name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
    )
    response = encode_describe([col]) + encode_rows([('X',)], [col]) + bytes([TTI_STA])
    columns, rows = _decode_response(response)
    assert [c['column_name'] for c in columns] == [b'DUMMY']
    assert rows == [['X']]


def test_encode_rows_multiple_with_null() -> None:
    cols = [
        ColumnMeta(name=b'A', data_type=TNS_TYPE_VARCHAR, data_length=5, max_size=5),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_VARCHAR, data_length=5, max_size=5),
    ]
    response = (
        encode_describe(cols)
        + encode_rows([('hi', 'yo'), ('lo', None)], cols)
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [['hi', 'yo'], ['lo', None]]


def test_encode_rows_large_values_chunk() -> None:
    from seerdb.common.tns_consts import TNS_TYPE_RAW

    # A VARCHAR2 / RAW value over the single-byte length (253) must chunk in the
    # 11g form so the client decodes it — the regression that surfaced as
    # "truncated DALC field" past 253 bytes.
    big_str = 'x' * 1000
    big_raw = bytes(range(256)) * 4  # 1024 bytes
    cols = [
        ColumnMeta(
            name=b'S', data_type=TNS_TYPE_VARCHAR, data_length=4000, max_size=4000
        ),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_RAW, data_length=2000, max_size=2000),
    ]
    response = (
        encode_describe(cols)
        + encode_rows([(big_str, big_raw)], cols)
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [[big_str, big_raw]]


def test_row_width_mismatch_raises() -> None:
    col = ColumnMeta(
        name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
    )
    with pytest.raises(InterfaceError):
        encode_rows([('X', 'extra')], [col])


def test_unsupported_value_type_raises() -> None:
    # A type the wire cannot carry raises NotSupportedError -- the DB-API's own
    # type for "this is not supported" -- and not a generic one. The Mirror keys
    # on it to answer a feature gap with ORA-03115 instead of ORA-00600, which
    # clients treat as fatal and which cost a whole session per gap (#875).
    from seerdb.common.exceptions import NotSupportedError

    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    with pytest.raises(NotSupportedError):
        encode_rows([(object(),)], [col])


def test_encode_error_reports_the_ora_code_and_message() -> None:
    from seerdb.common.tns import decode_token_oer, encode_error

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(
        encode_error(942, 'ORA-00942: table or view does not exist'), (0, [], [])
    )
    assert result[1] == 942  # ErrCode
    assert 'ORA-00942' in result[5]  # Message


def test_more_rows_terminator_carries_cursor_id() -> None:
    from seerdb.common.tns import decode_token_oer, encode_more_rows

    # The "more rows" status: call_status 1, no error, and the cursor id — what
    # the client's _drain_cursor keys on to issue follow-up TTI_FETCH calls.
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(encode_more_rows(9), (0, [], []))
    assert result[0] == 1  # CallStatus
    assert result[1] == 0  # ErrCode (not 1403 — the cursor is not drained)
    assert result[2] == 9  # CursorId


def test_end_of_fetch_is_built_from_oer_fields() -> None:
    # _END_OF_FETCH is the ORA-01403 terminator, built by _encode_oer rather than
    # stored. It must stay byte-identical to the live 11g capture and decode as the
    # 1403 "no data found" status the client keys on to stop fetching.
    from seerdb.common.tns import _END_OF_FETCH, decode_token_oer

    assert (
        _END_OF_FETCH
        == bytes.fromhex(
            '0401010104010102057b00000101010e03000000000000000000000000070001010000000019'
        )
        + b'ORA-01403: no data found\n'
    )
    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    result = decode_token_oer(_END_OF_FETCH, (0, [], []))
    assert result[0] == 1  # CallStatus
    assert result[1] == 1403  # ErrCode — cursor drained


def test_parse_fetch_extracts_cursor_and_count() -> None:
    from seerdb.common.tns import encode_dictionary_fetch, parse_fetch

    msg = encode_dictionary_fetch(
        {'seq': 4, 'field_version': 6, 'cursor': 7, 'fetch': 50}
    )
    req = parse_fetch(msg)
    assert req.cursor == 7
    assert req.fetch == 50


def test_encode_rows_number_values() -> None:
    from decimal import Decimal

    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    response = (
        encode_describe([col])
        + encode_rows([(1,), (-7,), (0,), (3.14,), (1000000,)], [col])
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [[1], [-7], [0], [Decimal('3.14')], [1000000]]


def test_encode_rows_binary_float_and_double() -> None:
    from seerdb.common.tns_consts import TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT

    # A BINARY_DOUBLE / BINARY_FLOAT column carries the IEEE-754 value (Python
    # float), not a base-100 NUMBER — the client decodes it back to float.
    dcol = ColumnMeta(name=b'D', data_type=TNS_TYPE_BDOUBLE, data_length=8, max_size=8)
    fcol = ColumnMeta(name=b'F', data_type=TNS_TYPE_BFLOAT, data_length=4, max_size=4)
    response = (
        encode_describe([dcol, fcol])
        + encode_rows([(3.5, 1.5), (-2.25, -0.5)], [dcol, fcol])
        + bytes([TTI_STA])
    )
    cols, rows = _decode_response(response)
    assert rows == [[3.5, 1.5], [-2.25, -0.5]]
    assert all(isinstance(v, float) for row in rows for v in row)


def test_encode_rows_high_precision_decimal() -> None:
    from decimal import Decimal

    # A NUMBER column carrying Decimals beyond float precision: the exact
    # base-100 encoder round-trips every significant digit.
    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    values = [
        Decimal('1.234567890123456789'),
        Decimal('-1.234567890123456789'),
        Decimal('123456789012345678901234567890'),
        Decimal('0.00000000000000000001'),
    ]
    response = (
        encode_describe([col])
        + encode_rows([(v,) for v in values], [col])
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [[v] for v in values]


def test_encode_rows_date_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_DATE

    col = ColumnMeta(name=b'D', data_type=TNS_TYPE_DATE, data_length=7, max_size=7)
    response = (
        encode_describe([col])
        + encode_rows(
            [
                (datetime.datetime(2024, 1, 15, 13, 30, 45),),
                (datetime.date(2020, 12, 31),),
            ],
            [col],
        )
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [
        [datetime.datetime(2024, 1, 15, 13, 30, 45)],
        [datetime.datetime(2020, 12, 31, 0, 0)],
    ]


def test_encode_rows_timestamp_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMP

    # A TIMESTAMP column is fixed at 11 bytes and keeps the sub-second part; a
    # value with no microseconds still encodes 11 bytes (nanos == 0).
    col = ColumnMeta(
        name=b'TS', data_type=TNS_TYPE_TIMESTAMP, data_length=11, max_size=11
    )
    response = (
        encode_describe([col])
        + encode_rows(
            [
                (datetime.datetime(2024, 1, 15, 13, 30, 45, 123456),),
                (datetime.datetime(2020, 12, 31, 23, 59, 59),),
            ],
            [col],
        )
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [
        [datetime.datetime(2024, 1, 15, 13, 30, 45, 123456)],
        [datetime.datetime(2020, 12, 31, 23, 59, 59)],
    ]


def test_encode_rows_timestamptz_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMPTZ

    # A TIMESTAMPTZ column is 13 bytes and carries the UTC offset. A naive value
    # is assumed to be UTC (a bare wall-clock in a TZ column).
    col = ColumnMeta(
        name=b'TZ', data_type=TNS_TYPE_TIMESTAMPTZ, data_length=13, max_size=13
    )
    utc = datetime.timezone.utc
    plus2 = datetime.timezone(datetime.timedelta(hours=2))
    response = (
        encode_describe([col])
        + encode_rows(
            [
                (datetime.datetime(2024, 1, 15, 13, 30, 45, 123456, tzinfo=utc),),
                (datetime.datetime(2024, 6, 1, 9, 0, 0, tzinfo=plus2),),
                (datetime.datetime(2020, 12, 31, 23, 59, 59),),  # naive → UTC
            ],
            [col],
        )
        + bytes([TTI_STA])
    )
    _, rows = _decode_response(response)
    assert rows == [
        [datetime.datetime(2024, 1, 15, 13, 30, 45, 123456, tzinfo=utc)],
        [datetime.datetime(2024, 6, 1, 9, 0, 0, tzinfo=plus2)],
        [datetime.datetime(2020, 12, 31, 23, 59, 59, tzinfo=utc)],
    ]


def test_encode_rows_timestamp_ltz_values() -> None:
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMPLTZ

    # TIMESTAMP WITH LOCAL TIME ZONE is the 11-byte TIMESTAMP shape, not the
    # 13-byte TZ one and not a 7-byte DATE: the server normalises it to the
    # session zone and sends no offset. Encoding it as a DATE dropped the
    # fractional seconds SILENTLY -- .123456 came back .0, no error (#826).
    col = ColumnMeta(
        name=b'LTZ', data_type=TNS_TYPE_TIMESTAMPLTZ, data_length=11, max_size=11
    )
    values = [
        (datetime.datetime(2024, 1, 15, 13, 30, 45, 123456),),
        (datetime.datetime(2023, 5, 4, 22, 30, 2, 500000),),
        (datetime.datetime(2020, 12, 31, 23, 59, 59),),
    ]
    body = encode_rows(values, [col])
    response = encode_describe([col]) + body + bytes([TTI_STA])
    _, rows = _decode_response(response)
    assert rows == [list(v) for v in values]
    # And the column really is 11 bytes wide on the wire, like a TIMESTAMP.
    assert body.count(bytes([11])) >= len(values)


def test_parse_exec_extracts_bind_values() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    msg = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 15,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'select :1, :2 from dual',
                'bind': ['hi', 42],
                'batch': [],
                'def': [],
            },
        }
    )
    req = parse_exec(msg)
    assert req.sql == 'select :1, :2 from dual'
    assert req.bind_count == 2
    assert req.binds == ['hi', 42]


def test_parse_exec_reads_the_autocommit_flag() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    def dml(auto: int):
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',  # DML — the options word carries autocommit
                    'auto': auto,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': 0,
                    'query': 'insert into t values (:1)',
                    'bind': ['x'],
                    'batch': [],
                    'def': [],
                },
            }
        )

    # The client sets the commit-on-success option (0x100) in autocommit mode.
    assert parse_exec(dml(1)).autocommit is True
    assert parse_exec(dml(0)).autocommit is False


def test_parse_exec_extracts_array_dml_rows() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    # executemany: the first row is `bind`, the rest ride in `batch`. parse_exec
    # must recover every iteration's values, in order.
    msg = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'change',
                'auto': 1,
                'fetch': 0,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'insert into t values (:1, :2)',
                'bind': [1, 'a'],
                'batch': [[2, 'b'], [3, 'c']],
                'def': [],
            },
        }
    )
    req = parse_exec(msg)
    assert req.bind_rows == [[1, 'a'], [2, 'b'], [3, 'c']]
    assert req.binds == [1, 'a']  # first row remains the single-execute view


# A live sqlplus 11.2 OCI (deadbeef dialect) OALL8 execute — the user's typed
# query. Captured from sqlplus 11.2 <-> XE 11.2 (#265).
_OCI_EXEC_USER = bytes.fromhex(
    '035e156180000000000000feffffffffffffff3600000000000000feffffffffffffff'
    '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
    '0000000000000000000000000000000000000000000000000000000000feffffffffff'
    'ffff0000000000000000fefffffffffffffffefffffffffffffff83514260000000000'
    '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
    '00000000000000000000000000000000000000001273656c65637420312066726f6d20'
    '6475616c01000000000000000000000000000000000000000000000000000000010000'
    '000000000000000000000000000000000000000000'
)
# sqlplus's own internal query (SELECT USER FROM DUAL) — NUL-terminated, unlike
# the user's typed one; the parse must strip the trailing NUL.
_OCI_EXEC_INTERNAL = bytes.fromhex(
    '035e066180000000000000feffffffffffffff4200000000000000feffffffffffffff'
    '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
    '0000000000000000000000000000000000000000000000000000000000feffffffffff'
    'ffff0000000000000000fefffffffffffffffefffffffffffffff83514260000000000'
    '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
    '00000000000000000000000000000000000000001653454c4543542055534552204652'
    '4f4d204455414c00010000000000000000000000000000000000000000000000000000'
    '00010000000000000000000000000000000000000000000000'
)


def test_parse_exec_oci_extracts_the_user_query() -> None:
    req = parse_exec_oci(_OCI_EXEC_USER)
    assert req.sql == 'select 1 from dual'
    assert req.cursor == 0  # a new statement


def test_parse_exec_oci_strips_the_internal_query_nul() -> None:
    # sqlplus NUL-terminates SELECT USER FROM DUAL; the trailing NUL must not
    # reach the backend.
    req = parse_exec_oci(_OCI_EXEC_INTERNAL)
    assert req.sql == 'SELECT USER FROM DUAL'
    assert '\x00' not in req.sql


# sqlplus 23.26's `select 1 + 1 as two from dual` to a live 18c: the narrow
# preamble, with the 12c band's 64 extra zero bytes ahead of the SQL (#1282).
_OCI_EXEC_18C = bytes.fromhex(
    '035e0b6180000000000000feffffffffffffff57000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000001d73656c6563742031202b203120617320'
    '74776f2066726f6d206475616c01000000000000000000000000000000000000'
    '0000000000000000000100000000000000008000000000000000000000000000'
    '00'
)


def test_parse_exec_oci_reads_the_12c_band_layout() -> None:
    # The session's field version says which layout the statement is in: the
    # inserted bytes are zeros, so the wire alone cannot tell (#1282).
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        req = parse_exec_oci(_OCI_EXEC_18C)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert req.sql == 'select 1 + 1 as two from dual'
    assert req.cursor == 0
    # Read in the 11.2 layout, the SQL is not where the header says it is.
    with pytest.raises(InterfaceError):
        parse_exec_oci(_OCI_EXEC_18C)


def test_parse_exec_oci_rejects_a_non_oci_message() -> None:
    with pytest.raises(InterfaceError):
        parse_exec_oci(b'\x03\x5e\x06not the oci shape' + b'\x00' * 200)


# The same two queries from sqlplus 23.26, which writes the preamble's scalar
# slots as ub4 where 11.2 wrote ub8 — 20 bytes shorter, so the SQL sits at 176
# rather than 196 (#866). Captured sqlplus 23.26 <-> XE 11.2 through
# tools/capture_proxy.py.
_OCI_EXEC_USER_NARROW = bytes.fromhex(
    '035e0b6180000000000000feffffffffffffff36000000feffffffffffffff0d000000'
    'fefffffffffffffffeffffffffffffff00000000010000000000000000000000000000'
    '00000000000000000000000000feffffffffffffff0000000000000000feffffffffff'
    'fffffefffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffe'
    'ffffffffffffff00000000000000000000000000000000000000000000000000000000'
    '1273656c65637420312066726f6d206475616c01000000000000000000000000000000'
    '0000000000000000000000000100000000000000008000000000000000000000000000'
    '00'
)
_OCI_EXEC_INTERNAL_NARROW = bytes.fromhex(
    '035e066180000000000000feffffffffffffff17010000feffffffffffffff0d000000'
    'fefffffffffffffffeffffffffffffff00000000010000000000000000000000000000'
    '00000000000000000000000000feffffffffffffff0000000000000000feffffffffff'
    'fffffefffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffe'
    'ffffffffffffff00000000000000000000000000000000000000000000000000000000'
    '5d53454c454354204445434f444528555345522c20275853244e554c4c272c20205853'
    '5f5359535f434f4e54455854282758532453455353494f4e272c27555345524e414d45'
    '27292c2055534552292046524f4d205359532e4455414c000100000000000000000000'
    '0000000000000000000000000000000000010000000000000000800000000000000000'
    '000000000000'
)


def test_parse_exec_oci_reads_the_narrow_preamble() -> None:
    # sqlplus 23.26's shorter header must give the same SQL as 11.2's longer one.
    req = parse_exec_oci(_OCI_EXEC_USER_NARROW)
    assert req.sql == 'select 1 from dual'
    assert req.cursor == 0
    assert req.bind_count == 0


def test_parse_exec_oci_narrow_preamble_strips_the_internal_query_nul() -> None:
    # The login probe whose row sqlplus needs — read with the wide offsets it
    # came back as a no-rows status and sqlplus reported SP2-0642 (#866).
    req = parse_exec_oci(_OCI_EXEC_INTERNAL_NARROW)
    assert req.sql.startswith('SELECT DECODE(USER,')
    assert req.sql.endswith('FROM SYS.DUAL')
    assert '\x00' not in req.sql


# The same `EXEC :n := 42` PL/SQL block from sqlplus 23.26. The shrinking slots
# are spread through the header, so the bind count moves by 12 where the SQL
# moves by 20 — read with one global shift it came back as 0xFFFFFFFE (an
# indicator) and sqlplus PRINT reported ORA-01008 (#866).
_OCI_EXEC_OUT_BIND_NARROW = bytes.fromhex(
    '035e042904040000000000feffffffffffffff3c000000feffffffffffffff0d000000'
    'fefffffffffffffffeffffffffffffff000000000100000000000000feffffffffffff'
    'ff010000000000000000000000feffffffffffffff0000000000000000feffffffffff'
    'fffffefffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffe'
    'ffffffffffffff00000000000000000000000000000000000000000000000000000000'
    '14626567696e203a6e203a3d2034323b20656e643b0100000001000000000000000000'
    '0000000000000000000000000000080000000000000000800000000000000000000000'
    '0000000102030000160000000000000000000000000000000000000000000000000000'
    '00000000000000000007fd01'
)


def test_parse_exec_oci_narrow_preamble_reads_the_bind_count() -> None:
    req = parse_exec_oci(_OCI_EXEC_OUT_BIND_NARROW)
    assert req.sql == 'begin :n := 42; end;'
    assert req.bind_count == 1
    # The OUT bind rides as the `fd 01` absent-value marker, typed by its OAC.
    assert req.binds == [None]
    assert req.bind_meta == [(TNS_TYPE_NUMBER, 22)]


# sqlplus 23.26's `select 1 from dual` (12c band), once with NLS_LANG set to
# ...AL32UTF8 -- the database's own character set -- and once to ...UTF8. The
# header's SQL length is the byte length for the first, three times it for the
# second (#1427).
_OCI_EXEC_SELECT1_AL32UTF8 = bytes.fromhex(
    '035e046180000000000000feffffffffffffff12000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000001273656c65637420312066726f6d206475'
    '616c010000000000000000000000000000000000000000000000000000000100'
    '00000000000000800000000000000000000000000000'
)
_OCI_EXEC_SELECT1_UTF8 = bytes.fromhex(
    '035e0a6180000000000000feffffffffffffff36000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000001273656c65637420312066726f6d206475'
    '616c010000000000000000000000000000000000000000000000000000000100'
    '00000000000000800000000000000000000000000000'
)


def test_parse_exec_oci_reads_the_sql_whatever_the_client_character_set() -> None:
    # Read as three times the byte length always, an AL32UTF8 client's
    # statement failed the length check, and every statement it ran was answered
    # with a bare success: SP2-0642 from sqlplus (#1427).
    from seerdb.common.tns import _DECODE_FIELD_VERSION
    from seerdb.common.tns_consts import FIELD_VERSION_12_1

    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        assert _OCI_EXEC_SELECT1_AL32UTF8[19] == 18  # the byte length
        assert _OCI_EXEC_SELECT1_UTF8[19] == 54  # three times it
        for request in (_OCI_EXEC_SELECT1_AL32UTF8, _OCI_EXEC_SELECT1_UTF8):
            assert parse_exec_oci(request).sql == 'select 1 from dual'
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_parse_exec_oci_rejects_an_unknown_preamble_width() -> None:
    # Neither indicator position holds — refuse rather than read a garbage SQL
    # from whichever offset happens to be in range.
    broken = bytearray(_OCI_EXEC_USER_NARROW)
    broken[23:31] = b'\x00' * 8
    with pytest.raises(InterfaceError):
        parse_exec_oci(bytes(broken))


# A live sqlplus 11.2 `EXEC :n := 42` — a PL/SQL block with one NUMBER OUT bind.
# The wire carries no bind direction: the OUT bind rides with the 2-byte `fd 01`
# placeholder in its value slot (the tail `... 07 fd 01`), and its OAC gives the
# type (0x02 NUMBER) + max size (0x16 = 22). Captured sqlplus 11.2 <-> XE 11.2.
_OCI_EXEC_OUT_BIND = bytes.fromhex(
    '035e152904040000000000feffffffffffffff4200000000000000feffffffffffffff'
    '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
    '0000000000feffffffffffffff01000000000000000000000000000000feffffffffff'
    'ffff0000000000000000fefffffffffffffffeffffffffffffff4871cd2b0000000000'
    '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
    '000000000000000000000000000000000000000016424547494e203a6e203a3d203432'
    '3b20454e443b0a00010000000100000000000000000000000000000000000000000000'
    '0008000000000000000000000000000000000000000000000001020300001600000000'
    '0000000000000000000000000000000000000000000000000000000000000007fd01'
)


def test_parse_exec_oci_out_bind_decodes_none_and_carries_meta() -> None:
    # A PL/SQL block's OUT bind (sqlplus VARIABLE / EXEC) has no input value — the
    # `fd 01` placeholder decodes to None so the backend is not fed a garbage value,
    # while bind_meta carries the (type, max_size) the OUT path needs (#265).
    req = parse_exec_oci(_OCI_EXEC_OUT_BIND)
    assert req.sql == 'BEGIN :n := 42; END;\n'
    assert req.bind_count == 1
    assert req.binds == [None]  # not the garbage the raw value used to decode to
    assert req.bind_meta == [(2, 22)]  # NUMBER (type 2), 22-byte buffer


# A live sqlplus 11.2 `DESCRIBE seer_n` reply body (the packet's TTC content, after
# the 8-byte header + 2-byte data flags) — one NUMBER(10,2) column `C` in schema
# PYO. Captured sqlplus 11.2 <-> XE 11.2; the generator reproduces it byte-for-byte.
_OCI_DESCRIBE_SEER_N = bytes.fromhex(
    '0801000100000027010700000007787e09020c281b00000000030000000350594f06000000'
    '06534545525f4e44c50100000000000000000000010000007244c501000000000001000000'
    'be01000000270b0700000007787e09020c281b000000000000000000000000000000000000'
    '000000010000000b0102000000be0100000027000700000007787e09020c281b0200000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000100000027090700000007787e09020c281b02'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000010000005c160002000100000001430a02010000000000000000'
    '00000000000000000000000000000000000000000000002400000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000010004000000'
    'ca140001000000000900000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000405000000130001010000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000001500000100000036010000000000000000000000000000'
    '20f6310a000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000'
)


def test_encode_describe_reply_oci_matches_live_11g() -> None:
    # The sqlplus `DESCRIBE` reply is generated field-by-field — computed meaningful
    # fields (type, size, precision, scale, nullability), carried opaque structure —
    # and reproduces the live 11g reply byte-for-byte for a NUMBER(10,2) column.
    from seerdb.common.tns import encode_describe_reply_oci

    col = ColumnMeta(
        name=b'C',
        data_type=TNS_TYPE_NUMBER,
        data_length=22,
        max_size=22,
        precision=10,
        scale=2,
        null_ok=1,
    )
    # The describe timestamp is generated (the current time) in production; pin it
    # to the capture's date here so the rest of the reply is checked byte-for-byte
    # against the live 11g bytes.
    # The capture's trailing OER carries its own counter (19) and the sequence of
    # the DESCRIBE call it answered (21) at offset 49 (#884).
    token = _ENCODE_OCI_CALL_SEQ.set(0x15)
    try:
        reply = encode_describe_reply_oci(
            [col],
            schema=b'PYO',
            table=b'SEER_N',
            timestamp=bytes.fromhex('787e09020c281b'),
        )
    finally:
        _ENCODE_OCI_CALL_SEQ.reset(token)
    assert reply == _OCI_DESCRIBE_SEER_N


def _desc_block(col: ColumnMeta) -> dict:
    # A DESCRIBE reply's block for ``col`` as its last column, read back by its
    # schema (_OCI_DESC_BLOCK) at 11.2.
    from seerdb.common.tns import _OCI_DESC_BLOCK_FROM_OCI, _oci_desc_block

    block = _oci_desc_block(col, last=True, timestamp=bytes(7))
    given = {'has_mark_zero': True, 'oci_12c': False, 'more': 0, 'last': True}
    (fields, rest) = _OCI_DESC_BLOCK_FROM_OCI(block, given)
    assert rest == b''
    return fields


def test_encode_describe_reply_oci_multicolumn_frames_each_column() -> None:
    # A multi-column reply carries the column count (header N+1, trailer N) and one
    # block per column, with the meaningful fields per type.
    from seerdb.common.tns import _OCI_DESC_HEAD_FROM_OCI, encode_describe_reply_oci

    cols = [
        ColumnMeta(name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        ColumnMeta(name=b'V', data_type=TNS_TYPE_VARCHAR, data_length=30, max_size=30),
    ]
    reply = encode_describe_reply_oci(cols, schema=b'PYO', table=b'T')
    # The header's column-count field is N+1.
    (head, _rest) = _OCI_DESC_HEAD_FROM_OCI(reply, {'oci_12c': False})
    assert (head['table'], head['column_count_plus_one']) == (b'T', 3)


def test_sqlplus_10_2_gets_the_narrower_describe_reply() -> None:
    # 11g's DESCRIBE <table> reply to sqlplus 10.2 is a byte shorter per column
    # and one in the trailer frame than to 11.2 -- 1217 against 1222 bytes for
    # a 4-column table (#1764): each block lacks the zero behind its 0x24 mark,
    # so a non-last column's describe-time entry sits a byte earlier.
    from seerdb.common.tns import (
        _OCI_DESC_TS_ENTRY_PRE,
        encode_describe_reply_oci,
    )
    from seerdb.common.tns_consts import (
        FIELD_VERSION_10_2,
        FIELD_VERSION_11_2,
        TNS_TYPE_DATE,
    )

    cols = [
        ColumnMeta(name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        ColumnMeta(name=b'V', data_type=TNS_TYPE_VARCHAR, data_length=30, max_size=30),
        ColumnMeta(name=b'D', data_type=TNS_TYPE_DATE, data_length=7, max_size=7),
    ]
    stamp = bytes.fromhex('787e0a0d0b2a19')
    replies = {}
    for fv in (FIELD_VERSION_11_2, FIELD_VERSION_10_2):
        with _at_field_version(fv):
            replies[fv] = encode_describe_reply_oci(
                cols, schema=b'PYO', table=b'T', timestamp=stamp
            )
    wide, narrow = replies[FIELD_VERSION_11_2], replies[FIELD_VERSION_10_2]
    assert len(narrow) == len(wide) - len(cols) - 1

    # The first column's describe-time entry, a byte nearer its name (the
    # header carries one too, which does not move).
    def entry_after_name(reply: bytes) -> int:
        name = reply.find(b'ID', reply.find(b'PYO') + 40)
        return reply.find(_OCI_DESC_TS_ENTRY_PRE, name) - name

    assert entry_after_name(narrow) == entry_after_name(wide) - 1


def test_national_char_values_and_describe_ride_as_utf16be() -> None:
    # NCHAR / NVARCHAR2 (csfrm 2) go on the wire as UTF-16BE (AL16UTF16), and the
    # describe metadata is sized so sqlplus renders NCHAR(3) and the client decodes
    # the value as UTF-16 — verified against live 11g.
    from seerdb.common.tns import (
        _OCI_DCB_CHAR_SEMANTICS_FLAG,
        _OCI_DCB_CHAR_SEMANTICS_OFF,
        AL16UTF16_CHARSET,
        _encode_dcb_column_oci,
        _national_wire_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_CHAR

    # NCHAR(5): 10-byte UTF-16 buffer, 5-char declared length.
    nchar = ColumnMeta(
        name=b'A',
        data_type=TNS_TYPE_CHAR,
        data_length=10,
        max_size=5,
        charset=AL16UTF16_CHARSET,
        csfrm=2,
    )
    plain = ColumnMeta(
        name=b'B',
        data_type=TNS_TYPE_CHAR,
        data_length=4,
        max_size=4,
        csfrm=1,
    )

    # 1) values: national -> UTF-16BE bytes; ordinary passes through.
    assert _national_wire_value('abc', nchar) == 'abc'.encode('utf-16-be')
    assert _national_wire_value('abc', plain) == 'abc'
    assert _national_wire_value(None, nchar) is None

    # 2) the SELECT DCB flags character-length semantics for national only.
    dcb_n = _encode_dcb_column_oci(nchar, 0, first=True)
    dcb_p = _encode_dcb_column_oci(plain, 0, first=True)
    assert dcb_n[_OCI_DCB_CHAR_SEMANTICS_OFF] == _OCI_DCB_CHAR_SEMANTICS_FLAG
    assert dcb_p[_OCI_DCB_CHAR_SEMANTICS_OFF] == 0

    # 3) the DESCRIBE reply carries the byte length + national flag + char length.
    n_block, p_block = _desc_block(nchar), _desc_block(plain)
    assert n_block['size'] == 10  # byte length; sqlplus halves it via the flag
    assert n_block['precision'] == 0x80  # national flag
    assert n_block['scale'] == 5  # character length
    assert p_block['size'] == 4  # ordinary char keeps its byte size unchanged
    assert p_block['precision'] == 0


def test_describe_reply_lays_out_interval_precisions() -> None:
    # sqlplus renders INTERVAL precisions from the describe block's precision/scale
    # bytes, which are laid out per family (verified against live 11g):
    #   YEAR TO MONTH -> the year precision in BOTH bytes (YEAR(3) -> 03 03);
    #   DAY TO SECOND -> swapped: precision = SECOND fractional (col.scale),
    #                    scale = DAY leading (col.precision) (DAY(2) SEC(6) -> 06 02).
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM

    # INTERVAL YEAR(3) TO MONTH: client carries the year precision in `precision`.
    ym = ColumnMeta(
        name=b'E',
        data_type=TNS_TYPE_INTERVALYM,
        data_length=5,
        max_size=5,
        precision=3,
        scale=0,
    )
    assert (_desc_block(ym)['precision'], _desc_block(ym)['scale']) == (3, 3)

    # INTERVAL DAY(2) TO SECOND(6): client carries day in `precision`, second in
    # `scale`; the describe swaps them.
    ds = ColumnMeta(
        name=b'F',
        data_type=TNS_TYPE_INTERVALDS,
        data_length=11,
        max_size=11,
        precision=2,
        scale=6,
    )
    assert _desc_block(ds)['precision'] == 6  # SECOND fractional
    assert _desc_block(ds)['scale'] == 2  # DAY leading


def test_describe_reply_puts_timestamp_precision_in_the_precision_field() -> None:
    # A real 11g DESCRIBE reports a TIMESTAMP's fractional-seconds precision in the
    # precision field (TIMESTAMP(6) -> 06 06), and sqlplus renders TIMESTAMP(N)
    # from it. The client carries that precision in `scale` (precision 0), so the
    # describe block mirrors scale into precision for TIMESTAMP types — while a
    # NUMBER keeps its own precision and scale distinct.
    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMP

    ts = ColumnMeta(
        name=b'TS',
        data_type=TNS_TYPE_TIMESTAMP,
        data_length=11,
        max_size=11,
        precision=0,
        scale=6,
    )
    num = ColumnMeta(
        name=b'N',
        data_type=TNS_TYPE_NUMBER,
        data_length=22,
        max_size=22,
        precision=8,
        scale=2,
    )

    # Mirrored from scale for TIMESTAMP; NUMBER keeps its own precision.
    assert (_desc_block(ts)['precision'], _desc_block(ts)['scale']) == (6, 6)
    assert (_desc_block(num)['precision'], _desc_block(num)['scale']) == (8, 2)


def test_parse_describe_oci_extracts_the_object_name() -> None:
    from seerdb.common.tns import parse_describe_oci

    # `03 77 <seq> <indicator/len fields> <ub4 flag> <ub1 namelen> <name>`
    req = (
        bytes.fromhex('037715feffffffffffffff1b0000000000000000000000000200000009')
        + b'seer_desc'
    )
    assert parse_describe_oci(req) == 'seer_desc'


def test_encode_describe_oci_roundtrips_the_meaningful_fields() -> None:
    # The thin client can't parse the OCI describe, so round-trip through the
    # codec's own reader: every meaningful field survives (#265).
    from seerdb.common.tns import _decode_describe_oci, encode_describe_oci

    cols = [
        ColumnMeta(
            name=b'DUMMY',
            data_type=TNS_TYPE_VARCHAR,
            data_length=1,
            max_size=1,
            charset=873,
            csfrm=1,
        ),
        ColumnMeta(
            name=b'1',
            data_type=TNS_TYPE_NUMBER,
            data_length=2,
            max_size=22,
            precision=0,
            scale=-127,
        ),
    ]
    back = _decode_describe_oci(encode_describe_oci(cols))
    assert [c['name'] for c in back] == [b'DUMMY', b'1']
    assert back[0]['data_type'] == TNS_TYPE_VARCHAR
    assert back[0]['charset'] == 873
    assert back[1]['data_type'] == TNS_TYPE_NUMBER
    assert back[1]['scale'] == -127  # a NUMBER literal's floating scale


def test_encode_dcb_column_oci_reproduces_the_live_column_block() -> None:
    # The whole 63-byte per-column block, byte-for-byte against the real 11g
    # describe for `select 1 from dual` (the NUMBER '1' column). This is ground
    # truth from the wire, not a hand-derived fixture — an earlier hand-typed
    # fixture hid a one-byte field shift that a live sqlplus caught (#265).
    from seerdb.common.tns import _encode_dcb_column_oci

    captured = bytes.fromhex(
        '51010200008102000000000000000000000000000000000000000000000000'
        '0000000000000000000000010101000000013100000000000000000000000000'
    )
    mine = _encode_dcb_column_oci(
        ColumnMeta(
            name=b'1',
            data_type=TNS_TYPE_NUMBER,
            data_length=2,
            max_size=0,
            precision=0,
            scale=-127,
        ),
        position=1,
        first=True,
    )
    assert mine == captured


def test_sqlplus_10_2_gets_the_narrower_describe() -> None:
    # 11g answers sqlplus 10.2 with a describe 3 + 4 per column + 4 bytes
    # shorter than it sends 11.2 (#1764): the preamble's length is a ub1, each
    # column's post-name block 9 bytes not 13, and the trailer lacks the zero
    # ub4 ahead of its marker (the LOB describe's trailer too).
    from seerdb.common.tns import (
        _OCI_RXH_FROM_OCI,
        _oci_dcb_tail,
        _oci_lob_describe_tail,
        encode_describe_oci,
    )
    from seerdb.common.tns_consts import (
        FIELD_VERSION_10_2,
        FIELD_VERSION_11_2,
        TNS_TYPE_CHAR,
        TNS_TYPE_NUMBER,
    )

    cols = [
        ColumnMeta(name=b'ONE', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        ColumnMeta(name=b'S', data_type=TNS_TYPE_CHAR, data_length=3, max_size=3),
        ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
    ]
    with _at_field_version(FIELD_VERSION_11_2):
        wide = encode_describe_oci(cols)
        wide_tail, wide_lob = _oci_dcb_tail(3), _oci_lob_describe_tail()
    with _at_field_version(FIELD_VERSION_10_2):
        narrow = encode_describe_oci(cols)
        tail, lob = _oci_dcb_tail(3), _oci_lob_describe_tail()
    assert wide[:5] == bytes.fromhex('1017000000')
    assert narrow[:2] == bytes.fromhex('1017')
    assert len(narrow) == len(wide) - 3 - 4 * len(cols)
    # Column spacing as 11g sends it to 10.2: 61 bytes from ONE's name to S's,
    # 59 from S's to N's (11.2: 65 and 63).
    names = [
        narrow.find(b'\x03ONE'),
        narrow.find(b'\x01S\x00'),
        narrow.find(b'\x01N\x00'),
    ]
    assert [names[1] - names[0], names[2] - names[1]] == [61, 59]
    assert (len(wide_tail), len(tail)) == (83, 79)
    # The row header, carrying the column count, four bytes earlier.
    (rxh, rest) = _OCI_RXH_FROM_OCI(tail[29:])
    assert (rxh['unpinned_2'], rxh['unpinned_4'], rest) == (0x22, 3, b'')
    assert (len(wide_lob), len(lob)) == (33, 29)


def test_encode_describe_oci_maxrowsize_is_nonzero() -> None:
    # The thick/OCI client allocates a row buffer of the DCB max-row-size; a zero
    # there overflows and segfaults sqlplus, so it must sum the column widths
    # (the thin client ignores the field) (#265).
    import struct

    from seerdb.common.tns import _OCI_DCB_PREAMBLE_LEN, encode_describe_oci

    col = ColumnMeta(name=b'1', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)
    payload = encode_describe_oci([col])
    off = 1 + 4 + _OCI_DCB_PREAMBLE_LEN  # token + preamble-len + preamble
    assert struct.unpack('<I', payload[off : off + 4])[0] == 22


def test_encode_version_banner_oci_matches_the_captured_reply() -> None:
    # The sqlplus / thick-OCI version reply (TTI_RPA + banner DALC + packed
    # version trailer), byte-for-byte against a live 11.2 capture (#265).
    from seerdb.common.tns import encode_version_banner_oci, is_version_call_oci

    banner = (
        b'Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production'
    )
    captured = bytes.fromhex(
        '084900494f7261636c65204461746162617365203131672045787072657373'
        '2045646974696f6e2052656c656173652031312e322e302e322e30202d2036'
        '346269742050726f64756374696f6e0002200b09010000000300'
    )
    assert encode_version_banner_oci(banner) == captured
    # The recogniser keys on the TTI_80SES (0x11 0x6b) lead AND the wrapped inner
    # function (0x03 0x3b), so a piggybacked changepassword (inner TTI_AUTH, which
    # shares the 0x11 0x6b prefix) is not mistaken for the version request.
    version = bytes.fromhex('116b043b000000e507000001000000') + b'\x03\x3b'
    change = bytes.fromhex('116b043b000000e507000001000000') + b'\x03\x73'
    assert is_version_call_oci(version) is True
    assert is_version_call_oci(change) is False
    assert is_version_call_oci(b'\x03\x5e\x06') is False


def test_the_version_reply_carries_the_release_it_is_given() -> None:
    # The trailer is the packed release sqlplus prints for SHOW RELEASE (#2024):
    # 23ai's two-line banner_full and 23.26.2.0.0, 18c's and 18.4.0.0.0, as
    # live servers sent them to sqlplus 23.26. The two bytes after 09 01 00 00
    # 00 change from session to session there, and stay the Mirror's own.
    from seerdb.common.tns import encode_version_banner_oci

    banner = (
        b'Oracle AI Database 26ai Free Release 23.26.2.0.0 - Develop, Learn, and '
        b'Run for Free\nVersion 23.26.2.0.0'
    )
    reply = encode_version_banner_oci(banner, 0x171A2000)
    assert reply[:-2] == b'\x08\x67\x00\x67' + banner + bytes.fromhex(
        '00201a170901000000'
    )
    banner = (
        b'Oracle Database 18c Express Edition Release 18.0.0.0.0 - Production\n'
        b'Version 18.4.0.0.0'
    )
    reply = encode_version_banner_oci(banner, 0x12040000)
    assert reply[:-2] == b'\x08\x56\x00\x56' + banner + bytes.fromhex(
        '000004120901000000'
    )


def test_encode_query_response_oci_structure() -> None:
    # The OCI execute response: describe + DCB tail + RXD row + status, computed
    # (not a captured blob). Renders live in sqlplus 11.2 (validated by replay
    # substitution); here we check the structure holds together offline (#265).
    from seerdb.common.tns import _decode_describe_oci, encode_query_response_oci

    col = ColumnMeta(
        name=b'1', data_type=TNS_TYPE_NUMBER, data_length=2, max_size=0, scale=-127
    )
    resp = encode_query_response_oci([col], [(1,)], sequence=19)
    assert _decode_describe_oci(resp)[0]['name'] == b'1'  # describe decodes back
    assert b'\x07\x02\xc1\x02' in resp  # the RXD row: NUMBER 1 = c1 02


def test_oci_trailers_are_computed_mostly_zero() -> None:
    # The two trailers are computed as mostly-zero with a few load-bearing
    # structural constants — not replayed capture bytes (#265).
    from seerdb.common.tns import _oci_dcb_tail, _oci_row_status

    tail = _oci_dcb_tail(1)
    status = _oci_row_status(19)
    assert len(tail) == 83 and tail.count(0) > 70
    assert len(status) == 171 and status.count(0) > 120


def test_encode_fetch_terminator_oci_signals_end_of_fetch() -> None:
    # The OCI end-of-fetch reply: an OER carrying ORA-01403, which sqlplus reads
    # as "cursor drained". Computed (mostly-zero OER + the message), not a blob;
    # renders live when the execute already returned the rows (#265).
    from seerdb.common.tns import encode_fetch_terminator_oci

    term = encode_fetch_terminator_oci(20)
    assert len(term) == 162
    assert term[0] == 0x04  # OER token
    assert term.endswith(b'ORA-01403: no data found\n')


def test_strip_oci_piggyback_unwraps_the_execute() -> None:
    # sqlplus wraps every statement past the first in an OCCA close-cursors
    # piggyback (0x11 0x69 + fixed prefix + cursor entries), then the execute.
    from seerdb.common.tns import strip_oci_piggyback

    # a real 1169 prefix (count=1 -> 23-byte header) + a stub execute
    wrapped = (
        bytes.fromhex('116908feffffffffffffff010000000000000002000000')
        + b'\x03\x5e\x06rest'
    )
    assert strip_oci_piggyback(wrapped) == b'\x03\x5e\x06rest'
    # Closing two cursors, captured from sqlplus against a live 11g: the count
    # takes 8 bytes and each cursor id 4, so the call starts at 27. Read as one
    # 8-byte entry per cursor it started at 31, inside the call (#1517).
    two = bytes.fromhex(
        '116911feffffffffffffff02000000000000000300000001000000035e1221'
    )
    assert strip_oci_piggyback(two) == bytes.fromhex('035e1221')
    # a bare execute (no piggyback) is returned unchanged
    assert strip_oci_piggyback(b'\x03\x5e\x06bare') == b'\x03\x5e\x06bare'


def test_encode_status_oci_and_commit_shapes() -> None:
    # The no-row reply (PL/SQL / DDL) is the 0x08 0x06 status; commit is a small
    # TTI_STA acknowledgement (#265).
    from seerdb.common.tns import encode_commit_status_oci, encode_status_oci

    status = encode_status_oci(7)
    assert status[:3] == b'\x08\x06\x00' and len(status) == 171
    assert encode_commit_status_oci(7)[0] == 0x09  # TTI_STA


def test_encode_commit_status_oci_carries_the_session_sequence() -> None:
    # The trailing ub2 is the OER end-to-end sequence, the same free-running
    # counter every other reply on this path carries — not a frozen capture
    # value (#883). Live 11g answered 7 where its neighbouring OERs were 5 and
    # 8; live 10g answered 6 in the same position one sequence lower.
    from seerdb.common.tns import encode_commit_status_oci

    assert encode_commit_status_oci(7) == bytes.fromhex('09050000000700')
    assert encode_commit_status_oci(6) == bytes.fromhex('09050000000600')
    # It moves with the counter rather than repeating one number.
    assert encode_commit_status_oci(4) != encode_commit_status_oci(5)


def test_encode_logoff_status_oci_stays_a_zero_sequence() -> None:
    # The one OCI reply a live server does NOT put its counter in: both 10g and
    # 11g send a literal 0 there, on every captured session (#883).
    from seerdb.common.tns import encode_logoff_status_oci

    assert encode_logoff_status_oci() == bytes.fromhex('09010000000000')


def test_encode_logoff_status_thin_matches_the_captured_wire() -> None:
    # python-oracledb 26.0.0 reads a reply to its TTI_LOGOFF before closing; the
    # thin reply is a TTI_STA status token (call status 1, sequence 0) in the
    # protocol's variable-length integer form, followed by the END_OF_RESPONSE
    # marker -- byte-identical to a live 23ai's logoff reply (#888). Distinct
    # from the OCI fixed-width form above.
    from seerdb.common.tns import encode_logoff_status_thin

    assert encode_logoff_status_thin() == bytes.fromhex('090101001d')


def test_encode_long_value_oci_matches_the_captured_wire() -> None:
    # A LONG value streams inline as 0xFE-chunked bytes + a zero trailing ub4,
    # reproduced byte-for-byte from a live 11g LONG SELECT (#407).
    from seerdb.common.tns import encode_long_value_oci

    got = encode_long_value_oci('LONG-value-inline-0123456789-abcdefghij')
    assert got == bytes.fromhex(
        'fe274c4f4e472d76616c75652d696e6c696e652d3031323334353637383'
        '92d6162636465666768696a0000000000'
    )
    # NULL is an empty value still followed by the trailing indicator.
    assert encode_long_value_oci(None) == b'\x00\x00\x00\x00\x00'
    # LONG RAW carries raw bytes; a value over one chunk (0xFC) splits.
    big = bytes(range(256)) * 2  # 512 bytes -> chunks 0xFC, 0xFC, 0x08
    raw = encode_long_value_oci(big)
    assert raw[0] == 0xFE and raw[-4:] == b'\x00\x00\x00\x00'
    assert raw[1] == 0xFC  # first chunk length
    # The chunks reassemble to the original content.
    body, pos, acc = raw[1:], 0, bytearray()
    while body[pos] != 0:
        length = body[pos]
        acc += body[pos + 1 : pos + 1 + length]
        pos += 1 + length
    assert bytes(acc) == big


def test_encode_describe_oci_long_column_is_streamed() -> None:
    # A LONG column describes as a character type (charset + 0x80 flag) with its
    # sizes zero — the value is streamed inline, not fixed-width (#407).
    from seerdb.common.tns import ColumnMeta, encode_describe_oci
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TNS_TYPE_LONGRAW

    long_col = ColumnMeta(name=b'V', data_type=TNS_TYPE_LONG, data_length=0, max_size=0)
    body = encode_describe_oci([long_col])
    col = body[36:]  # column block, after preamble + max-row-size + column count
    assert col[2] == TNS_TYPE_LONG and col[3] == 0x80  # char flag
    assert int.from_bytes(col[34:38], 'little') == 0  # max size zeroed
    # A LONG contributes nothing to the max-row-size (offset 28, ub4 LE).
    assert int.from_bytes(body[28:32], 'little') == 0
    # LONG RAW is binary — no char flag.
    raw_col = ColumnMeta(
        name=b'R', data_type=TNS_TYPE_LONGRAW, data_length=0, max_size=0
    )
    assert encode_describe_oci([raw_col])[36:][3] == 0x00


# Two OALL8 executes from sqlplus 10.2.0.5 to 11g XE, captured through a logging
# proxy (#1764): its pointer fields hold addresses, and its SQL starts at 148.
_OCI_ALL8_10_2_SELECT = bytes.fromhex(
    '035e06618000000000000098fd6929000000004200000034d36729000000000d00000000'
    '0000000000000068d3672900000000000000000100000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000006a'
    'd367290000000020fe6929000000000000000000000000000000000000000080d3672900'
    '0000001653454c45435420555345522046524f4d204455414c0001000000000000000000'
    '000000000000000000000000000000000000010000000000000000000000000000000000'
    '000000000000'
)
_OCI_ALL8_10_2_OUT_BIND = bytes.fromhex(
    '035e342904040000000000f8036a29000000004200000034d36729000000000d00000000'
    '0000000000000068d3672900000000000000000100000000000000c8ed69290000000001'
    '00000000000000000000000000000000000000000000000000000000000000000000006a'
    'd3672900000000c8ed6929000000000000000000000000000000000000000080d3672900'
    '00000016424547494e203a72203a3d2034323b20454e443b0a0001000000010000000000'
    '000000000000000000000000000000000000080000000000000000000000000000000000'
    '000000000000010203000016000000000000000000000000000000000000000000000000'
    '000000000000000000000007fd01'
)


def test_sqlplus_10_2s_execute_parses() -> None:
    # sqlplus 10.2's narrow preamble puts the SQL at 148, 28 bytes ahead of the
    # 23.26 form, and fills its pointers with addresses; the session's field
    # version picks the layout (#1764).
    from seerdb.common.tns import is_reexecute_oci, parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_10_2, TNS_TYPE_NUMBER

    with _at_field_version(FIELD_VERSION_10_2):
        select = parse_exec_oci(_OCI_ALL8_10_2_SELECT)
        block = parse_exec_oci(_OCI_ALL8_10_2_OUT_BIND)
    assert (select.sql, select.cursor, select.bind_count) == (
        'SELECT USER FROM DUAL',
        0,
        0,
    )
    assert block.sql == 'BEGIN :r := 42; END;\n'
    assert block.bind_count == 1
    assert block.binds == [None]  # an OUT bind: the absent-value placeholder
    assert block.bind_meta == [(TNS_TYPE_NUMBER, 22)]
    # An address in the SQL pointer is a fresh execute, not a re-execute.
    assert not is_reexecute_oci(_OCI_ALL8_10_2_SELECT)
    # Read as 11.2 it is refused by name, not misparsed.
    with pytest.raises(InterfaceError, match='no indicator at offset 11'):
        parse_exec_oci(_OCI_ALL8_10_2_SELECT)


# sqlplus 11.2.0.2's DBMS_OUTPUT.GET_LINES call to 11g XE, captured through a
# logging proxy (#1826); sqlplus 10.2 sends the same bind section.
_OCI_GET_LINES_11_2 = bytes.fromhex(
    '035e3e2904040000000000feffffffffffffff9c00000000000000feffffffffffffff0d'
    '00000000000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '000000feffffffffffffff02000000000000000000000000000000feffffffffffffff00'
    '00000000000000fefffffffffffffffeffffffffffffff189cf639000000000000000000'
    '000000fefffffffffffffffeffffffffffffff0000000000000000000000000000000000'
    '00000000000000000000000000000034424547494e2044424d535f4f55545055542e4745'
    '545f4c494e4553283a4c494e45532c203a4e554d4c494e4553293b20454e443b01000000'
    '010000000000000000000000000000000000000000000000080000000000000000000000'
    '000000000000000000000000006d000000d007000000000000000000001000000010ab9e'
    'ebb9d6af92fce040e50a194e468001000000000000000001020100001600000000000000'
    '000000000000000000000000000000000000000000000000000000000724000000240022'
    '0208ab9eebb9d6af92fce040e50a194e4680000000000000000000000000000100010000'
    '000000000000000000000000010016c10600000000000000000000000000000000000000'
    '00'
)


def test_a_pre_12c_get_lines_call_reads_its_binds() -> None:
    # sqlplus 11.2 and 10.2 bind GET_LINES's collection with two zeros fewer
    # ahead of its type id and two more in its empty value, and :NUMLINES with
    # flag 01 and its whole padded buffer. Unread, the call was refused and SET
    # SERVEROUTPUT ON printed nothing (#1826).
    from seerdb.common.tns import parse_exec_oci
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        TNS_TYPE_ADT,
        TNS_TYPE_NUMBER,
    )

    with _at_field_version(FIELD_VERSION_11_2):
        call = parse_exec_oci(_OCI_GET_LINES_11_2)
    assert call.sql == 'BEGIN DBMS_OUTPUT.GET_LINES(:LINES, :NUMLINES); END;'
    assert call.binds == [None, 5]  # the collection OUT, the count IN OUT
    assert call.bind_meta == [(TNS_TYPE_ADT, 2000), (TNS_TYPE_NUMBER, 22)]
    assert call.bind_types[0][3] == bytes.fromhex('ab9eebb9d6af92fce040e50a194e4680')


# `SELECT :vc7, :vc4k, :ch13, :nch5, :nvc9, :n FROM dual` as sqlplus 23.26 and
# 11.2 sent it to a Mirror-over-PG: VARCHAR2(7), VARCHAR2(4000), CHAR(13),
# NCHAR(5), NVARCHAR2(9) and NUMBER. The NCHAR ones hold `?`, in UTF-16.
_OCI_SIX_BINDS_23_26 = bytes.fromhex(
    '035e1e6980000000000000feffffffffffffff9f000000feffffffffffffff0d000000fe'
    'fffffffffffffffeffffffffffffff000000000100000000000000feffffffffffffff06'
    '0000000000000000000000feffffffffffffff0000000000000000fefffffffffffffffe'
    'fffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000003553454c454354203a7663372c'
    '203a7663346b2c203a636831332c203a6e6368352c203a6e7663392c203a6e2046524f4d'
    '206475616c01000000000000000000000000000000000000000000000000000000010000'
    '000000000000800000000000000000000000000000010103000015000000000000000000'
    '000000000000000000000000000000000000000000006903010000000000000000000101'
    '030000e02e00000000000000000000000000000000000000000000000000000000000069'
    '030100000000000000000001600300002700000000000000000000000000000000000000'
    '00000000000000000000000069030100000000000000000001600300000a000000000000'
    '00000000001000000000000000000000000000000000000000d007020005000000000000'
    '000101030000120000000000000000000000100000000000000000000000000000000000'
    '0000d0070200090000000000000001020300001600000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000070361626302696afe'
    '0100013f00fe0100013f0002c12b056465666768'
)
_OCI_SIX_BINDS_11_2 = bytes.fromhex(
    '035e1a6980000000000000feffffffffffffff9f000000feffffffffffffff0d000000fe'
    'fffffffffffffffeffffffffffffff000000000100000000000000feffffffffffffff06'
    '0000000000000000000000feffffffffffffff0000000000000000fefffffffffffffffe'
    'fffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff000000000000000000000000000000000000000000000000000000003553454c45'
    '4354203a7663372c203a7663346b2c203a636831332c203a6e6368352c203a6e7663392c'
    '203a6e2046524f4d206475616c0100000000000000000000000000000000000000000000'
    '000000000001000000000000000000000000000000000000000000000001010300001500'
    '000000000000000000000000000000000000000000006903010000000000000000000101'
    '030000e02e00000000000000000000000000000000000000000000690301000000000000'
    '000000016003000027000000000000000000000000000000000000000000000069030100'
    '000000000000000001600300000a00000000000000100000000000000000000000000000'
    '00d007020005000000000000000101030000120000000000000010000000000000000000'
    '000000000000d00702000900000000000000010203000016000000000000000000000000'
    '0000000000000000000000000000000000000000000000070361626302696a02003f0200'
    '3f02c12b056465666768'
)


@pytest.mark.parametrize(
    ('request_bytes', 'field_version'),
    [
        (_OCI_SIX_BINDS_23_26, FIELD_VERSION_18_1_EXT_1),
        (_OCI_SIX_BINDS_11_2, FIELD_VERSION_11_2),
    ],
    ids=['23.26', '11.2'],
)
def test_an_oci_execute_reads_each_bind_from_its_descriptor(
    request_bytes: bytes, field_version: int
) -> None:
    # Each bind's descriptor is read whole (_OAC): the VARCHAR2(4000)'s
    # 12000-byte buffer sends its value behind the others, and the NCHAR pair is
    # national. Found by a pattern scan, the statement took descriptor bytes for
    # its first value, and PostgreSQL refused the NUL in it (#2064).
    with _at_field_version(field_version):
        call = parse_exec_oci(request_bytes)
    assert call.binds == ['abc', 'defgh', 'ij', '?', '?', 42]
    assert call.bind_meta == [
        (TNS_TYPE_VARCHAR, 21),
        (TNS_TYPE_VARCHAR, 12000),
        (TNS_TYPE_CHAR, 39),
        (TNS_TYPE_CHAR, 10),
        (TNS_TYPE_VARCHAR, 18),
        (TNS_TYPE_NUMBER, 22),
    ]
    assert [form for (_t, form, _s, _o) in call.bind_types] == [1, 1, 1, 2, 2, 1]


def test_is_reexecute_oci_detects_the_sql_less_reexecute() -> None:
    # A fresh OCI execute carries the SQL pointer indicator at offset 11; a
    # re-execute (the LONG fetch step) omits it (#407).
    from seerdb.common.oci import OCI_INDICATOR
    from seerdb.common.tns import is_reexecute_oci

    fresh = bytes([0x03, 0x5E, 0x01]) + b'\x00' * 8 + OCI_INDICATOR + b'\x00' * 240
    reexec = bytes([0x03, 0x5E, 0x01]) + b'\x00' * 8 + b'\x00' * 8 + b'\x00' * 240
    assert is_reexecute_oci(reexec) is True
    assert is_reexecute_oci(fresh) is False


def test_long_row_replies_carry_the_right_status() -> None:
    # The re-execute reply ends with the execute row-status (0x08 0x06); a
    # fetch-delivered LONG row ends with the "more rows" OER status (#407).
    from seerdb.common.tns import (
        ColumnMeta,
        encode_long_fetch_row_oci,
        encode_reexec_row_oci,
    )
    from seerdb.common.tns_consts import TNS_TYPE_LONG

    col = ColumnMeta(name=b'V', data_type=TNS_TYPE_LONG, data_length=0, max_size=0)
    reexec = encode_reexec_row_oci([col], [('hi',)], sequence=19, more=True)
    assert reexec[0] == 0x06  # TTI_RXH
    assert b'\x08\x06\x00' in reexec  # execute row-status
    fetch = encode_long_fetch_row_oci([col], ('hi',), sequence=0x11)
    assert fetch[0] == 0x06  # TTI_RXH
    assert fetch[-136:][:2] == b'\x04\x01'  # OER "more rows" status, no 1403 body


def _cell_locator(cell: bytes) -> dict:
    # The locator a LOB cell carries to an 11.2 client, behind its ub4 and ub1
    # lengths, read back by its schema (_OCI_LOB_LOCATOR).
    from seerdb.common.tns import _OCI_LOB_LOCATOR_FROM_OCI

    (fields, rest) = _OCI_LOB_LOCATOR_FROM_OCI(cell[5:])
    assert rest == b''
    return fields


def test_lob_locator_carries_the_content_byte_size() -> None:
    # The row locator's size field is the content BYTE count (big-endian): a CLOB
    # is UTF-16 (2 bytes per char), a BLOB is its raw bytes. NULL is a zero
    # length, all four bytes of it (no read, #1287). This unit is what makes
    # sqlplus accept the locator (#405).
    from seerdb.common.tns import encode_lob_locator_oci

    clob = encode_lob_locator_oci('A' * 2000, is_clob=True)
    assert _cell_locator(clob)['byte_size'] == 4000  # 2000 chars * 2
    blob = encode_lob_locator_oci(b'\x00' * 2500, is_clob=False)
    assert _cell_locator(blob)['byte_size'] == 2500  # raw bytes
    assert encode_lob_locator_oci(None, is_clob=True) == bytes(4)
    # CLOB and BLOB use different locator templates: the type bytes and the charset
    # differ (a CLOB is AL32UTF8 characters, a BLOB is binary) so sqlplus does not
    # decode a BLOB's raw bytes as text (#406).
    assert (_cell_locator(clob)['lob_kind'], _cell_locator(blob)['lob_kind']) == (2, 1)
    assert (_cell_locator(clob)['charset'], _cell_locator(blob)['charset']) == (873, 0)


def test_lob_read_response_selects_clob_or_blob_locator() -> None:
    # The READ reply echoes the character (CLOB) or binary (BLOB) locator template,
    # matching the row locator so sqlplus renders the content correctly (#406).
    from seerdb.common.tns import encode_lob_read_response_oci

    clob_reply = encode_lob_read_response_oci(b'\x00A', 1, 2, is_clob=True, sequence=17)
    blob_reply = encode_lob_read_response_oci(
        b'\xca\xfe', 2, 2, is_clob=False, sequence=17
    )
    # The echoed locator carries the same type/charset split as the row locator.
    assert bytes.fromhex('0001020c88') in clob_reply  # CLOB locator signature
    assert bytes.fromhex('0001010c08') in blob_reply  # BLOB locator signature
    assert bytes.fromhex('0001020c88') not in blob_reply


def test_nclob_locator_carries_the_national_form() -> None:
    # An NCLOB's locator, in its row and echoed in each READ reply, is a CLOB's
    # with the national form: header `04 4c 08` (kind NCLOB, national bit 0x40,
    # fixed-width charset) and charset 2000 (AL16UTF16), as a live 11g sends
    # sqlplus 23.26. A CLOB-form locator under an NCLOB describe makes sqlplus
    # refuse the value with ORA-24806 (#1369).
    from seerdb.common.tns import (
        _oci_lob_locator,
        encode_lob_locator_oci,
        encode_lob_read_response_oci,
    )

    nclob = _oci_lob_locator(True, national=True)
    assert nclob[3:6] == bytes.fromhex('044c08')
    assert _oci_lob_locator(True)[3:6] == bytes.fromhex('020c88')
    row = encode_lob_locator_oci('nat', is_clob=True, national=True)
    assert _cell_locator(row)['charset'] == 2000  # AL16UTF16
    assert nclob[8] == 0x02  # still a character LOB
    assert row[6:].startswith(nclob[:9])
    reply = encode_lob_read_response_oci(
        b'\x00n', 1, 2, is_clob=True, national=True, sequence=17
    )
    assert bytes.fromhex('0001044c08') in reply
    assert bytes.fromhex('0001020c88') not in reply


def test_oci_lob_reads_flag_national_lobs() -> None:
    # The sqlplus read queue says which LOB is national, so its READ reply echoes
    # the locator its row carried (#1369); the thin queue keeps its pairs.
    from seerdb.common.tns import (
        TNS_TYPE_BLOB,
        TNS_TYPE_CLOB,
        ColumnMeta,
        oci_lob_contents,
        oci_lob_reads,
    )

    columns = [
        ColumnMeta(
            name=b'N', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0, csfrm=2
        ),
        ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_BLOB, data_length=4000, max_size=0),
    ]
    rows = [('n', 'c', b'\x01')]
    assert oci_lob_reads(columns, rows) == [
        ('n'.encode('utf-16-be'), True, True),
        ('c'.encode('utf-16-be'), True, False),
        (b'\x01', False, False),
    ]
    assert oci_lob_contents(columns, rows) == [
        ('n'.encode('utf-16-be'), True),
        ('c'.encode('utf-16-be'), True),
        (b'\x01', False),
    ]


# A TTI_LOBOPS READ from sqlplus 23.26 (narrow form), captured through the Mirror:
# the first chunk (offset 1, amount 7) of the first of two CLOB columns, its
# locator echoed as the Mirror minted it before #1430 -- with no slot.
_OCI_LOBOPS_READ_TWO_CLOBS = bytes.fromhex(
    '036001feffffffffffffff6a0000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000200000000000000000000'
    '000000000001000000000000000400000000000000feffffffffffffff000000000000'
    '0000000000000000000000000000000000000000000000000000000000000068000102'
    '0c88000002000000010000005600000001000000010000000200020369000200000000'
    '0000000000000000000000000000000000000000000000000000000000000000000000'
    '0000010000000000000000001405000000000000280000000000020000000007000000'
    '00000000'
)


def test_a_lob_read_names_its_lob_by_the_slot_in_its_locator() -> None:
    # sqlplus reads a row's LOBs interleaved -- a's first chunk, b's first, a's
    # second -- and tells them apart only by the locator each read echoes. A
    # shared locator served a's second chunk from b (#1430). Each LOB's locator
    # now carries its column index, in the row, in every READ reply, and is read
    # back from the request.
    from seerdb.common.tns import (
        encode_lob_fetch_rows_oci,
        encode_lob_read_response_oci,
        parse_lobops_read,
        parse_lobops_slot,
    )

    assert parse_lobops_read(_OCI_LOBOPS_READ_TWO_CLOBS) == (1, 7)
    assert parse_lobops_slot(_OCI_LOBOPS_READ_TWO_CLOBS) is None  # minted slot-less
    loc = _OCI_LOBOPS_READ_TWO_CLOBS.find(bytes.fromhex('680001020c88'))
    for slot in (0, 1, 5):
        reply = encode_lob_read_response_oci(b'\x00A', 1, 2, slot=slot, sequence=17)
        echoed = reply[reply.find(bytes.fromhex('680001020c88')) :][:105]
        request = bytearray(_OCI_LOBOPS_READ_TWO_CLOBS)
        request[loc : loc + 105] = echoed  # what sqlplus sends on its next read
        assert parse_lobops_slot(bytes(request)) == slot
    clob = ColumnMeta(name=b'A', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0)
    row = encode_lob_fetch_rows_oci([clob, clob], [('aa', 'bb')], sequence=3)
    sig = bytes.fromhex('680001020c88')
    starts = [i for i in range(len(row)) if row.startswith(sig, i)]
    assert len(starts) == 2
    assert row[starts[0] : starts[0] + 105] != row[starts[1] : starts[1] + 105]


# sqlplus 11.2's TTI_LOBOPS READs, the wide form (#2251): its second read of a
# CLOB (80 characters from 81) to a live 11g, a real locator in it, and its
# first read of the first of a row's two LOBs through the Mirror, the locator
# as the Mirror minted it, with the slot of column 0.
_OCI_LOBOPS_READ_WIDE_11G = bytes.fromhex(
    '036019feffffffffffffff6a000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000200000000'
    '0000000000000000000000000000000000000051000000000000000400000000000000fe'
    'ffffffffffffff0000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000680001020c8800000200000001000000'
    '6e875100060c3200060c3100020002036900020100016500000000000000000000000001'
    '282a6d000000000000000000000000000000000000000000060c310100015d0000001405'
    '00000000001f40000000000002010001655000000000000000'
)
_OCI_LOBOPS_READ_WIDE_MIRROR = bytes.fromhex(
    '036006feffffffffffffff6a000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000200000000'
    '0000000000000000000000000000000000000001000000000000000400000000000000fe'
    'ffffffffffffff0000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000680001020c8800000200000001000000'
    '560000000100000001000000020002036900020000000000000000010000000000000000'
    '000000000000000000000000000000000000000000000000010000000000000000001405'
    '00000000001f40000000000002000000005000000000000000'
)


def test_parse_lobops_read_extracts_offset_and_amount() -> None:
    # sqlplus's TTI_LOBOPS READ carries a 1-based source offset and an amount;
    # the Mirror serves exactly that slice so the read loop terminates (#405). A
    # short/garbled request falls back to read-all.
    from seerdb.common.tns import parse_lobops_read

    assert parse_lobops_read(_OCI_LOBOPS_READ_WIDE_11G) == (81, 80)
    assert parse_lobops_read(_OCI_LOBOPS_READ_WIDE_MIRROR) == (1, 80)
    # Too short → read the whole LOB from the start.
    assert parse_lobops_read(b'\x03\x60\x01') == (1, 2**31)
    assert parse_lobops_read(_OCI_LOBOPS_READ_WIDE_MIRROR[:200]) == (1, 2**31)


def test_a_wide_lob_read_names_its_lob_by_its_slot() -> None:
    # sqlplus 11.2 reads in the wide form, whose locator went unread: no read
    # named its LOB, so a row's CLOB read past its first chunk continued the
    # BLOB read in between and printed short (#2251). Its counts are the wide
    # codec's: read in full, the locator and its slot come back, and the reply's
    # locator, which sqlplus echoes on its next read, keeps the slot.
    from seerdb.common.tns import (
        encode_lob_read_response_oci,
        parse_lobops_locator,
        parse_lobops_slot,
    )

    assert parse_lobops_slot(_OCI_LOBOPS_READ_WIDE_MIRROR) == 0
    locator = parse_lobops_locator(_OCI_LOBOPS_READ_WIDE_11G)
    assert locator is not None and locator.startswith(bytes.fromhex('00680001020c88'))
    from seerdb.common.tns import _LOBOPS_READ_FROM_OCI_WIDE

    (read, rest) = _LOBOPS_READ_FROM_OCI_WIDE(_OCI_LOBOPS_READ_WIDE_11G)
    assert (read['operation'], read['source_length'], rest) == (2, 106, b'')
    loc = _OCI_LOBOPS_READ_WIDE_MIRROR.find(bytes.fromhex('680001020c88'))
    reply = encode_lob_read_response_oci(b'\x00A', 1, 2, slot=1, sequence=17)
    echoed = reply[reply.find(bytes.fromhex('680001020c88')) :][:105]
    request = bytearray(_OCI_LOBOPS_READ_WIDE_MIRROR)
    request[loc : loc + 105] = echoed
    assert parse_lobops_slot(bytes(request)) == 1


# sqlplus 23.26's third CLOB read of one LOB (#1287): the narrow request, whose
# fields sit elsewhere than the wide form's. It asks for 50 characters from
# character 51.
_OCI_LOBOPS_READ_NARROW = bytes.fromhex(
    '036004feffffffffffffff6a0000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000200000000'
    '000000000000000000000033000000000000000400000000000000feffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '0000000000000000680001020c88000002000000010000005600000001000000'
    '0100000002000203690002000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000010000000000000000001405'
    '00000000000258000000000002000000003200000000000000'
)


def test_parse_lobops_read_reads_the_narrow_request() -> None:
    # Read with the wide offsets, this request is too short, so the Mirror
    # served the whole LOB to every read, which sqlplus cannot take (#1287).
    from seerdb.common.tns import parse_lobops_read

    assert parse_lobops_read(_OCI_LOBOPS_READ_NARROW) == (51, 50)


def test_lob_column_value_carries_the_lob_length_and_chunk_size() -> None:
    # A live 11g sends sqlplus 23.26, which offers CCAP_LOB_12C, a LOB column as
    # its locator length (ub4), the LOB's length (ub8, characters for a CLOB),
    # its chunk size (ub4), then the locator; sqlplus cannot parse the row
    # without the middle two. sqlplus 11.2 gets the bare form (#1287).
    from seerdb.common.features import _SESSION_FEATURES, Features
    from seerdb.common.tns import encode_lob_locator_oci

    bare = encode_lob_locator_oci('short clob', is_clob=True)
    token = _SESSION_FEATURES.set(Features(oci_lob_12c=True))
    try:
        value = encode_lob_locator_oci('short clob', is_clob=True)
        blob = encode_lob_locator_oci(b'\x01\x02', is_clob=False)
        null = encode_lob_locator_oci(None, is_clob=True)
    finally:
        _SESSION_FEATURES.reset(token)
    assert int.from_bytes(value[4:12], 'little') == 10  # characters
    assert int.from_bytes(value[12:16], 'little') == 8132  # 11g's chunk size
    # Around them, the bare form a client without CCAP_LOB_12C reads.
    assert value[:4] + value[16:] == bare
    assert int.from_bytes(blob[4:12], 'little') == 2  # bytes
    assert null == bytes(4)


def test_encode_lob_describe_oci_omits_the_dcb_tail() -> None:
    # The LOB execute reply is a describe with a distinct 33-byte tail + LOB status,
    # NOT the ordinary inline-row DCB tail (which carries the 0x06 0x01 0x22 marker)
    # — this is what makes sqlplus accept the locator row (#405).
    from seerdb.common.tns import ColumnMeta, encode_lob_describe_oci
    from seerdb.common.tns_consts import TNS_TYPE_CLOB

    col = ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0)
    reply = encode_lob_describe_oci([col], sequence=15)
    assert reply[0] == TTI_DCB
    assert bytes.fromhex('060122') not in reply  # no DCB-tail marker
    assert b'\x08\x06\x00' in reply  # LOB execute status present


def test_oci_lob_describe_tail_is_built_from_fields() -> None:
    # The 33-byte LOB describe tail (#405) is built field-by-field, not stored:
    # the describe-time DALC head (ub4 char-length 7 + byte-length 7) + one carried
    # ub4 at offset 17. It must stay byte-identical to the live 11g capture.
    from seerdb.common.tns import _OCI_LOB_DESCRIBE_TAIL, _oci_lob_describe_tail

    assert _OCI_LOB_DESCRIBE_TAIL == bytes.fromhex(
        '0007000000070000000000000000000000e81f0000000000000000000000000000'
    )
    assert _oci_lob_describe_tail() == _OCI_LOB_DESCRIBE_TAIL
    assert (8168).to_bytes(4, 'little') in _OCI_LOB_DESCRIBE_TAIL


def test_encode_lob_read_response_slices_and_reports_totals() -> None:
    # The READ reply carries the requested slice as LOB_DATA and reports the whole
    # LOB's byte size in the echoed locator plus this read's amount (#405).
    from seerdb.common.tns import (
        _OCI_LOB_LOCATOR_FROM_OCI,
        encode_lob_read_response_oci,
    )

    content = 'Hello'.encode('utf-16-be')  # a 5-char slice, 10 bytes
    reply = encode_lob_read_response_oci(
        content, amount=5, total_bytes=4000, sequence=17
    )
    assert reply[0] == TTI_LOB
    # The return parameters: the RPA token, the echoed locator, the ub8 amount.
    tail = reply[-251:]
    (locator, rest) = _OCI_LOB_LOCATOR_FROM_OCI(tail[1:])
    assert locator['byte_size'] == 4000
    assert int.from_bytes(rest[:8], 'little') == 5


def test_oci_lob_contents_reports_type_and_wire_bytes() -> None:
    # Each non-NULL LOB cell yields (wire-content, is_clob): CLOB is UTF-16BE, BLOB
    # is raw; NULL LOBs are skipped (they draw no read) (#405).
    from seerdb.common.tns import ColumnMeta, oci_lob_contents
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    cols = [
        ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_BLOB, data_length=4000, max_size=0),
    ]
    got = oci_lob_contents(cols, [('hi', b'\xca\xfe'), (None, None)])
    assert got == [('hi'.encode('utf-16-be'), True), (b'\xca\xfe', False)]


def test_oci_lob_contents_encodes_a_json_cell_as_its_oson_image() -> None:
    # A native JSON column reads back over the LOB path like a CLOB / BLOB, but
    # its content is the value's OSON image (is_clob False — the client decodes
    # OSON, not text). NULL is skipped like any other LOB (#30/#50/#70).
    from seerdb.common.oson import decode_oson, encode_oson
    from seerdb.common.tns import ColumnMeta, oci_lob_contents
    from seerdb.common.tns_consts import TNS_TYPE_JSON

    cols = [
        ColumnMeta(name=b'D', data_type=TNS_TYPE_JSON, data_length=4000, max_size=0)
    ]
    doc = {'hello': 'world', 'n': 42, 'arr': [1, 2, 3]}
    got = oci_lob_contents(cols, [(doc,), (None,)], for_oci=True)
    assert len(got) == 1
    image, is_clob = got[0]
    assert is_clob is False
    assert image == encode_oson(doc)
    assert decode_oson(image) == doc


def test_a_thin_json_cell_rides_in_the_row_and_queues_no_lob() -> None:
    # The thin path does not hand a JSON column over as a locator with its image
    # following over TTI_LOBOPS. A real server prefetches the whole value into the
    # row, and the reference client's read_oson expects exactly that -- it issues
    # no TTI_LOBOPS call at all, so a queue entry here would shift every later
    # LOB's position (#826, the same shape VECTOR needed in #887).
    from seerdb.common.oson import encode_oson
    from seerdb.common.tns import (
        ColumnMeta,
        encode_prefetched_lob_value_thin,
        encode_rows,
        oci_lob_contents,
    )

    doc = {'hello': 'world', 'n': 42}
    col = ColumnMeta(name=b'D', data_type=TNS_TYPE_JSON, data_length=8200, max_size=0)
    assert oci_lob_contents([col], [(doc,)]) == []
    image = encode_oson(doc, allow_wide=True)
    assert encode_prefetched_lob_value_thin(image) in encode_rows([(doc,)], [col])
    # The OCI (sqlplus) path does read it over TTI_LOBOPS, so it still queues.
    assert len(oci_lob_contents([col], [(doc,)], for_oci=True)) == 1


def test_encode_value_emits_a_thin_lob_locator_for_a_json_column() -> None:
    # The type-only encoder treats JSON like a CLOB / BLOB: a locator whose
    # content follows over TTI_LOBOPS, NULL a bare 0x00 (#30/#50). A row built by
    # _thin_column_value no longer reaches this for a JSON column -- it carries
    # the OSON image in the row instead (#826) -- but the locator form is still
    # what a bare encode_value means by a JSON value.
    from seerdb.common.tns import encode_lob_locator_thin, encode_value
    from seerdb.common.tns_consts import TNS_TYPE_JSON

    assert encode_value({'a': 1}, TNS_TYPE_JSON) == encode_lob_locator_thin()
    assert encode_value(None, TNS_TYPE_JSON) == b'\x00'


def test_parse_exec_decodes_a_native_json_bind_as_a_json_value() -> None:
    # A JSON bind the client can OSON-encode rides inline as its OSON image (the
    # _native_lob_bind_value framing), not a plain DALC. parse_exec reads it back
    # and hands the backend a JSON-wrapped Python value so a bare list / scalar
    # re-binds into a JSON column rather than as a collection / VARCHAR (#50/#70).
    from seerdb.common.datatypes import JSON
    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        encode_dictionary_exec,
        parse_exec,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_23_1

    doc = {'hello': 'world', 'n': 42, 'arr': [1, 2, 3]}
    # The native framing (bytes_with_length) and the 12.2+ OALL8 middle block are
    # post-11g forms: encode AND decode at 23ai (the session pins both context
    # vars to the negotiated version per message).
    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    dec = _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    try:
        payload = encode_dictionary_exec(
            {
                'seq': 4,
                'field_version': FIELD_VERSION_23_1,
                'query': {
                    'type': 'select',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': 0,
                    'query': 'insert into t values (:1)',
                    'bind': [doc],
                    'batch': [],
                    'def': [],
                },
            }
        )
        request = parse_exec(payload)
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)
    assert isinstance(request.binds[0], JSON)
    assert request.binds[0].value == doc


def test_oci_lob_contents_encodes_a_vector_cell_by_element_format() -> None:
    # A native VECTOR column reads back over the LOB path with its binary image;
    # the column's element format (ColumnMeta.vector_format) drives the re-encode
    # so INT8 stays integral, not a default FLOAT32 (#55).
    from seerdb.common.tns import ColumnMeta, oci_lob_contents
    from seerdb.common.tns_consts import TNS_TYPE_VECTOR
    from seerdb.common.vector import decode_vector

    cols = [
        ColumnMeta(
            name=b'V',
            data_type=TNS_TYPE_VECTOR,
            data_length=0,
            max_size=0,
            vector_format=4,  # INT8
        )
    ]
    got = oci_lob_contents(cols, [([1, -2, 3, -4],), (None,)], for_oci=True)
    assert len(got) == 1
    image, is_clob = got[0]
    assert is_clob is False
    decoded = decode_vector(image)
    # decode_vector reports the element format in the array's typecode ('b' is
    # INT8), so the cell keeps the width it was declared with (#826).
    assert decoded == array.array('b', [1, -2, 3, -4])


def test_encode_value_emits_a_thin_lob_locator_for_a_vector_column() -> None:
    # A VECTOR value rides as a LOB locator inline (its binary image follows over
    # TTI_LOBOPS), like a CLOB / BLOB / JSON; NULL is a bare 0x00 (#55).
    from seerdb.common.tns import encode_lob_locator_thin, encode_value
    from seerdb.common.tns_consts import TNS_TYPE_VECTOR

    assert encode_value([1.0, 2.0], TNS_TYPE_VECTOR) == encode_lob_locator_thin()
    assert encode_value(None, TNS_TYPE_VECTOR) == b'\x00'


def test_parse_exec_decodes_a_native_vector_bind_type_preserving() -> None:
    # A native VECTOR bind rides inline as its binary image (the
    # _native_lob_bind_value framing). parse_exec decodes it to a type-preserving
    # value (array.array by the image's element type) so the backend re-binds a
    # FLOAT64 / INT8 / BINARY vector faithfully rather than as a FLOAT32 list (#55).
    import array

    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        encode_dictionary_exec,
        parse_exec,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_23_1

    vec = array.array('b', [1, -2, 3, -4])  # INT8
    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    dec = _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    try:
        payload = encode_dictionary_exec(
            {
                'seq': 4,
                'field_version': FIELD_VERSION_23_1,
                'query': {
                    'type': 'select',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': 0,
                    'query': 'insert into t values (:1)',
                    'bind': [vec],
                    'batch': [],
                    'def': [],
                },
            }
        )
        request = parse_exec(payload)
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)
    bound = request.binds[0]
    assert isinstance(bound, array.array)
    assert bound.typecode == 'b'
    assert list(bound) == [1, -2, 3, -4]


def test_parse_exec_decodes_a_ref_bind_with_its_type_oid() -> None:
    # A REF bind (#139): its OAC carries the referenced type's 16-byte OID with a
    # two-length framing that a plain-DALC OAC read would desync on (dropping the
    # next bind -> ORA-01008). parse_exec must decode the OAC cleanly and rebuild
    # a DbRef pairing the locator (from the value) with that OID, so a second
    # bind after it still parses and the backend can re-bind the REF.
    from seerdb.common.dbobject import DbRef
    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        encode_dictionary_exec,
        parse_exec,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_23_1

    oid = bytes.fromhex('00280209' + 'a1' * 12)
    ref = DbRef(bytes.fromhex('0028') + b'\xbb' * 30, type_oid=oid, type_name='T')
    enc = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    dec = _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    try:
        payload = encode_dictionary_exec(
            {
                'seq': 4,
                'field_version': FIELD_VERSION_23_1,
                'query': {
                    'type': 'select',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': 0,
                    'query': 'insert into t values (:1, :2)',
                    # A scalar bind AFTER the REF proves the OAC realigned: a
                    # desync would swallow it and surface as ORA-01008.
                    'bind': [ref, 100],
                    'batch': [],
                    'def': [],
                },
            }
        )
        request = parse_exec(payload)
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)
    assert request.bind_count == 2
    bound = request.binds[0]
    assert isinstance(bound, DbRef)
    assert bound.bytes == ref.bytes
    assert bound.type_oid == oid
    assert request.binds[1] == 100


def test_encode_value_emits_a_thin_lob_locator_for_lob_columns() -> None:
    # A thin (oracledb/seerdb) client's LOB column carries a minted opaque locator
    # inline; the content follows over TTI_LOBOPS. NULL is a bare 0x00 (#413).
    from seerdb.common.tns import (
        _THIN_LOB_LOCATOR,
        encode_lob_locator_thin,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    for lob_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        # A CLOB / BLOB carries the locator metadata, sized from the value (#853).
        locator = encode_value('anything', lob_type)
        assert locator == encode_lob_locator_thin(len('anything'), with_metadata=True)
        # sb4 length prefix, then the length-led locator bytes the client keeps.
        assert _THIN_LOB_LOCATOR in locator
        assert encode_value(None, lob_type) == b'\x00'


def test_encode_lob_read_response_thin_carries_content_then_a_success_oer() -> None:
    # The thin READ reply is the whole LOB as LOB_DATA followed by a success OER:
    # the client reads the content, scans to the 04 01 XX OER, and stops (#413).
    from seerdb.common.tns import (
        _THIN_LOB_LOCATOR,
        _oci_lob_data,
        decode_ub4,
        encode_lob_read_response_thin,
    )
    from seerdb.common.tns_consts import TTI_RPA

    content = 'grüße'.encode('utf-16-be')
    reply = encode_lob_read_response_thin(content, is_clob=True)
    assert reply[0] == TTI_LOB
    assert reply.startswith(_oci_lob_data(content))
    # Between the content and the OER sits the return-parameter block: the echoed
    # locator raw (not length-prefixed, the client reads back exactly what it
    # sent) and the amount read, in characters for a CLOB (#903).
    tail = reply[len(_oci_lob_data(content)) :]
    assert tail[0] == TTI_RPA
    assert tail[1 : 1 + len(_THIN_LOB_LOCATOR)] == _THIN_LOB_LOCATOR
    amount, rest = decode_ub4(tail[1 + len(_THIN_LOB_LOCATOR) :])
    assert amount == len(content) // 2  # characters, not bytes
    # The trailing success OER the client scans for (04 01 <status>).
    assert rest.startswith(b'\x04\x01')
    assert encode_lob_read_response_thin(b'').startswith(_oci_lob_data(b''))


def test_lob_data_is_chunked_at_every_length_as_oracle_sends_it() -> None:
    # Oracle frames TTI_LOB content chunked whatever its length (#1970). The
    # expected frames are what live 11g (fv 6) and 23ai (fv 24) sent for BLOB
    # reads of these lengths. A plain <len><data> for 254 bytes put the 0xFE
    # marker in the length byte, so the client read the first content byte as a
    # chunk length and hung.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _lob_data_thin
    from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_23_4

    def x(n: int) -> bytes:
        return b'x' * n

    tok = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        for n in (1, 10, 252, 253, 254, 255):
            assert _lob_data_thin(x(n)) == b'\x0e\xfe' + bytes([n]) + x(n) + b'\x00'
        assert _lob_data_thin(x(256)) == (
            b'\x0e\xfe\xff' + x(255) + b'\x01' + x(1) + b'\x00'
        )
        assert _lob_data_thin(b'') == b'\x0e\x00'
    finally:
        _ENCODE_FIELD_VERSION.reset(tok)

    tok = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_4)
    try:
        for n in (1, 10, 252, 253, 254, 255):
            assert _lob_data_thin(x(n)) == (
                b'\x0e\xfe\x01' + bytes([n]) + x(n) + b'\x00'
            )
        # 23ai sends 256 bytes as one chunk; the Mirror's 255-byte chunks read
        # the same.
        assert _lob_data_thin(x(256)) == (
            b'\x0e\xfe\x01\xff' + x(255) + b'\x01\x01' + x(1) + b'\x00'
        )
    finally:
        _ENCODE_FIELD_VERSION.reset(tok)


def test_lob_read_reply_chunks_in_the_negotiated_versions_framing() -> None:
    # A LOB read reply longer than one chunk uses the negotiated version's chunk
    # framing: 11g a single length byte per chunk, a 12.2+ client the variable-
    # width big-endian (ub4) length its own long-value reader consumes. A read at
    # 11g stays byte-identical to _oci_lob_data. Both must decode back to the
    # content through the client's chunk logic.
    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        _THIN_LOB_LOCATOR,
        _oci_lob_data,
        decode_ub4,
        encode_lob_read_response_thin,
    )
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        FIELD_VERSION_23_1,
        TTI_OER,
        TTI_RPA,
    )

    content = bytes(range(256)) * 3  # 768 bytes → several chunks

    def read_back(reply: bytes, is_12c: bool) -> bytes:
        assert reply[0] == TTI_LOB
        pos = 1
        assert reply[pos] == 0xFE  # chunked marker
        pos += 1
        out = bytearray()
        while True:
            if is_12c:
                length, rest = decode_ub4(reply[pos:])
                pos = len(reply) - len(rest)
            else:
                length, pos = reply[pos], pos + 1
            if length == 0:
                break
            out += reply[pos : pos + length]
            pos += length
        # The return-parameter block now sits between the chunks and the OER.
        assert reply[pos] == TTI_RPA
        pos += 1 + len(_THIN_LOB_LOCATOR)
        _amount, rest = decode_ub4(reply[pos:])
        assert rest[0] == TTI_OER  # the success OER stop signal follows
        return bytes(out)

    tok = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        eleven = encode_lob_read_response_thin(content)
        assert eleven.startswith(_oci_lob_data(content))  # unchanged at 11g
        assert read_back(eleven, is_12c=False) == content
    finally:
        _ENCODE_FIELD_VERSION.reset(tok)

    tok = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    try:
        newer = encode_lob_read_response_thin(content)
        assert newer != eleven
        assert read_back(newer, is_12c=True) == content
    finally:
        _ENCODE_FIELD_VERSION.reset(tok)


def test_parse_lobops_request_classifies_create_temp() -> None:
    # CREATE_TEMP drives the temp-LOB write flow (#412): the Mirror recognises the
    # client's fixed block and the CLOB / BLOB type byte in it.
    from seerdb.common.tns import encode_dictionary_lobops, parse_lobops_request

    for is_blob in (False, True):
        body = encode_dictionary_lobops(
            {'seq': 1, 'create_temp': True, 'is_blob': is_blob}
        )
        req = parse_lobops_request(body)
        assert req.kind == 'create_temp'
        assert req.is_blob is is_blob


def test_parse_lobops_request_extracts_the_write_locator_and_payload() -> None:
    # WRITE carries the locator field and a 0x0E chunked payload; the Mirror
    # pulls both out to append to the temp LOB (#412). Cover both the single-chunk
    # (<= 0xFC) and the multi-chunk (0xFE-marked) payload forms.
    #
    # WRITE reads a real ub2 prefix here, unlike the OPEN / CLOSE / IS_OPEN /
    # GET_LENGTH group, which skip by the declared source length. Making WRITE
    # match them regressed 44 tests: its payload starts immediately after the
    # locator, so a two-byte error in the locator's extent misreads the 0x0E
    # payload marker and corrupts every write (#903/#887).
    from seerdb.common.tns import encode_dictionary_lobops, parse_lobops_request
    from seerdb.common.tns_consts import TNS_LOB_OP_WRITE

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x00'
    for payload in (b'short-payload', bytes(range(256)) * 200):  # 51200 B multi-chunk
        body = encode_dictionary_lobops(
            {
                'seq': 1,
                'operation': TNS_LOB_OP_WRITE,
                'locator': locator,
                'data': payload,
            }
        )
        req = parse_lobops_request(body)
        assert req.kind == 'write'
        # The field carries the ub2 the encoder wrote; resolve() maps it back.
        assert req.locator.endswith(locator)
        assert len(req.locator) == len(locator) + 2
        assert req.payload == payload


def test_temp_lob_responses_round_trip_through_the_client_decoders() -> None:
    # The Mirror's CREATE_TEMP / WRITE replies must parse with the client's own
    # readers: CREATE_TEMP returns the minted locator in a bare RPA, the content-
    # free ack an RPA (skipped by its ub2 length) then a success OER (#412).
    from seerdb.common.tns import (
        decode_lobops_oer,
        encode_create_temp_response,
        encode_lobops_ack,
        mint_temp_lob_locator,
    )

    locator = mint_temp_lob_locator(3, is_blob=True)
    create = encode_create_temp_response(locator)
    # The client reads: 0x08, ub2 length, then the locator bytes.
    assert create[0] == 0x08  # TTI_RPA
    assert int.from_bytes(create[1:3], 'big') == len(locator)
    assert create[3 : 3 + len(locator)] == locator
    # 40 bytes on the wire, as a real server sends: the client allocated that
    # much and reads exactly that much back (#846).
    assert 2 + len(locator) == 40
    # ... and the reply does NOT end at the locator. This test used to assert
    # `create[3:] == locator`, which pinned the defect itself: a client that
    # parses the whole reply reads a character set and a flags byte next, then
    # keeps reading until a status OER ends the response, and waited forever for
    # one. The shape below is what a live 23ai sends.
    tail = create[3 + len(locator) :]
    assert tail[:3] == bytes([0x02, 0x03, 0x69])  # charset 873, AL32UTF8
    assert tail[4] == 0x04  # TTI_OER closes the response
    err_code, _msg = decode_lobops_oer(create, 6)
    assert err_code in (0, 1403)

    ack = encode_lobops_ack(locator)
    err_code, _msg = decode_lobops_oer(ack, 6)
    assert err_code in (0, 1403)  # a success OER, not a real error


def test_minted_temp_clob_locator_declares_utf16be_content() -> None:
    # The reference thin client encodes what it writes to a CLOB by two flag bytes
    # of the locator, read at offsets 6 and 7 of the ub2-prefixed 40 bytes it
    # holds: the variable-length-charset bit (0x80, flag byte 3) and the
    # little-endian bit (0x40, flag byte 4). It writes UTF-16BE when the charset
    # bit is set and the little-endian bit clear, UTF-16LE when both are set, and
    # UTF-8 when the charset bit is clear. The Mirror decodes every temp CLOB as
    # UTF-16BE, so the minted locator must present that exact combination -- the
    # bit clear gave UTF-8 and, once set, an uncleared little-endian bit gave
    # UTF-16LE, and either mojibake'd the bind and killed the session (#903). A
    # BLOB carries no charset and keeps both bytes as-is.
    from seerdb.common.tns import (
        ExecRequest,
        TempLobRef,
        encode_create_temp_response,
        mint_temp_lob_locator,
    )
    from seerdb.server.session import _resolve_temp_lob_binds, _TempLobs

    flag_3, flag_4, var_length_charset, little_endian = 6, 7, 0x80, 0x40
    for index in (0, 7, 0x01020304):
        clob = encode_create_temp_response(mint_temp_lob_locator(index, is_blob=False))[
            1:41
        ]
        assert clob[flag_3] & var_length_charset  # UTF-16...
        assert not clob[flag_4] & little_endian  # ...BE, not LE
        blob = encode_create_temp_response(mint_temp_lob_locator(index, is_blob=True))[
            1:41
        ]
        assert not blob[flag_3] & var_length_charset
    # Distinctness survives the flags: consecutive locators still differ.
    assert len({mint_temp_lob_locator(i, is_blob=False) for i in range(5)}) == 5
    # And the content a client then writes, UTF-16BE, resolves to the value.
    temp_lobs = _TempLobs()
    locator = temp_lobs.mint(is_blob=False)
    temp_lobs.append(locator, 'A test string value'.encode('utf-16-be'))
    ref = TempLobRef(locator, is_blob=False)
    request = ExecRequest(
        'insert into t values (:1)', 0, 1, 0, binds=[ref], bind_rows=[[ref]]
    )
    assert _resolve_temp_lob_binds(request, temp_lobs).binds == ['A test string value']


def test_a_resolved_temp_lob_still_says_it_was_a_lob() -> None:
    # The content of a temp LOB the client bound resolves to a str / bytes that
    # is ALSO a ClobValue / BlobValue, so a backend binding on to Oracle can bind
    # a LOB instead of a VARCHAR2 that refuses it past 32 KB (#1067). An empty
    # one stays the typed BindVar it was (#903); a batch gets typed values too.
    from seerdb.common.tns import ExecRequest, TempLobRef
    from seerdb.server.backend import BindVar, BlobValue, ClobValue
    from seerdb.server.session import _resolve_temp_lob_binds, _TempLobs

    temp_lobs = _TempLobs()
    clob = temp_lobs.mint(is_blob=False)
    temp_lobs.append(clob, ('x' * 40000).encode('utf-16-be'))
    blob = temp_lobs.mint(is_blob=True)
    temp_lobs.append(blob, b'\x00\x01')
    empty = temp_lobs.mint(is_blob=False)
    row = [
        TempLobRef(clob, is_blob=False),
        TempLobRef(blob, is_blob=True),
        TempLobRef(empty, is_blob=False),
        7,
    ]
    request = ExecRequest(
        'insert into t values (:1, :2, :3, :4)', 0, 1, 0, binds=row, bind_rows=[row]
    )
    (c, b, e, n) = _resolve_temp_lob_binds(request, temp_lobs).binds
    assert type(c) is ClobValue and c == 'x' * 40000
    assert type(b) is BlobValue and b == b'\x00\x01'
    assert isinstance(e, BindVar) and e.value == ''
    assert n == 7
    batch = ExecRequest(
        'insert into t values (:1)',
        0,
        2,
        0,
        binds=[row[0]],
        bind_rows=[[row[0]], [row[1]]],
    )
    rows = _resolve_temp_lob_binds(batch, temp_lobs).bind_rows
    assert [type(r[0]) for r in rows] == [ClobValue, BlobValue]


def _lobops_op_request(
    operation: int, locator: bytes, *, seq: int = 1, prefixed: bool = True
) -> bytes:
    # A TTI_LOBOPS request for a state op (FREE_TEMP / OPEN / CLOSE / TRIM /
    # GET_CHUNK_SIZE), built in the shared §14.1 layout with the ub2-prefixed
    # locator — the same field block the client's WRITE / FILE_OPEN encoders use.
    import struct

    from seerdb.common.tns import _fun_header, encode_sb4
    from seerdb.common.tns_consts import FIELD_VERSION_11_2, TTI_LOBOPS

    body = _fun_header(TTI_LOBOPS, seq, FIELD_VERSION_11_2)
    body += bytes([1])  # source pointer present
    # A temp-LOB op declares the locator length PLUS the ub2 prefix; a column
    # LOB sends the locator raw and declares its size alone.
    body += encode_sb4(len(locator) + 2 if prefixed else len(locator))
    body += bytes([0])  # dest pointer absent
    body += encode_sb4(0)  # dest_length
    body += encode_sb4(0)  # short source offset
    body += encode_sb4(0)  # short dest offset
    body += bytes([0, 0, 0])  # charset / short-amount / null-lob pointer flags
    body += encode_sb4(operation)  # operation code
    body += bytes([0, 0])  # scn-array pointer + length
    body += encode_sb4(0)  # source offset (ub8)
    body += encode_sb4(0)  # dest offset (ub8)
    body += bytes([0])  # amount pointer flag
    body += struct.pack('>HHH', 0, 0, 0)  # three reserved ub2 array-LOB slots
    if prefixed:
        body += struct.pack('>H', len(locator)) + locator
    else:
        body += locator  # raw, the way a column LOB carries it
    return body


def test_is_open_reply_echoes_the_locator_raw_then_a_ub1_flag() -> None:
    # The client reads this reply as read_raw_bytes(len(its own locator)) then
    # read_ub1, so the locator goes back RAW -- the ub2 length an ordinary ack
    # carries would shift every following byte and it would take two locator
    # bytes as the flag (#903/#887).
    from seerdb.common.tns import encode_lobops_is_open
    from seerdb.common.tns_consts import TTI_RPA

    locator = bytes.fromhex('0002010c02800001000000010000003ea9cd0001f5d4')
    closed = encode_lobops_is_open(locator, False)
    opened = encode_lobops_is_open(locator, True)

    assert closed[0] == TTI_RPA
    assert closed[1 : 1 + len(locator)] == locator  # raw: no ub2 in between
    # Exactly one byte separates the locator from the status, and it is the flag.
    assert closed[1 + len(locator)] == 0
    assert opened[1 + len(locator)] == 1
    # Nothing else moves between the two answers.
    flag_at = 1 + len(locator)
    assert closed[:flag_at] == opened[:flag_at]
    assert closed[flag_at + 1 :] == opened[flag_at + 1 :]


def test_open_close_errors_are_a_bare_oer() -> None:
    # A failure carries NO locator echo -- captured from 23ai, a second
    # lob.open() comes back as the OER token straight after the data flags
    # (#903/#887). A reply built from the ack with a code swapped in would
    # desync the client.
    from seerdb.common.tns import (
        LOBOPS_ERR_ALREADY_OPEN,
        LOBOPS_ERR_NOT_OPENED,
        encode_lobops_error,
    )
    from seerdb.common.tns_consts import TTI_OER, TTI_RPA

    for code, message in (LOBOPS_ERR_ALREADY_OPEN, LOBOPS_ERR_NOT_OPENED):
        reply = encode_lobops_error(code, message)
        assert reply[0] == TTI_OER, code
        assert reply[0] != TTI_RPA, code
        assert message in reply, code
    assert LOBOPS_ERR_ALREADY_OPEN[0] == 22293
    assert LOBOPS_ERR_NOT_OPENED[0] == 22289
    # The double space after "perform" is the server's own text, not a typo.
    assert b'cannot perform  operation' in LOBOPS_ERR_NOT_OPENED[1]


def test_parse_lobops_request_classifies_the_state_opcodes() -> None:
    # FREE_TEMP releases a temp LOB (its own kind, so the session drops the
    # buffer); OPEN / CLOSE / GET_CHUNK_SIZE are acknowledged; each carries the
    # locator so the reply can echo it (#417). TRIM has since moved out of the
    # acknowledged set -- it carries a new length and is answered with one, the
    # way GET_LENGTH is (#826).
    from seerdb.common.tns import parse_lobops_request
    from seerdb.common.tns_consts import (
        TNS_LOB_OP_CLOSE,
        TNS_LOB_OP_FREE_TEMP,
        TNS_LOB_OP_GET_CHUNK_SIZE,
        TNS_LOB_OP_IS_OPEN,
        TNS_LOB_OP_OPEN,
        TNS_LOB_OP_TRIM,
    )

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x01'
    req = parse_lobops_request(_lobops_op_request(TNS_LOB_OP_FREE_TEMP, locator))
    assert req.kind == 'free_temp'
    assert req.locator == locator
    # OPEN / CLOSE are named apart from the plain acks: the server has to
    # remember the state so IS_OPEN can report it, and so a second open can be
    # refused (#903/#887).
    # OPEN / CLOSE / IS_OPEN take the locator RAW: the client writes it with no
    # length of its own and declares `len(locator)` as the source length, so the
    # declared length is the locator's exactly. GET_CHUNK_SIZE still goes
    # through the older ub2-prefixed walk.
    for op, kind in (
        (TNS_LOB_OP_OPEN, 'open'),
        (TNS_LOB_OP_CLOSE, 'close'),
        (TNS_LOB_OP_IS_OPEN, 'is_open'),
    ):
        req = parse_lobops_request(_lobops_op_request(op, locator, prefixed=False))
        assert req.kind == kind, op
        assert req.locator == locator, op
    chunk = parse_lobops_request(_lobops_op_request(TNS_LOB_OP_GET_CHUNK_SIZE, locator))
    assert chunk.kind == 'ack'
    assert chunk.locator == locator
    # TRIM joins the declared-length group: its reply echoes the locator
    # verbatim, so the parse must hand back the field as sent (#903/#887).
    trim = parse_lobops_request(
        _lobops_op_request(TNS_LOB_OP_TRIM, locator, prefixed=False)
    )
    assert trim.kind == 'trim'
    assert trim.locator == locator


def test_open_close_and_is_open_agree_on_the_locator() -> None:
    # The trio keys a session state off the locator, so all three must extract
    # the SAME bytes. They did not: OPEN stripped a ub2 prefix unconditionally
    # while IS_OPEN skipped by the declared length, so on a RAW locator (what a
    # column LOB sends) one of them keyed on garbage and `isopen()` denied an
    # open it had just accepted (#903/#887).
    from seerdb.common.tns import parse_lobops_request
    from seerdb.common.tns_consts import (
        TNS_LOB_OP_CLOSE,
        TNS_LOB_OP_IS_OPEN,
        TNS_LOB_OP_OPEN,
    )

    raw = bytes.fromhex('0002010c02800001000000010000003ea9cd0001f5d4')
    keys = {
        parse_lobops_request(_lobops_op_request(op, raw, prefixed=False)).locator
        for op in (TNS_LOB_OP_OPEN, TNS_LOB_OP_CLOSE, TNS_LOB_OP_IS_OPEN)
    }
    assert keys == {raw}


def test_parse_lobops_read_extracts_offset_and_amount_from_a_raw_locator() -> None:
    # A column-LOB READ sends the locator RAW (a persistent-LOB op), not the
    # ub2-length-prefixed form a temp op uses. The parser must skip it by the
    # declared source-locator-length, not by reading a 2-byte prefix: reading the
    # first two locator bytes as a length overshot the buffer, threw, and dropped
    # every read to the "whole LOB from offset 1" fallback -- which served the
    # wrong row's content from the read queue (#903). Both framings must parse.
    from seerdb.common.tns import encode_dictionary_lobops, parse_lobops_request
    from seerdb.common.tns_consts import TNS_LOB_OP_READ

    locator = b'\x00seerdb-mirror-lob-locator-0000000000\x00'  # 38 bytes
    for prefixed in (False, True):
        body = encode_dictionary_lobops(
            {
                'seq': 1,
                'operation': TNS_LOB_OP_READ,
                'locator': locator,
                'source_offset': 25000,
                'amount': 10,
                'locator_prefixed': prefixed,
            }
        )
        req = parse_lobops_request(body)
        assert req.kind == 'read', prefixed
        assert req.offset == 25000, prefixed
        assert req.amount == 10, prefixed


def test_parse_exec_decodes_a_temp_lob_bind_as_a_reference() -> None:
    # A CLOB / BLOB bind is the temp-LOB descriptor 01 28 28 | ub2 len | locator,
    # not a plain DALC — parse_exec keeps it as a TempLobRef for the session to
    # resolve (#412). Built with the client's own execute encoder.
    from seerdb.common.datatypes import TempLob
    from seerdb.common.tns import TempLobRef, encode_dictionary_exec, parse_exec

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x01'
    payload = encode_dictionary_exec(
        {
            'seq': 4,
            'field_version': 6,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 0,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'insert into t values (:1, :2)',
                'bind': [7, TempLob(locator, True)],
                'batch': [],
                'def': [],
            },
        }
    )
    request = parse_exec(payload)
    assert request.binds[0] == 7
    ref = request.binds[1]
    assert isinstance(ref, TempLobRef)
    assert ref.locator == locator
    assert ref.is_blob is True


def test_encode_dml_status_oci_carries_the_verb_and_rowcount() -> None:
    # Each DML verb has its own command type (sqlplus reads the verb from the
    # statement-type fields), and the affected-row count rides in the OER where
    # other OERs put the row kind, so sqlplus prints "N rows created/updated/
    # deleted".
    from seerdb.common.tns import _OCI_OER_FROM_OCI, encode_dml_status_oci

    for keyword in ('INSERT', 'UPDATE', 'DELETE'):
        status = encode_dml_status_oci(keyword, 7, sequence=19)
        assert status[:3] == b'\x08\x06\x00'
        assert len(status) == 187
        (oer, _rest) = _OCI_OER_FROM_OCI(
            status[35:], {'oci_12c': False, 'oci_pre12c': True}
        )
        assert oer['row_kind'] == 7

    # The verb templates are distinct — the command-code byte differs per verb.
    codes = {
        kw: encode_dml_status_oci(kw, 1, sequence=19)
        for kw in ('INSERT', 'UPDATE', 'DELETE')
    }
    assert codes['INSERT'] != codes['UPDATE'] != codes['DELETE']

    # An unknown verb (e.g. MERGE) falls back to the INSERT template.
    assert encode_dml_status_oci('MERGE', 3, sequence=19) == encode_dml_status_oci(
        'INSERT', 3, sequence=19
    )

    # Zero rows is representable (DML matching no rows).
    none = encode_dml_status_oci('DELETE', 0, sequence=19)
    pre_12c = {'oci_12c': False, 'oci_pre12c': True}
    assert _OCI_OER_FROM_OCI(none[35:], pre_12c)[0]['row_kind'] == 0


def test_oci_dml_frame_trailer_is_derived_from_the_rowid() -> None:
    # The 16-byte DML status trailer is not stored independently: it carries two
    # of the rowid's big-endian words as ub2s, inside a fixed frame. It must stay
    # byte-identical to the capture and track the rowid.
    from seerdb.common.tns import (
        _OCI_DML_FRAME_TRAILER,
        _OCI_DML_ROWID,
        _oci_dml_frame_trailer,
    )

    assert _OCI_DML_FRAME_TRAILER.hex() == '0d000d010001b57f00010000b4b10000'
    assert _oci_dml_frame_trailer(_OCI_DML_ROWID) == _OCI_DML_FRAME_TRAILER
    # The two byte-swapped rowid words really do come from the rowid.
    assert _OCI_DML_FRAME_TRAILER[6:8] == _OCI_DML_ROWID[0:2][::-1]
    assert _OCI_DML_FRAME_TRAILER[12:14] == _OCI_DML_ROWID[8:10][::-1]


def test_encode_ddl_status_oci_carries_the_command_type() -> None:
    # One frame carries the V$SQL command code at offset 57; sqlplus renders it as
    # "Table created." (1) / "Table dropped." (12) / "Index created." (9) etc. DDL
    # affects no rows — nothing but that field varies.
    from seerdb.common.tns import ddl_command_type, encode_ddl_status_oci

    create = encode_ddl_status_oci(1, sequence=17)
    drop = encode_ddl_status_oci(12, sequence=17)
    for body in (create, drop):
        assert body[:3] == b'\x08\x06\x00'
        assert len(body) == 171
    assert create[57] == 0x01  # CREATE TABLE
    assert drop[57] == 0x0C  # DROP TABLE
    assert create != drop

    # The resolver maps (verb, object) -> V$SQL command type.
    assert ddl_command_type('create table t (x number)') == 1
    assert ddl_command_type('CREATE INDEX ix ON t (x)') == 9
    assert ddl_command_type('drop view v') == 22
    assert ddl_command_type('truncate table t') == 85
    assert ddl_command_type('grant select on t to bob') == 17
    # a bare verb defaults to its TABLE variant; a non-DDL verb is None.
    assert ddl_command_type('alter something') == 15
    assert ddl_command_type('begin null; end;') is None


@pytest.mark.parametrize(
    ('sql', 'command_type'),
    [
        # sqlplus prints its feedback line from this code; each of these fell
        # back to TABLE or to the PL/SQL code before (#2012). The codes are
        # V$SQLCOMMAND's on a live 23ai.
        ("comment on table t is 'x'", 29),
        ('create or replace procedure p as begin null; end;', 24),
        ('CREATE OR REPLACE EDITIONABLE FUNCTION f RETURN NUMBER AS', 91),
        ('create or replace package pk as end;', 94),
        ('create or replace package body pk as end;', 97),
        ('create or replace trigger tr before insert on t begin null; end;', 59),
        ('create or replace type ty as object (a number)', 77),
        ('create or replace type body ty as end;', 81),
        ('create or replace force view v as select 1 x from dual', 21),
        ('create unique index i on t (x)', 9),
        ('create global temporary table g (x int)', 1),
        ("alter session set nls_date_format = 'YYYY-MM-DD'", 42),
        ('alter user u identified by x', 43),
        ('drop procedure p', 68),
        ('drop function f', 93),
        ('drop package pk', 96),
        ('drop public synonym s', 20),
        ('create public database link l connect to u identified by x', 32),
        ('create materialized view log on t', 71),
        ('savepoint a', 46),
        ('set transaction read only', 48),
        ('rename a to b', 28),
        ('call p()', 170),
        ('revoke select on t from bob', 18),
    ],
)
def test_ddl_command_type_follows_v_sqlcommand(sql: str, command_type: int) -> None:
    from seerdb.common.tns import ddl_command_type

    assert ddl_command_type(sql) == command_type


def test_oci_no_row_status_tags_commit_and_rollback() -> None:
    # A bare COMMIT / ROLLBACK typed in sqlplus is executed as a SQL statement
    # (not OCITransCommit), so it reaches the OCI execute path. The Mirror must
    # tag it with its V$SQL command type (44 / 45, captured live from 11g) so
    # sqlplus renders "Commit complete." / "Rollback complete." rather than the
    # generic "PL/SQL procedure successfully completed."
    from seerdb.common.tns import encode_status_oci
    from seerdb.server.session import _oci_no_row_status, _OciSequence

    commit = _oci_no_row_status('COMMIT', 0, _OciSequence())
    rollback = _oci_no_row_status('rollback', 0, _OciSequence())
    plain = _oci_no_row_status('BEGIN NULL; END;', 0, _OciSequence())

    assert commit[:3] == b'\x08\x06\x00'
    assert len(commit) == 171
    assert commit[57] == 44  # OCI_CMD_COMMIT
    assert rollback[57] == 45  # OCI_CMD_ROLLBACK
    # a non-transaction, non-DML/DDL statement still gets the generic status
    assert plain == encode_status_oci(1)  # first _OciSequence.next() is 1


def test_oci_status_frame_prefixes_share_one_builder() -> None:
    # The describe/outbind, DDL and DML exec-status frames all begin with the same
    # 35-byte `08 06` preamble, built by _oci_status_frame_prefix from a cursor id
    # and two statement-kind markers. Each must stay byte-identical to its capture.
    from seerdb.common.tns import (
        _OCI_DDL_FRAME_PREFIX,
        _OCI_DML_FRAME_PREFIX,
        _OCI_STATUS_FRAME_PREFIX,
        _oci_status_frame_prefix,
    )

    assert (
        _OCI_STATUS_FRAME_PREFIX.hex()
        == '0806000000000000000000020000000000000000000000000000000000000000000000'
    )
    assert (
        _OCI_DDL_FRAME_PREFIX.hex()
        == '08060000eb5b0000000000000000000000000000000000000000000000000000000000'
    )
    assert (
        _OCI_DML_FRAME_PREFIX.hex()
        == '08060000e85b0000000000020000000100000000000000000000000000000000000000'
    )
    # Reproduced from the named fields.
    assert _oci_status_frame_prefix(row_producing=True) == _OCI_STATUS_FRAME_PREFIX
    assert _oci_status_frame_prefix(0x5BEB) == _OCI_DDL_FRAME_PREFIX
    assert (
        _oci_status_frame_prefix(0x5BE8, row_producing=True, dml=True)
        == _OCI_DML_FRAME_PREFIX
    )


# A single INTERVAL DAY TO SECOND, INTERVAL YEAR TO MONTH or ROWID column's
# describe from a live 18c to sqlplus 23.26, from the max row size through the
# column's name (#2017). The PEP 249 tuple a passthrough reads gives these no
# length; described with 0, sqlplus sized its row buffer at nothing and crashed.
_OCI_LIVE_DESCRIBE_BODY = {
    'interval_ds': bytes.fromhex(
        '0b000000010000005c01b7000206010000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000010303000000'
        '03494453'
    ),
    'interval_ym': bytes.fromhex(
        '05000000010000005c01b6000200010000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000010303000000'
        '0349594d'
    ),
    'rowid': bytes.fromhex(
        '10000000010000005c010b000000010000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000303000000'
        '03524944'
    ),
}


@pytest.mark.parametrize(
    ('kind', 'column'),
    [
        (
            'interval_ds',
            ColumnMeta(
                name=b'IDS',
                data_type=TNS_TYPE_INTERVALDS,
                data_length=0,
                max_size=0,
                precision=2,
                scale=6,
            ),
        ),
        (
            'interval_ym',
            ColumnMeta(
                name=b'IYM',
                data_type=TNS_TYPE_INTERVALYM,
                data_length=0,
                max_size=0,
                precision=2,
            ),
        ),
        (
            'rowid',
            ColumnMeta(
                name=b'RID',
                data_type=TNS_TYPE_RID,
                data_length=0,
                max_size=0,
                null_ok=0,
            ),
        ),
    ],
)
def test_an_unsized_column_describes_as_a_live_server_does(kind, column) -> None:
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _oci_describe_body
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        body = _oci_describe_body([column])
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    live = _OCI_LIVE_DESCRIBE_BODY[kind]
    assert body[: len(live)] == live


def test_a_rowid_cell_is_four_ub4s() -> None:
    # sqlplus reads a ROWID cell as its four parts, each a ub4 LE; the thin
    # form crashed it (#2017). Four rows of one table, as a live 18c sent them.
    from seerdb.common.tns import _OCI, encode_rowid_value

    live = {
        'AABAomAAMAAAACLAAA': '260a04000c0000008b00000000000000',
        'AABAomAAMAAAACLAAB': '260a04000c0000008b00000001000000',
        'AABAomAAMAAAACLAEr': '260a04000c0000008b0000002b010000',
        'AABAomAAMAAAACMAAp': '260a04000c0000008c00000029000000',
    }
    for rowid, image in live.items():
        assert encode_rowid_value(rowid, _OCI) == b'\x10' + bytes.fromhex(image)


# `cast(1.5 as binary_float) bf, cast(2.5 as binary_double) bd` described by a
# live 18c to sqlplus 23.26, from the max row size through the second name
# (#2018): each column length 1 with no max size, and 4 + 8 toward the max row
# size. A passthrough's PEP 249 tuple gives both their display size, 127, and
# sqlplus refused the column with ORA-03115.
_OCI_LIVE_BINARY_FLOAT_DESCRIBE = bytes.fromhex(
    '0c000000020000005c0164000000010000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000010202000000'
    '0242460000000000000000000000000000016500000001000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000010202000000024244'
)


def test_binary_float_and_double_describe_as_a_live_server_does() -> None:
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _oci_describe_body
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    columns = [
        ColumnMeta(
            name=b'BF', data_type=TNS_TYPE_BFLOAT, data_length=127, max_size=127
        ),
        ColumnMeta(
            name=b'BD', data_type=TNS_TYPE_BDOUBLE, data_length=127, max_size=127
        ),
    ]
    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        body = _oci_describe_body(columns)
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    live = _OCI_LIVE_BINARY_FLOAT_DESCRIBE
    assert body[: len(live)] == live


# `timestamp '2024-01-02 03:04:05 +02:00' tz` described by a live 18c to
# sqlplus 23.26 (#2018): length 1, no max size, 13 toward the max row size.
# A passthrough's PEP 249 tuple gives it a display size of 23.
_OCI_LIVE_TIMESTAMPTZ_DESCRIBE = bytes.fromhex(
    '0d000000010000005c01b5000009010000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000010202000000'
    '02545a'
)


def test_timestamp_with_time_zone_describes_as_a_live_server_does() -> None:
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _oci_describe_body
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    column = ColumnMeta(
        name=b'TZ',
        data_type=TNS_TYPE_TIMESTAMPTZ,
        data_length=23,
        max_size=23,
        scale=9,
    )
    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        body = _oci_describe_body([column])
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    live = _OCI_LIVE_TIMESTAMPTZ_DESCRIBE
    assert body[: len(live)] == live


@pytest.mark.parametrize(
    ('value', 'image'),
    [
        # The wall clock at the offset, the offset hour with 0x40 set (#2018).
        (
            datetime.datetime(
                2024,
                1,
                2,
                3,
                4,
                5,
                500000,
                tzinfo=datetime.timezone(-datetime.timedelta(hours=5, minutes=30)),
            ),
            '787c01020405061dcd65004f1e',
        ),
        (
            datetime.datetime(2024, 7, 1, 12, 0, tzinfo=datetime.timezone.utc),
            '787c07010d010100000000543c',
        ),
        # Just after midnight local is the previous day in UTC; the cell keeps
        # its own date.
        (
            datetime.datetime(
                2024, 1, 1, 0, 30, tzinfo=datetime.timezone(datetime.timedelta(hours=2))
            ),
            '787c0101011f0100000000563c',
        ),
    ],
)
def test_a_timestamp_with_time_zone_cell_is_its_wall_clock(value, image) -> None:
    from seerdb.common.tns import _oci_timestamptz_value

    assert _oci_timestamptz_value(value) == b'\x0d' + bytes.fromhex(image)


# A CLOB and a BLOB column's describe from a live 18c to sqlplus 23.26, from
# the max row size through the name (#2019): a data length of 4000. The PEP 249
# tuple a passthrough reads gives a LOB no size; described with 0, sqlplus took
# the column for one that sends nothing and hung on the row. Fixed by the
# wire-length fallback of #2044; kept here as that ticket's regression test.
_OCI_LIVE_LOB_DESCRIBE = {
    'clob': bytes.fromhex(
        '00000000010000005c0170800000a00f00000000000000000000000000000000'
        '00000000000000000000000000006903010000000000fe3f0000010101000000'
        '0143'
    ),
    'blob': bytes.fromhex(
        '00000000010000005c0171000000a00f00000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000010101000000'
        '0142'
    ),
}


@pytest.mark.parametrize(
    ('kind', 'column'),
    [
        (
            'clob',
            ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=0, max_size=0),
        ),
        (
            'blob',
            ColumnMeta(name=b'B', data_type=TNS_TYPE_BLOB, data_length=0, max_size=0),
        ),
    ],
)
def test_a_passthrough_lob_column_describes_as_a_live_server_does(kind, column) -> None:
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _oci_describe_body
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        body = _oci_describe_body([column])
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    live = _OCI_LIVE_LOB_DESCRIBE[kind]
    assert body[: len(live)] == live


def test_read_chunked_sql_reassembles_the_chunks() -> None:
    # Long OCI SQL is chunked: 0xFE marker, then <ub1 len><chunk> runs. The reader
    # reassembles them up to the declared total (#265), and says where the last
    # one ends, which is where a bound statement's binds are looked for (#2028).
    from seerdb.common.tns import _read_chunked_sql

    data = b'\xfe\x03abc\x02de\x00tail'
    assert _read_chunked_sql(data, 5) == (b'abcde', 8)
    assert _read_chunked_sql(data, 9) == (b'abcde', 9)


def test_encode_error_oci_matches_the_captured_ora_error() -> None:
    # Byte-for-byte against a real 11g OCI error reply (ORA-00942): the OER frame
    # with call-status 0x05, the code at offset 12, and the message (#265, #350).
    from seerdb.common.tns import encode_error_oci

    captured = bytes.fromhex(
        '040500000013000100000000ae030000000002000e0003000000000000000000'
        '0000000000000000000000000000000000150000010000003601000000000000'
        '000000000000000020f6310a0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000284f52412d30303934323a207461626c65206f7220766965'
        '7720646f6573206e6f742065786973740a'
    )
    # sequence 0x13 is the reply's own counter; 0x15 the sequence of the call it
    # answered, which the capture carries at offset 49 (#884).
    token = _ENCODE_OCI_CALL_SEQ.set(0x15)
    try:
        assert (
            encode_error_oci(942, 'table or view does not exist', sequence=0x13)
            == captured
        )
    finally:
        _ENCODE_OCI_CALL_SEQ.reset(token)


def test_oci_dcb_tail_is_column_aware() -> None:
    # The DCB tail carries the column count; the client reads it to parse each
    # row, so it is load-bearing for a multi-column result (#265, #346).
    from seerdb.common.tns import _OCI_RXH_FROM_OCI, _oci_dcb_tail

    for count in (1, 3):
        (rxh, rest) = _OCI_RXH_FROM_OCI(_oci_dcb_tail(count)[33:])
        assert (rxh['unpinned_4'], rest) == (count, b'')
    # Its `06 01 22` head, which the client cannot do without.
    assert _oci_dcb_tail(2)[33:36] == bytes.fromhex('060122')


def test_encode_query_response_oci_signals_more_rows() -> None:
    # more=True sets the status's error-position byte, which sqlplus reads as
    # "fetch for the rest" (#351).
    from seerdb.common.tns import _OCI_OER_FROM_OCI, encode_query_response_oci

    col = ColumnMeta(
        name=b'N', data_type=TNS_TYPE_NUMBER, data_length=2, max_size=0, scale=-127
    )
    done = encode_query_response_oci([col], [(1,)], sequence=19, more=False)
    more = encode_query_response_oci([col], [(1,)], sequence=19, more=True)
    pre_12c = {'oci_12c': False, 'oci_pre12c': True}
    assert _OCI_OER_FROM_OCI(more[-136:], pre_12c)[0]['error_pos'] == 0x1E
    assert _OCI_OER_FROM_OCI(done[-136:], pre_12c)[0]['error_pos'] == 0


def test_encode_fetch_batch_oci_carries_rows_and_terminator() -> None:
    # A fetch batch: RXH + one RXD per remaining row + the end-of-fetch OER (#351).
    from seerdb.common.tns import encode_fetch_batch_oci

    col = ColumnMeta(
        name=b'N', data_type=TNS_TYPE_NUMBER, data_length=2, max_size=0, scale=-127
    )
    batch = encode_fetch_batch_oci([col], [(1,), (2,)], sequence=20)
    assert batch[0] == 0x06  # TTI_RXH token
    assert batch.count(b'\x07\x02\xc1') == 2  # two RXD rows (07 + NUMBER DALC)
    assert batch.endswith(b'ORA-01403: no data found\n')


def test_parse_exec_oci_extracts_bind_values() -> None:
    # A live sqlplus bound execute — SELECT :n, :s FROM dual with :n=42 (NUMBER),
    # :s='hello' (VARCHAR). The bind count is in the header; the OAC markers give
    # each type and the RXD row carries the values (#265, #347).
    bound = bytes.fromhex(
        '035e176980000000000000feffffffffffffff4500000000000000feffffffffffffff'
        '0d00000000000000fefffffffffffffffeffffffffffffff0000000001000000000000'
        '0000000000feffffffffffffff02000000000000000000000000000000feffffffffff'
        'ffff0000000000000000fefffffffffffffffefffffffffffffff815aa0f0000000000'
        '00000000000000fefffffffffffffffeffffffffffffff000000000000000000000000'
        '00000000000000000000000000000000000000001753454c454354203a6e2c203a7320'
        '46524f4d206475616c0100000000000000000000000000000000000000000000000000'
        '0000010000000000000000000000000000000000000000000000010203000016000000'
        '0000000000000000000000000000000000000000000000000000000000000000010103'
        '00001e0000000000000000000000000000000000000000000000690301000000000000'
        '0000000702c12b0568656c6c6f'
    )
    req = parse_exec_oci(bound)
    assert req.sql == 'SELECT :n, :s FROM dual'
    assert req.bind_count == 2
    assert req.binds == [42, 'hello']


def test_encode_out_bind_response_oci_matches_captured_11g_reply() -> None:
    # The sqlplus `EXEC :n := 7` OUT-bind reply, captured live from 11g and
    # normalised (the server pointer, SCN and an internal sequence counter, which
    # are instance-specific, zeroed). The encoder reproduces it byte-for-byte: a
    # ttc=0b01 body with the bind count at offset 4, one 0x10 define marker, an
    # RXD row (07 + NUMBER 7 DALC + a 2-byte return code) and the fixed tail (#347).
    from seerdb.common.tns import encode_out_bind_response_oci

    captured_n7 = bytes.fromhex(
        '0b0105cc010000000000010000000000000000000000000000000000e80700000000000000'
        '00000000000000000000000000100702c10800000806000000000000000000020000000000'
        '00000000000000000000000000000000000004010000000000010100000000000000000002'
        '0000002f000000000000000000000000000000000000000000000000000000000001000000'
        '3601000000000000000000000000000020f6310a0000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000000000'
        '000000000000'
    )
    assert encode_out_bind_response_oci([7], sequence=0) == captured_n7


def test_encode_out_bind_response_oci_marshals_each_bind() -> None:
    # Bind count (offset 4) and one 0x10 define marker per OUT value; the RXD row
    # carries each value as a DALC followed by a 2-byte per-bind return code. A
    # VARCHAR OUT bind rides the same frame as a NUMBER one (#347).
    from seerdb.common.tns import encode_out_bind_response_oci
    from seerdb.common.tns_consts import TTI_RXD

    two = encode_out_bind_response_oci([7, 9], sequence=0)
    assert two[4] == 2  # bind count
    assert two[50:52] == b'\x10\x10'  # one define marker per bind
    rxd = two[52:]
    assert rxd[0] == TTI_RXD
    # 07 | 02 c1 08 (NUMBER 7) 00 00 | 02 c1 0a (NUMBER 9) 00 00
    assert rxd[:11] == bytes.fromhex('0702c108000002c10a0000')

    text = encode_out_bind_response_oci(['hi'], sequence=0)
    assert text[4] == 1
    assert text[51:].startswith(bytes.fromhex('0702686900'))  # 07 + 'hi' DALC


def test_a_national_out_value_goes_back_as_utf16() -> None:
    # A live 18c answers sqlplus 23.26's `EXEC :nch5 := 'kl'` for an NCHAR(5)
    # and `EXEC :nvc9 := 'mno'` for an NVARCHAR2(9) with the values in UTF-16BE,
    # each behind its define marker and before its return code. In the database
    # character set, sqlplus held `?` (#2239).
    from seerdb.common.tns import encode_out_bind_response_oci

    for value, live in (
        ('kl   ', '10070a006b006c0020002000200000'),
        ('mno', '10070600' + '6d006e006f0000'),
    ):
        reply = encode_out_bind_response_oci([value], sequence=0, forms=[2])
        assert reply[50:].startswith(bytes.fromhex(live))
    # The database form keeps its own character set.
    reply = encode_out_bind_response_oci(['mno'], sequence=0, forms=[1])
    assert reply[50:].startswith(bytes.fromhex('1007036d6e6f0000'))


# --- Server-side scrollable cursors (#181/#485) ---------------------------------


def _scroll_exec(cursor: int, orientation: int, position: int, fetch: int) -> bytes:
    # Build a SCROLLABLE OALL8 the way the thin client marshals a scroll
    # re-execute (an open cursor, empty query, the orientation/position in the
    # al8i4 array). field_version 6 is the Mirror's advertised 11.2 layout.
    from seerdb.common.tns import encode_dictionary_exec
    from seerdb.common.tns_consts import FIELD_VERSION_11_2

    return encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': FIELD_VERSION_11_2,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': fetch,
                'server_version': VERSION_11_2_0_2,
                'cursor': cursor,
                'query': '',
                'bind': [],
                'batch': [],
                'def': [],
                'scrollable': True,
                'scroll': (orientation, position),
            },
        }
    )


def test_parse_exec_reads_scroll_request() -> None:
    from seerdb.common.tns_consts import (
        TNS_FETCH_ORIENTATION_ABSOLUTE,
        TNS_FETCH_ORIENTATION_LAST,
    )

    # A scroll re-execute: the SCROLLABLE flag plus orientation + 1-based position
    # ride the al8i4 array (indices 9/10/11), which parse_exec now decodes even
    # though the message carries no binds.
    req = parse_exec(_scroll_exec(7, TNS_FETCH_ORIENTATION_ABSOLUTE, 5, 3))
    assert req.scrollable is True
    assert req.cursor == 7
    assert req.scroll_orientation == TNS_FETCH_ORIENTATION_ABSOLUTE
    assert req.scroll_position == 5

    last = parse_exec(_scroll_exec(7, TNS_FETCH_ORIENTATION_LAST, 0, 3))
    assert last.scroll_orientation == TNS_FETCH_ORIENTATION_LAST

    # A plain (non-scrollable) execute leaves the flag clear.
    from seerdb.common.tns import encode_dictionary_exec

    plain = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 15,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'select 1 from dual',
                'bind': [],
                'batch': [],
                'def': [],
            },
        }
    )
    assert parse_exec(plain).scrollable is False


def test_scroll_start_row_maps_orientation() -> None:
    from seerdb.common.tns import scroll_start_row
    from seerdb.common.tns_consts import (
        TNS_FETCH_ORIENTATION_ABSOLUTE,
        TNS_FETCH_ORIENTATION_FIRST,
        TNS_FETCH_ORIENTATION_LAST,
    )

    assert scroll_start_row(TNS_FETCH_ORIENTATION_FIRST, 0, 10) == 1
    assert scroll_start_row(TNS_FETCH_ORIENTATION_LAST, 0, 10) == 10
    # ABSOLUTE / RELATIVE / CURRENT take the client's already-absolute position.
    assert scroll_start_row(TNS_FETCH_ORIENTATION_ABSOLUTE, 4, 10) == 4
    # An empty result set has no last row.
    assert scroll_start_row(TNS_FETCH_ORIENTATION_LAST, 0, 0) == 0


def test_scroll_terminator_carries_rowcount_and_eof() -> None:
    from seerdb.common.tns import _scroll_terminator, decode_token_oer

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)

    # Mid-stream: the OER carries the cumulative row number (absolute position of
    # the last row delivered) and no ORA-01403, so the client keeps scrolling.
    more = decode_token_oer(
        _scroll_terminator(0, server_rowcount=6, eof=False), (0, [], [])
    )
    assert more[1] == 0  # not end-of-fetch
    assert more[3][0] == 6  # cumulative row number

    # A batch that reaches the end terminates with ORA-01403 (still carrying the
    # cumulative row number).
    end = decode_token_oer(
        _scroll_terminator(0, server_rowcount=6, eof=True), (0, [], [])
    )
    assert end[1] == 1403
    assert end[3][0] == 6

    # The opening execute's terminator ties in the kept-open cursor id.
    opened = decode_token_oer(
        _scroll_terminator(9, server_rowcount=2, eof=False), (0, [], [])
    )
    assert opened[2] == 9


def test_scroll_response_bodies_frame_rows_and_describe() -> None:
    from seerdb.common.tns import (
        _scroll_terminator,
        encode_rows,
        encode_scroll_open_response,
        encode_scroll_response,
    )
    from seerdb.common.tns_consts import TTI_DCB, TTI_RXH

    col = ColumnMeta(name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)

    # The open leads with a describe (DCB); the re-execute leads with the row
    # header (RXH) and omits the describe. Both end with the scroll terminator.
    opened = encode_scroll_open_response(
        [col], [(1,), (2,)], cursor_id=9, server_rowcount=2, eof=False
    )
    assert opened[0] == TTI_DCB
    assert encode_rows([(1,), (2,)], [col]) in opened  # the prefetched batch
    assert opened.endswith(_scroll_terminator(9, server_rowcount=2, eof=False))

    reexec = encode_scroll_response([col], [(6,)], server_rowcount=6, eof=True)
    assert reexec[0] == TTI_RXH  # no describe on a reposition
    assert reexec.endswith(_scroll_terminator(0, server_rowcount=6, eof=True))

    # Scrolled off the end: an empty batch (header only) ending in ORA-01403.
    off = encode_scroll_response([], [], server_rowcount=0, eof=True)
    assert off == encode_rows([], []) + _scroll_terminator(
        0, server_rowcount=0, eof=True
    )


# --- INTERVAL DAY TO SECOND / YEAR TO MONTH (#484) -----------------------------


def test_encode_value_native_boolean_is_one_byte_and_decodes_back() -> None:
    # A native SQL BOOLEAN column value (23ai) is a one-byte DALC — 0x01 for TRUE,
    # 0x00 for FALSE — which the client's decode_value reads by its last byte. A
    # bool must take this path, not the NUMBER-0/1 fallback: NUMBER 0 encodes to
    # 0x80, whose last byte is non-zero, so FALSE would read back as TRUE.
    from seerdb.common.tns import encode_value
    from seerdb.common.tns_consts import TNS_TYPE_BOOLEAN
    from seerdb.common.types import decode_value

    col = {'data_type': TNS_TYPE_BOOLEAN}
    assert encode_value(True, TNS_TYPE_BOOLEAN) == bytes([1, 1])
    assert encode_value(False, TNS_TYPE_BOOLEAN) == bytes([1, 0])
    # The DALC content (past the length byte) round-trips through the decoder.
    assert decode_value(col, encode_value(True, TNS_TYPE_BOOLEAN)[1:]) is True
    assert decode_value(col, encode_value(False, TNS_TYPE_BOOLEAN)[1:]) is False


def test_encode_value_dispatches_interval_columns() -> None:
    import datetime

    from seerdb.common.datatypes import IntervalYM
    from seerdb.common.tns import (
        encode_token_interval_ds,
        encode_token_interval_ym,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM

    # The scalar-value encoder must route an INTERVAL column's Python value
    # (timedelta / IntervalYM) to the interval encoder, DALC-wrapped — otherwise
    # it falls through to the isinstance chain and raises, dropping the wire.
    td = datetime.timedelta(days=1, hours=2)
    assert encode_value(td, TNS_TYPE_INTERVALDS) == bytes(
        [11]
    ) + encode_token_interval_ds(td)
    iy = IntervalYM(1, 2)
    assert encode_value(iy, TNS_TYPE_INTERVALYM) == bytes(
        [5]
    ) + encode_token_interval_ym(iy)
    # NULL stays the empty DALC regardless of type.
    assert encode_value(None, TNS_TYPE_INTERVALDS) == bytes([0])


# --- LONG / LONG RAW inline column values (#484) -------------------------------


@pytest.mark.parametrize('version', [6, 17])  # 11g single-byte / 12.2+ ub4 chunks
def test_encode_long_value_thin_roundtrips_via_client_reader(version: int) -> None:
    # The inline LONG value chunks in the session's negotiated framing (a single
    # length byte per chunk at 11g, a ub4 from 12.2 up); the client's reader at
    # that same version must recover the content and stop exactly at its end.
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        _ENCODE_FIELD_VERSION,
        _read_long_column,
        encode_long_value_thin,
    )

    e_tok = _ENCODE_FIELD_VERSION.set(version)
    d_tok = _DECODE_FIELD_VERSION.set(version)
    try:
        for content in (
            b'hello',
            b'x' * 700,  # multi-chunk
            b'',
            ('café — 日本').encode('utf-8'),
        ):
            # A trailing sentinel proves the two ub4 indicators are consumed and
            # the reader stops exactly at the value's end (no desync).
            val, rest = _read_long_column(encode_long_value_thin(content) + b'\xaa\xbb')
            assert val == content
            assert rest == b'\xaa\xbb'

        # A NULL LONG still carries the trailing indicators, so the reader realigns.
        val, rest = _read_long_column(encode_long_value_thin(None) + b'\xaa\xbb')
        assert val is None
        assert rest == b'\xaa\xbb'
    finally:
        _ENCODE_FIELD_VERSION.reset(e_tok)
        _DECODE_FIELD_VERSION.reset(d_tok)


def test_encode_value_routes_long_columns_and_null_carries_trailers() -> None:
    from seerdb.common.tns import encode_long_value_thin, encode_value
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TNS_TYPE_LONGRAW

    # A LONG / LONG RAW column must use the inline streaming form, not a DALC —
    # and a NULL LONG must still carry the two trailing indicators (the bare-0x00
    # DALC NULL would desync the client's _read_long_column).
    assert encode_value('abc', TNS_TYPE_LONG) == encode_long_value_thin('abc')
    assert encode_value(b'\x00\x01', TNS_TYPE_LONGRAW) == encode_long_value_thin(
        b'\x00\x01'
    )
    assert encode_value(None, TNS_TYPE_LONG) == encode_long_value_thin(None)
    assert encode_value(None, TNS_TYPE_LONG) != bytes([0])  # not the DALC NULL


# --- ROWID / UROWID column values (#484) ---------------------------------------


def test_string_to_rowid_inverts_rowid_to_string() -> None:
    from seerdb.common.types import rowid_to_string, string_to_rowid

    for text in ('AAAAB0AABAAAAOhAAA', 'AAAK6JAAEAAACGPAAA'):
        obj, file, block, slot = string_to_rowid(text)
        assert rowid_to_string(obj, file, block, slot) == text


def test_encode_rowid_value_roundtrips_via_client_reader() -> None:
    from seerdb.common.tns import _read_rowid_column, encode_rowid_value

    for text in ('AAAAB0AABAAAAOhAAA', 'AAAK6JAAEAAACGPAAA'):
        val, rest = _read_rowid_column(encode_rowid_value(text) + b'\xaa')
        assert val == text
        assert rest == b'\xaa'
    # A NULL rowid is a bare present-indicator the reader reports as None.
    val, rest = _read_rowid_column(encode_rowid_value(None) + b'\xaa')
    assert val is None
    assert rest == b'\xaa'


def test_encode_urowid_value_roundtrips_via_client_reader() -> None:
    from seerdb.common.tns import _read_urowid_column, encode_urowid_value

    for text in ('*BAEALAMCwQL+', '*BAEAGYMCwQL+'):
        val, rest = _read_urowid_column(encode_urowid_value(text) + b'\xaa')
        assert val == text
        assert rest == b'\xaa'
    val, rest = _read_urowid_column(encode_urowid_value(None) + b'\xaa')
    assert val is None
    assert rest == b'\xaa'


def test_urowid_value_roundtrips_the_chunked_long_form() -> None:
    # A large UROWID (an index-organized table's rowid, 300+ bytes) exceeds the
    # 252-byte single-length limit and rides in the 0xFE-chunked form, like a
    # LONG value. Reading it as one length-prefixed block desynced the row and
    # left a stray 0xFE that the token loop rejected ("no decoder for response
    # token 254", #904); encoding it raised on bytes([>255]). Round-trip both the
    # 12c+ ub4-length chunk form and the pre-12c single-byte one.
    import base64

    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        _ENCODE_FIELD_VERSION,
        _read_urowid_column,
        encode_urowid_value,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_23_1

    # a ~400-byte rowid body -> the "*"+base64 form a decoded UROWID takes
    big = '*' + base64.b64encode(bytes(range(200)) * 2).decode('ascii').rstrip('=')
    for version in (FIELD_VERSION_11_2, FIELD_VERSION_23_1):
        et = _ENCODE_FIELD_VERSION.set(version)
        dt = _DECODE_FIELD_VERSION.set(version)
        try:
            wire = encode_urowid_value(big)
            assert bytes([0xFE]) in wire[:6], version  # chunked, not single-length
            val, rest = _read_urowid_column(wire + b'\xaa')
        finally:
            _ENCODE_FIELD_VERSION.reset(et)
            _DECODE_FIELD_VERSION.reset(dt)
        assert val == big, version
        assert rest == b'\xaa', version


def test_encode_value_routes_rowid_columns() -> None:
    from seerdb.common.tns import (
        encode_rowid_value,
        encode_urowid_value,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_RID, TNS_TYPE_UROWID

    assert encode_value('AAAAB0AABAAAAOhAAA', TNS_TYPE_RID) == encode_rowid_value(
        'AAAAB0AABAAAAOhAAA'
    )
    assert encode_value('*BAEALAMCwQL+', TNS_TYPE_UROWID) == encode_urowid_value(
        '*BAEALAMCwQL+'
    )


# --- National char (NCHAR / NVARCHAR) bind decode (#484) ------------------------


def test_decode_oac_fields_exposes_csfrm() -> None:
    from seerdb.common.tns import decode_oac_fields, decode_token_oac, encode_tokens_oac

    # Build the OAC bytes the client sends for one VARCHAR bind, then confirm the
    # new decoder surfaces the charset-form byte the 5-tuple form drops, and an
    # empty type OID (a scalar bind carries none).
    oac = encode_tokens_oac(['hi'], b'')
    dtype, maxlen, scale, charset, csfrm, toid, rest = decode_oac_fields(oac)
    assert csfrm == 1  # an ordinary (DB) char bind
    assert toid == b''  # a scalar bind has no referenced-type OID
    # The 5-tuple form stays byte-compatible (same fields minus csfrm / toid).
    assert (dtype, maxlen, scale, charset, rest) == decode_token_oac(oac, ())


def test_decode_bind_value_honours_national_csfrm() -> None:
    from seerdb.common.tns import _decode_bind_value
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

    text = 'café—Ω—日本'
    raw = text.encode('utf-16-be')  # how an NCHAR / NVARCHAR bind arrives
    # csfrm 2 (national) decodes UTF-16BE; csfrm 1 (ordinary) mojibakes it.
    assert _decode_bind_value(TNS_TYPE_VARCHAR, 2, raw) == text
    assert _decode_bind_value(TNS_TYPE_VARCHAR, 1, raw) != text
    # A NULL bind stays None regardless of form.
    assert _decode_bind_value(TNS_TYPE_VARCHAR, 2, b'') is None


# --- PL/SQL OUT binds: thin IOV response (#483) --------------------------------


def test_encode_out_bind_response_thin_roundtrips_via_client() -> None:
    from seerdb.client.cursor import _assign_out_binds
    from seerdb.common.datatypes import NUMBER, STRING, Var
    from seerdb.common.tns import (
        ScalarOutBind,
        decode_packet,
        encode_out_bind_response_thin,
    )
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    # callproc([21, out NUMBER, io VARCHAR]) — the Mirror marks every bind IN OUT
    # and returns each value; the client keeps only the positions it bound as a Var.
    resp = encode_out_bind_response_thin(
        [
            ScalarOutBind(21, TNS_TYPE_NUMBER),
            ScalarOutBind(42, TNS_TYPE_NUMBER),
            ScalarOutBind('hi!', TNS_TYPE_VARCHAR),
        ]
    )
    v_out, v_io = Var(NUMBER), Var(STRING, 100)
    bind = [21, v_out, v_io]
    result = decode_packet(resp, (0, [], [], bind))
    assert result[1] == 0  # success OER
    record = result[4][0]
    assert record['out_positions'] == [0, 1, 2]
    assert record['directions'] == [48, 48, 48]  # all IN OUT (#1363)
    # The client assigns only its Var positions; the plain IN value 0 is skipped.
    assert _assign_out_binds(bind, result) == []
    assert v_out.getvalue() == 42
    assert v_io.getvalue() == 'hi!'


def test_a_binds_charset_form_reaches_the_backend() -> None:
    # A national bind is not a distinct TNS type -- NVARCHAR2 is VARCHAR with
    # csfrm 2 -- so a backend handed tns_type alone resolves the wrong type and
    # binds NVARCHAR2 as VARCHAR2 upstream. A PL/SQL table of the former then
    # rejects it with PLS-00418 (#990). The form rides on the OAC and the Mirror
    # already keeps it; it simply never reached BindVar.
    from dataclasses import replace

    from seerdb.server.backend import BindVar
    from seerdb.server.session import _bind_vars

    seeded = Var(str, is_array=True, num_elements=3)
    seeded.setvalue(0, ['a', 'b'])
    msg = _client_exec_request(
        17, 'BEGIN p(:1, :2); END;', [seeded, 'plain'], kind='block'
    )
    with _at_field_version(17):
        req = parse_exec(msg)
    # Force the national form on the first bind, as an NVARCHAR OAC would.
    req = replace(
        req,
        bind_types=[
            (t, 2 if i == 0 else 1, m, o)
            for i, (t, _c, m, o) in enumerate(req.bind_types)
        ],
    )
    binds = _bind_vars(req)
    assert all(isinstance(b, BindVar) for b in binds)
    assert [b.csfrm for b in binds] == [2, 1]


def test_the_describe_relays_a_vector_columns_flags() -> None:
    # A VECTOR column that allows ANY number of dimensions says so with a flag,
    # and the count beside it is 0. Zeroing the flag tells the client the column
    # allows exactly none -- a different claim, and a wrong one (#1013).
    from seerdb.common.tns import ColumnMeta, encode_describe
    from seerdb.common.tns_consts import (
        FIELD_VERSION_23_4,
        TNS_TYPE_VECTOR,
        VECTOR_FLAG_FLEXIBLE_DIM,
    )

    def described(**kw) -> bytes:
        col = ColumnMeta(
            name=b'V',
            data_type=TNS_TYPE_VECTOR,
            data_length=0,
            max_size=0,
            **kw,
        )
        with _at_field_version(FIELD_VERSION_23_4):
            return encode_describe([col])

    flexible = described(
        vector_dimensions=0, vector_format=2, vector_flags=VECTOR_FLAG_FLEXIBLE_DIM
    )
    fixed = described(vector_dimensions=16, vector_format=2, vector_flags=0)
    # The two describes differ, and by more than the dimension count: without
    # the flag a client reads the flexible column's 0 as a real answer.
    assert flexible != fixed
    assert VECTOR_FLAG_FLEXIBLE_DIM in flexible

    # A column with no vector metadata at all still encodes a zero flag.
    plain = described()
    assert plain != flexible


def test_an_unopened_ref_cursor_is_reported_with_id_zero() -> None:
    # A REF cursor the block never OPENED is reported with cursor id 0 and no
    # columns. The client keys on the id -- executing a ref cursor whose id is 0
    # with no statement of its own is what makes it raise. Parking it like any
    # other cursor handed the caller a valid handle, so a fetch returned nothing
    # instead of failing: silently empty, which cannot be told from a cursor
    # opened over no rows (#1016).
    from seerdb.common.tns import ColumnMeta, RefCursorOutBind
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import CursorResult
    from seerdb.server.session import _Cursors, _out_bind_entries

    cursors = _Cursors()
    col = ColumnMeta(name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22)

    (never_opened,) = _out_bind_entries(
        [CursorResult(columns=[], rows=[])], [(102, 4)], cursors
    )
    assert isinstance(never_opened, RefCursorOutBind)
    assert never_opened.cursor_id == 0
    assert never_opened.columns == []

    # An opened one still gets a real id and is parked for the client to drain.
    (opened,) = _out_bind_entries(
        [CursorResult(columns=[col], rows=[(1,)])], [(102, 4)], cursors
    )
    assert isinstance(opened, RefCursorOutBind)
    assert opened.cursor_id != 0
    assert cursors.has(opened.cursor_id)


def test_a_ref_cursor_out_bind_parks_the_cursors_in_its_rows() -> None:
    # A REF CURSOR whose rows hold a CURSOR(...) column: each of those inner
    # cursors needs a parked id of its own, as a query's do, or the
    # CursorResult reaches the row encoder when the client drains the REF
    # CURSOR and the session dies with "no wire encoding for a column value of
    # type CursorResult" (#1465).
    from seerdb.common.tns import ColumnMeta, NestedCursor, RefCursorOutBind
    from seerdb.common.tns_consts import TNS_TYPE_REFCURSOR, TNS_TYPE_VARCHAR
    from seerdb.server.backend import CursorResult
    from seerdb.server.session import _Cursors, _out_bind_entries

    leaf = ColumnMeta(
        name=b'V', data_type=TNS_TYPE_VARCHAR, data_length=10, max_size=10
    )
    inner = ColumnMeta(
        name=b'C', data_type=TNS_TYPE_REFCURSOR, data_length=5, max_size=0
    )
    deep = CursorResult(columns=[leaf], rows=[('deep',)])
    cursors = _Cursors()
    (entry,) = _out_bind_entries(
        [CursorResult(columns=[inner], rows=[(deep,)])], [(102, 4)], cursors
    )
    assert isinstance(entry, RefCursorOutBind)
    _cols, parked = cursors.take(entry.cursor_id, 10)
    nested = parked[0][0]
    assert isinstance(nested, NestedCursor)
    assert nested.cursor_id != entry.cursor_id
    assert cursors.take(nested.cursor_id, 10)[1] == [('deep',)]


def test_a_vector_out_bind_carries_its_image_not_a_locator() -> None:
    # A VECTOR is never fetched over TTI_LOBOPS -- the server prefetches the
    # whole value into the reply. That was settled for COLUMNS in #887 and for
    # RETURNING binds in §22.1c; the OUT-bind carrier was still minting a
    # locator, 41 bytes whatever the value, and the client ran off the end of it
    # (#1010).
    import array
    from collections.abc import Iterable
    from typing import cast

    from seerdb.common.tns import _encode_out_bind_value, _read_lob_bind_value
    from seerdb.common.tns_consts import TNS_TYPE_VECTOR

    small = _encode_out_bind_value(array.array('f', [1.5] * 4), TNS_TYPE_VECTOR)
    large = _encode_out_bind_value(array.array('f', [1.5] * 4000), TNS_TYPE_VECTOR)
    # The bug's signature was a CONSTANT size: a locator says nothing about the
    # value, so the two encodings were byte-identical in length.
    assert len(large) > len(small) * 10

    # And it reads back as the image, through the client's own reader.
    from seerdb.common.lob import LOB
    from seerdb.common.vector import decode_vector

    value, rest = _read_lob_bind_value(small, TNS_TYPE_VECTOR)
    assert isinstance(value, LOB)
    assert rest == b'', 'the reader must consume the value exactly'
    image = value._prefetched
    assert image is not None, 'the image must ride in the value, not be fetched'
    assert list(cast(Iterable, decode_vector(image))) == [1.5] * 4


def test_a_raw_vector_bind_is_typed_for_its_echoed_value() -> None:
    # The Mirror cannot see bind direction on the wire, so it marks every bind
    # of a block OUT and echoes a value for each -- including a pure-IN one. The
    # client discards positions it did not bind as a Var, but it still has to
    # READ PAST them, and reading past a VECTOR means knowing it is one (#1010).
    import array

    from seerdb.common.datatypes import DB_TYPE_VECTOR, Var
    from seerdb.common.tns import _lob_bind_type
    from seerdb.common.tns_consts import TNS_TYPE_VECTOR

    assert _lob_bind_type(array.array('f', [1.0, 2.0])) == TNS_TYPE_VECTOR
    assert _lob_bind_type([1.0, 2.0]) == TNS_TYPE_VECTOR
    assert _lob_bind_type(Var(DB_TYPE_VECTOR)) == TNS_TYPE_VECTOR
    # Things that are not vector binds keep reading as plain DALC values.
    assert _lob_bind_type('a string') is None
    assert _lob_bind_type(42) is None
    assert _lob_bind_type(None) is None


def test_encode_out_bind_response_thin_lob_roundtrips_via_client() -> None:
    # A LOB-class OUT bind rides as the LOB block, not a DALC (#979): the client
    # reads it with the reader a fetched LOB column uses, and gets a LOB whose
    # locator resolves back to the content the Mirror recorded -- which is what
    # answers the read the client then issues.
    from seerdb.client.cursor import _assign_out_binds
    from seerdb.common.datatypes import DB_TYPE_BLOB, DB_TYPE_CLOB, Var
    from seerdb.common.lob import LOB
    from seerdb.common.tns import (
        _LOB_EMIT_LOG,
        LobEmitLog,
        ScalarOutBind,
        decode_packet,
        encode_out_bind_response_thin,
    )
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    log = LobEmitLog()
    _LOB_EMIT_LOG.set(log)
    try:
        resp = encode_out_bind_response_thin(
            [
                ScalarOutBind('clob content', TNS_TYPE_CLOB),
                ScalarOutBind(b'blob content', TNS_TYPE_BLOB),
                ScalarOutBind(None, TNS_TYPE_CLOB),
            ]
        )
    finally:
        _LOB_EMIT_LOG.set(None)
    v_clob, v_blob, v_null = Var(DB_TYPE_CLOB), Var(DB_TYPE_BLOB), Var(DB_TYPE_CLOB)
    bind = [v_clob, v_blob, v_null]
    result = decode_packet(resp, (0, [], [], bind))
    assert result[1] == 0  # success OER
    assert _assign_out_binds(bind, result) == []
    got_clob, got_blob = v_clob.getvalue(), v_blob.getvalue()
    assert isinstance(got_clob, LOB)
    assert isinstance(got_blob, LOB)
    # A NULL LOB is a single 0x00, so there is nothing to build a LOB from.
    assert v_null.getvalue() is None
    # Each locator the client got back is one the Mirror can still resolve, so
    # the read that follows serves the right value -- a locator it cannot look
    # up would read as empty rather than error.
    assert log.content(got_clob.raw) == ('clob content', True)
    assert log.content(got_blob.raw) == (b'blob content', False)


def test_encode_returning_response_lob_roundtrips_via_client() -> None:
    # A LOB return bind rides as the LOB block, not a DALC (#987). Sent as a
    # DALC the client read the block length as the whole value and handed back
    # an EMPTY string -- the right shape with the wrong content, which is why
    # this asserts the content and not just the type.
    from typing import cast

    from seerdb.client.cursor import _assign_return_binds
    from seerdb.common.datatypes import DB_TYPE_CLOB, Var
    from seerdb.common.lob import LOB
    from seerdb.common.tns import (
        _LOB_EMIT_LOG,
        LobEmitLog,
        decode_packet,
        encode_returning_response,
        set_decode_return_binds,
    )
    from seerdb.common.tns_consts import TNS_TYPE_CLOB

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    log = LobEmitLog()
    _LOB_EMIT_LOG.set(log)
    try:
        resp = encode_returning_response(
            2, [[('first',), ('second',)]], [TNS_TYPE_CLOB]
        )
    finally:
        _LOB_EMIT_LOG.set(None)

    var = Var(DB_TYPE_CLOB)
    bind = [var]
    set_decode_return_binds([0], {0: TNS_TYPE_CLOB})
    try:
        result = decode_packet(resp, (0, [], [], bind))
    finally:
        set_decode_return_binds(None)
    _assign_return_binds(bind, result)
    values = cast(list, var.getvalue())
    # Two rows, so the SECOND is the half a mis-measured first never reaches.
    assert len(values) == 2
    assert all(isinstance(v, LOB) for v in values)
    recorded = [log.content(v.raw) for v in values]
    assert [entry[0] for entry in recorded if entry is not None] == ['first', 'second']


def test_a_long_return_bind_is_a_plain_dalc() -> None:
    # A LONG return bind is a DALC -- no 0xFE chunk marker and no trailing
    # indicators, unlike a LONG COLUMN in a row. Measured on a live 23ai
    # returning a CLOB column into a DB_TYPE_LONG var; giving it the column
    # framing desynced the reply on a zero byte (#987).
    from seerdb.common.tns import encode_returning_response
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TTI_RXD

    resp = encode_returning_response(1, [[('A short CLOB - 1619',)]], [TNS_TYPE_LONG])
    body = resp[resp.index(bytes([TTI_RXD])) :]
    #  RXD | ub4 rows=1 | DALC(19) | sb4 trunc=0
    assert body[:2] == bytes([TTI_RXD, 0x01])
    assert body[2] == 0x01  # the ub4 row count's value byte
    assert body[3] == 19  # a plain 1-byte DALC length, NOT 0xFE
    assert body[4:23] == b'A short CLOB - 1619'
    assert body[23] == 0x00  # the truncation length, with no LONG trailer first


def test_a_returned_number_takes_a_varchar_binds_type() -> None:
    # The value goes out in the RETURN BIND's type: a number into a VARCHAR is
    # its TO_CHAR text, measured on 23ai, not NUMBER bytes in a DALC (#1501).
    from decimal import Decimal

    from seerdb.common.tns import _as_return_bind_type, encode_returning_response
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR, TTI_RXD

    for value, text in (
        (1, '1'),
        (0.5, '.5'),
        (-0.5, '-.5'),
        (Decimal('1.50'), '1.5'),
        (1e-10, '.0000000001'),
        (12345678901234567890, '12345678901234567890'),
    ):
        assert _as_return_bind_type(value, TNS_TYPE_VARCHAR) == text
    assert _as_return_bind_type(7, TNS_TYPE_NUMBER) == 7
    resp = encode_returning_response(1, [[(1,)]], [TNS_TYPE_VARCHAR])
    body = resp[resp.index(bytes([TTI_RXD])) :]
    assert body[3:5] == bytes([1]) + b'1'  # DALC of the text '1', not NUMBER 1


def test_a_long_out_bind_is_a_plain_dalc() -> None:
    # A LONG OUT bind is a DALC and its return code -- `03 61 62 63 | 00`, as a
    # live 23ai sends `begin :v := 'abc'; end;` -- not the chunked form a LONG
    # column takes in a row, which desynced the client (#1458). A long value
    # still chunks as any DALC does, and NULL is the empty DALC.
    from seerdb.common.tns import ScalarOutBind, _encode_out_bind_row_thin
    from seerdb.common.tns_consts import TNS_TYPE_LONG, TNS_TYPE_LONGRAW, TTI_RXD

    row = _encode_out_bind_row_thin(
        [ScalarOutBind(value='abc', tns_type=TNS_TYPE_LONG)]
    )
    assert row == bytes([TTI_RXD, 0x03]) + b'abc' + bytes([0x00])
    raw = _encode_out_bind_row_thin(
        [ScalarOutBind(value=b'\n\x0b', tns_type=TNS_TYPE_LONGRAW)]
    )
    assert raw == bytes([TTI_RXD, 0x02, 0x0A, 0x0B, 0x00])
    null = _encode_out_bind_row_thin(
        [ScalarOutBind(value=None, tns_type=TNS_TYPE_LONG)]
    )
    assert null == bytes([TTI_RXD, 0x00, 0x00])


@pytest.mark.parametrize('version', [6, 17])  # 11.2 and 23ai OAC layouts
def test_parse_exec_reads_an_associative_array_bind(version: int) -> None:
    # An arrayvar bind (#122) carries the ARRAY flag and its capacity in the
    # OAC, and its value as a ub4 count plus the elements; a pure OUT array sends
    # a count of 0. The Mirror keeps the capacity per bind and the elements as a
    # list, so a backend can register an array variable (#743).
    from seerdb.common.datatypes import Var

    seeded = Var(int, is_array=True, num_elements=3)
    seeded.setvalue(0, [11, 22, 33])
    empty = Var(str, is_array=True, num_elements=5)
    msg = _client_exec_request(
        version, 'BEGIN p(:1, :2, :3); END;', [seeded, 7, empty], kind='block'
    )
    with _at_field_version(version):
        req = parse_exec(msg)
    assert req.binds == [[11, 22, 33], 7, []]
    assert req.bind_arrays == [3, 0, 5]
    assert [t for t, _s in req.bind_meta] == [
        TNS_TYPE_NUMBER,
        TNS_TYPE_NUMBER,
        TNS_TYPE_VARCHAR,
    ]


def test_encode_out_bind_response_thin_array_roundtrips_via_client() -> None:
    # An associative-array OUT bind comes back as its element count and the
    # elements; the client's arrayvar receives the list (#743).
    from seerdb.client.cursor import _assign_out_binds
    from seerdb.common.datatypes import Var
    from seerdb.common.tns import (
        ArrayOutBind,
        ScalarOutBind,
        decode_packet,
        encode_out_bind_response_thin,
    )

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    resp = encode_out_bind_response_thin(
        [
            ScalarOutBind(3, TNS_TYPE_NUMBER),
            ArrayOutBind(['a', 'bb', None], TNS_TYPE_VARCHAR),
            ArrayOutBind([], TNS_TYPE_NUMBER),
        ]
    )
    names = Var(str, is_array=True, num_elements=5)
    numbers = Var(int, is_array=True, num_elements=5)
    bind = [3, names, numbers]
    result = decode_packet(resp, (0, [], [], bind))
    assert result[1] == 0
    _assign_out_binds(bind, result)
    assert names.getvalue() == ['a', 'bb', None]
    assert numbers.getvalue() == []


def test_parse_exec_exposes_bind_meta() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    # bind_meta carries (tns_type, max_size) per bind — the type + OUT buffer size
    # a PL/SQL block's OUT binds need registered on the backend.
    msg = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 6,
            'query': {
                'type': 'block',
                'auto': 0,
                'fetch': 0,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'BEGIN p(:1, :2); END;',
                'bind': [7, 'hi'],
                'batch': [],
                'def': [],
            },
        }
    )
    req = parse_exec(msg)
    assert len(req.bind_meta) == 2
    assert req.bind_meta[0][0] == TNS_TYPE_NUMBER  # a NUMBER bind's type
    assert all(size >= 0 for _t, size in req.bind_meta)


def test_encode_out_bind_response_thin_refcursor_entry() -> None:
    from seerdb.common.datatypes import CURSOR, Var
    from seerdb.common.tns import (
        RefCursorOutBind,
        decode_packet,
        encode_out_bind_response_thin,
    )

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    cols = [
        ColumnMeta(name=b'A', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
        ColumnMeta(name=b'B', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1),
    ]
    # A REF CURSOR OUT bind: the client decodes an inline-describe marker carrying
    # the parked cursor id + row format (which it then drains with TTI_FETCH).
    resp = encode_out_bind_response_thin([RefCursorOutBind(columns=cols, cursor_id=7)])
    result = decode_packet(resp, (0, [], [], [Var(CURSOR)]))
    assert result[1] == 0  # success OER
    value = result[4][0]['out_values'][0]
    assert value['_refcursor'] is True
    assert value['cursor_id'] == 7
    assert [c['column_name'] for c in value['row_format']] == [b'A', b'B']


# --- Array-DML batcherrors (#18/#486) ------------------------------------------


def test_encode_batch_errors_status_roundtrips_via_client() -> None:
    from seerdb.common.tns import decode_token_oer, encode_batch_errors_status

    _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    # Two rows of a 5-row executemany violated the PK (offsets 2 and 4); the
    # client reads ORA-24381 + the per-row (offset, code, message) arrays.
    body = encode_batch_errors_status(
        3,
        [
            (2, 1, 'ORA-00001: unique constraint violated'),
            (4, 1, 'ORA-00001: unique constraint violated'),
        ],
    )
    result = decode_token_oer(body, (0, [], []))
    assert result[1] == 24381  # the array-DML summary code (non-fatal)
    assert result[3][0] == 3  # affected-row count (the applied rows)
    errs = result[7]
    assert [(e['offset'], e['code']) for e in errs] == [(2, 1), (4, 1)]
    assert 'ORA-00001' in errs[0]['message']
    # No batch errors → the three arrays stay empty (a plain status is unchanged).
    plain = decode_token_oer(encode_batch_errors_status(0, []), (0, [], []))
    assert plain[7] == []


def test_parse_exec_reads_batcherrors_flag() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    def dml(batcherrors: bool) -> bytes:
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': 0,
                    'query': 'INSERT INTO t VALUES (:1, :2)',
                    'bind': [1, 'a'],
                    'batch': [[2, 'b']],
                    'def': [],
                    'batcherrors': batcherrors,
                },
            }
        )

    assert parse_exec(dml(True)).batcherrors is True
    assert parse_exec(dml(False)).batcherrors is False


# --- Cursor cache: cached re-execute without OACs (#80/#486) --------------------


def test_peek_exec_cursor_reads_cursor_and_query_presence() -> None:
    from seerdb.common.tns import encode_dictionary_exec, peek_exec_cursor

    def msg(cursor: int, query: str) -> bytes:
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': cursor,
                    'query': query,
                    'bind': [1, 'a'],
                    'batch': [],
                    'def': [],
                },
            }
        )

    # A fresh parse carries SQL; a cached re-execute has a cursor id and no SQL.
    assert peek_exec_cursor(msg(0, 'INSERT INTO t VALUES (:1, :2)')) == (0, True)
    assert peek_exec_cursor(msg(5, '')) == (5, False)
    assert peek_exec_cursor(b'\x03\x05not an exec') == (0, True)


def test_parse_exec_takes_array_rowcounts_from_the_dml_rowcounts_bit_alone() -> None:
    # al8i4[9] is a word of unrelated flags. The reference thin client sets
    # IMPLICIT_RESULTSET (0x8000) there on EVERY ordinary execute; the
    # arraydmlrowcounts request is DML_ROWCOUNTS (0x4000). Testing for the
    # composite seerdb's own client sends (both bits) took every executemany
    # from the reference client for a row-count request, and answered it with a
    # block it could not parse (#859).
    from seerdb.common.tns import _DECODE_FIELD_VERSION, encode_dictionary_exec
    from seerdb.server.session import _skip_piggybacks

    # A plain executemany from the reference client, byte-for-byte off a live
    # capture (fv24): an OCCA piggyback, then the OALL8 -- two iterations, one
    # bind, al8i4[9] = IMPLICIT_RESULTSET alone.
    captured = bytes.fromhex(
        '116905000101010101035e06000280290001012101010d0000000101047fffff'
        'ff0101010000000000000000000100000000000000000000000000000021696e'
        '7365727420696e746f20656d315f70726f62652076616c75657320283a312901'
        '0101020000000000000002800000000002010000011600000000000000000702'
        'c1020702c103'
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_exec(_skip_piggybacks(captured))
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.sql == 'insert into em1_probe values (:1)'
    assert (request.iterations, request.bind_rows) == (2, [[1], [2]])
    assert request.arraydmlrowcounts is False  # it asked for nothing
    assert request.batcherrors is False

    # seerdb's own client asking for the counts writes the composite
    # (DML_ROWCOUNTS | IMPLICIT_RESULTSET); the request bit is in it, so it is
    # still recognised.
    asked = encode_dictionary_exec(
        {
            'seq': 3,
            'field_version': 17,
            'query': {
                'type': 'change',
                'auto': 0,
                'fetch': 0,
                'server_version': 0,
                'cursor': 0,
                'query': 'insert into t values (:1)',
                'bind': [1],
                'batch': [[2], [3]],
                'def': [],
                'arraydmlrowcounts': True,
            },
        }
    )
    token = _DECODE_FIELD_VERSION.set(17)
    try:
        request = parse_exec(asked)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.arraydmlrowcounts is True
    assert (request.iterations, request.bind_rows) == (3, [[1], [2], [3]])


def test_parse_exec_reads_oacs_of_an_empty_sql_execute_that_carries_them() -> None:
    # "No SQL" does not imply "no OACs". seerdb's own cached re-execute omits the
    # bind descriptors and relies on the server remembering them (#80/#486), but
    # the reference thin client sends an empty-SQL execute that still carries
    # them. Trusting the empty-query flag left the parser sitting on an OAC where
    # it expected a TTI_RXD, so it found no bind rows at all and the backend was
    # handed an execute with no values -- ORA-01008 on the second executemany of
    # every session (#859).
    #
    # Captured live (fv24): the second `executemany` of
    # `insert into em_probe values (:1, :2)`, three rows, no SQL, WITH OACs.
    from seerdb.common.tns import _DECODE_FIELD_VERSION

    captured = bytes.fromhex(
        '035e08000280280103000001010d0000000101047fffffff0101020000000000'
        '0000000001000000000000000000000000000000000103000000000000000280'
        '0000000002010000011600000000000000000101000001040000000002036901'
        '00000702c10401630702c10501640702c1060165'
    )
    remembered = [(TNS_TYPE_NUMBER, 1, 22, b''), (TNS_TYPE_VARCHAR, 1, 10, b'')]
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        # The session hands over the remembered types (it sees an empty query);
        # the parser must notice the descriptors are present and read them.
        request = parse_exec(captured, bind_types=remembered)
        # ...and the same message parses identically with nothing remembered.
        without = parse_exec(captured)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.sql == ''
    assert request.cursor == 3
    assert request.iterations == 3
    assert request.bind_rows == [[3, 'c'], [4, 'd'], [5, 'e']]
    assert without.bind_rows == request.bind_rows


def test_parse_exec_cached_reexecute_decodes_binds_without_oacs() -> None:
    from seerdb.common.tns import encode_dictionary_exec

    def msg(cursor: int, query: str, binds: list) -> bytes:
        return encode_dictionary_exec(
            {
                'seq': 3,
                'field_version': 6,
                'query': {
                    'type': 'change',
                    'auto': 0,
                    'fetch': 0,
                    'server_version': VERSION_11_2_0_2,
                    'cursor': cursor,
                    'query': query,
                    'bind': binds,
                    'batch': [],
                    'def': [],
                },
            }
        )

    # First parse remembers the bind format (bind_types); the re-execute omits the
    # OACs, so parsing it needs those remembered types or its RXD mis-decodes.
    first = parse_exec(msg(0, 'INSERT INTO t VALUES (:1, :2)', [1, 'a']))
    assert first.binds == [1, 'a']
    assert len(first.bind_types) == 2

    reexec = msg(5, '', [2, 'b'])
    # Parsing the OAC-less re-execute without the remembered types mis-reads the
    # RXD (the session never does this — it always supplies the types).
    with pytest.raises((InterfaceError, IndexError, DataError)):
        parse_exec(reexec)
    # With the remembered types the new bind values decode correctly.
    assert parse_exec(reexec, bind_types=first.bind_types).binds == [2, 'b']


# --- Object REF column describe + value (#494) ---------------------------------


def test_ref_column_describe_and_value_roundtrip() -> None:
    from seerdb.common.dbobject import DbRef
    from seerdb.common.tns import encode_describe, encode_rows
    from seerdb.common.tns_consts import TNS_TYPE_REF, TTI_STA

    # A REF column carries the referenced type's identity in the describe and the
    # opaque locator bytes in the row; the client rebuilds a typed DbRef.
    col = ColumnMeta(
        name=b'R',
        data_type=TNS_TYPE_REF,
        data_length=4000,
        max_size=4000,
        type_name=b'PERSON',
        type_schema=b'PYO',
        type_oid=b'\x01' * 16,
    )
    ref = DbRef(b'\x00\x28\x02\x09', 'PERSON', 'PYO', b'\x01' * 16)
    response = encode_describe([col]) + encode_rows([(ref,)], [col]) + bytes([TTI_STA])
    columns, rows = _decode_response(response)
    # The describe carried the type identity (what surfaces as ref.type_name).
    assert columns[0]['type_name'] == 'PERSON'
    assert columns[0]['type_schema'] == 'PYO'
    assert columns[0]['type_oid'] == b'\x01' * 16
    # The value decoded back to a DbRef with that identity and its locator bytes.
    got = rows[0][0]
    assert got.type_name == 'PERSON'
    assert got.bytes == b'\x00\x28\x02\x09'


def test_run_returning_runs_once_per_iteration_when_no_input_row() -> None:
    # A RETURNING statement whose binds are all clause-filled sends no input row,
    # so bind_rows is empty; the server must still run it request.iterations times
    # (one per array iteration) rather than skipping or under-running it (#33).
    from typing import cast

    from seerdb.common.tns import ExecRequest
    from seerdb.server.backend import Backend, BindVar, Result
    from seerdb.server.session import _Cursors, _run_returning

    class _Backend:
        def __init__(self) -> None:
            self.calls: list = []

        def execute_returning(self, sql: str, rows) -> Result:
            self.calls.append(rows)
            # One returned row per iteration, like a real INSERT ... RETURNING.
            return Result(
                rowcount=len(rows), returned_rows=[[(i,)] for i in range(len(rows))]
            )

    backend = _Backend()
    request = ExecRequest(
        sql='insert into t (id) values (s.nextval) returning id into :1',
        cursor=0,
        bind_count=1,
        fetch=0,
        bind_rows=[],
        bind_meta=[(TNS_TYPE_NUMBER, 22)],
        return_binds=frozenset({0}),
        iterations=3,
    )
    # The cursor registry is only consulted for a REF CURSOR bind (#1048), and
    # this request has none -- an empty one says so.
    result = _run_returning(cast(Backend, backend), request.sql, request, _Cursors())
    # Three synthesized rows reached the backend, each a lone clause-filled bind.
    assert len(backend.calls) == 1
    sent = backend.calls[0]
    assert len(sent) == 3
    assert all(len(row) == 1 and isinstance(row[0], BindVar) for row in sent)
    assert len(result.returned_rows) == 3


def test_encode_status_reports_no_transaction_by_default() -> None:
    # call_status is a flag word; with no transaction open the bit stays clear
    # and the reply is exactly what it always was.
    from seerdb.common.tns import decode_ub4, encode_status

    status, _ = decode_ub4(encode_status(1)[1:])
    assert status == 0


def test_encode_status_sets_the_transaction_flag_while_one_is_open() -> None:
    # A live server sets TXN_IN_PROGRESS in every reply's call_status while the
    # session holds an uncommitted transaction. python-oracledb reads that bit to
    # decide whether releasing the connection owes a rollback; with it clear the
    # DML kept its TM lock and blocked later statements with ORA-00054 (#889).
    from seerdb.common.tns import _ENCODE_TXN_IN_PROGRESS, decode_ub4, encode_status

    token = _ENCODE_TXN_IN_PROGRESS.set(True)
    try:
        status, _ = decode_ub4(encode_status(1)[1:])
    finally:
        _ENCODE_TXN_IN_PROGRESS.reset(token)
    assert status & TNS_EOCS_FLAGS_TXN_IN_PROGRESS


def test_transaction_flag_is_ored_into_the_callers_status() -> None:
    # The caller's value says what the reply is ("more rows"); the bit says what
    # the session is. One must not overwrite the other.
    from seerdb.common.tns import _ENCODE_TXN_IN_PROGRESS, decode_ub4, encode_more_rows

    token = _ENCODE_TXN_IN_PROGRESS.set(True)
    try:
        status, _ = decode_ub4(encode_more_rows(3)[1:])
    finally:
        _ENCODE_TXN_IN_PROGRESS.reset(token)
    assert status & TNS_EOCS_FLAGS_TXN_IN_PROGRESS
    assert status & 1  # the "more rows" status the caller asked for survives


def test_end_of_fetch_terminator_carries_the_transaction_flag() -> None:
    # The 11g terminator is a constant built at import time, so it would freeze
    # the flag clear; it must be re-encoded while a transaction is open (#889).
    from seerdb.common.tns import _ENCODE_TXN_IN_PROGRESS, _end_of_fetch, decode_ub4

    plain, _ = decode_ub4(_end_of_fetch()[1:])
    token = _ENCODE_TXN_IN_PROGRESS.set(True)
    try:
        in_txn, _ = decode_ub4(_end_of_fetch()[1:])
    finally:
        _ENCODE_TXN_IN_PROGRESS.reset(token)
    assert not plain & TNS_EOCS_FLAGS_TXN_IN_PROGRESS
    assert in_txn & TNS_EOCS_FLAGS_TXN_IN_PROGRESS


def test_mark_transaction_tracks_statement_kinds() -> None:
    # DML and PL/SQL open a transaction; autocommit closes it again; a query
    # leaves the flag as it found it.
    from seerdb.common.tns import _ENCODE_TXN_IN_PROGRESS
    from seerdb.server.session import _mark_transaction

    token = _ENCODE_TXN_IN_PROGRESS.set(False)
    try:
        _mark_transaction('insert into t values (1)', False)
        assert _ENCODE_TXN_IN_PROGRESS.get() is True
        _mark_transaction('select 1 from dual', False)
        assert _ENCODE_TXN_IN_PROGRESS.get() is True  # a query changes nothing
        _mark_transaction('insert into t values (2)', True)
        assert _ENCODE_TXN_IN_PROGRESS.get() is False  # autocommit closes it
        _mark_transaction('begin null; end;', False)
        assert _ENCODE_TXN_IN_PROGRESS.get() is True
    finally:
        _ENCODE_TXN_IN_PROGRESS.reset(token)


def test_a_json_bind_is_not_sorted_to_the_end_of_the_row() -> None:
    # A LONG-class bind's value rides after the row's others, and a native JSON
    # bind's OAC declares 32 MiB -- which made it LONG-class by size. It is not:
    # it carries its own descriptor framing and rides IN PLACE. Sorting it to the
    # end swapped it with every bind after it, so `update t set j = :1 where
    # id = :2` put the image in the NUMBER's slot (#826). It went unnoticed
    # because a JSON bind is usually last, where the move is a no-op.
    from seerdb.common.datatypes import JSON
    from seerdb.common.tns import _DECODE_FIELD_VERSION, _long_bind_positions

    # Byte-for-byte off a live capture (fv24): `update TestJson set JsonCol = :1
    # where IntCol = :2` binding {'b': 2} and 1, JSON FIRST.
    captured = bytes.fromhex(
        '035e05000280290001013201010d0000000101047fffffff0101020000000000'
        '0000000001000000000000000000000000000000327570646174652054657374'
        '4a736f6e20736574204a736f6e436f6c203d203a3120776865726520496e7443'
        '6f6c203d203a3201010101000000000000000280000000007701000004020000'
        '0000040200000000000000040200000000020100000116000000000000000007'
        '01282800260004610800000001000000000000001d0000000000000000000000'
        '00000000000000000000001dff4a5a012102010002000b0000e500000162a401'
        '01000000073402c10302c102'
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_exec(captured)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.bind_types[0][0] == 119  # TNS_TYPE_JSON
    assert request.bind_types[0][2] == 33554432  # ...declaring 32 MiB
    assert isinstance(request.binds[0], JSON)
    assert request.binds[0].value == {'b': 2}
    assert request.binds[1] == 1  # ...and the NUMBER after it is intact

    # The encoder side has the same rule, read the other way: a JSON bind must
    # not be listed as LONG-class, or seerdb's own client writes it out of place
    # and a real 23ai answers ORA-24813.
    assert _long_bind_positions([JSON({'b': 2}), 1], 4000) == frozenset()


def test_a_parse_only_execute_is_recognised_and_carries_no_binds() -> None:
    # `cursor.parse()` asks the server to parse the statement WITHOUT running it:
    # PARSE (0x01) set, EXECUTE (0x20) clear. A query adds DESCRIBE (0x20000) and
    # the reply owes the column metadata; a DML / PL/SQL parse owes only a
    # success status. Either way the message carries NO bind values, so running
    # it reached the backend as ORA-01008 -- which is what every parse in the
    # reference suite hit (#826).
    from seerdb.common.tns import _DECODE_FIELD_VERSION

    # Byte-for-byte off a live capture (fv24): parse of
    # `select LongIntCol from TestNumbers where IntCol = :val`, options 0x20001.
    query_parse = bytes.fromhex(
        '035e030004000200010001013601010d0000000101047fffffff000000000000'
        '0000000000010000000000000000000000000000003673656c656374204c6f6e'
        '67496e74436f6c2066726f6d20546573744e756d626572732077686572652049'
        '6e74436f6c203d203a76616c010100000000000001010000000000'
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_exec(query_parse)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.parse_only is True
    assert request.describe_only is True
    assert request.bind_count == 0  # a parse sends no values, whatever :val is


def test_a_non_query_parse_is_handed_to_a_backend_that_can_validate() -> None:
    # A non-query parse owes only a status, and answering it from the Mirror's
    # own side is how every parse-time error was lost: nothing parsed the
    # statement, so `returning IntCol into :ROWID` came back clean where a real
    # server answers ORA-01745 (#1019). A backend with a `parse` method is asked,
    # and what it refuses reaches the client as that error.
    from typing import cast

    from seerdb.common.tns import ExecRequest
    from seerdb.server.backend import Backend, BackendError
    from seerdb.server.session import _answer_parse

    asked = []

    class _CanParse:
        def parse(self, sql: str) -> None:
            asked.append(sql)
            if 'ROWID' in sql:
                raise BackendError('invalid host/bind variable name', ora_code=1745)

    request = ExecRequest(
        sql='', cursor=0, bind_count=0, fetch=0, parse_only=True, describe_only=False
    )
    good = 'insert into t (v) values (:1)'
    assert _answer_parse(
        cast(Backend, _CanParse()), good, request
    )  # a status, no exception
    assert asked == [good]

    bad = 'insert into t (v) values (:1) returning v into :ROWID'
    with pytest.raises(BackendError) as err:
        _answer_parse(cast(Backend, _CanParse()), bad, request)
    assert err.value.ora_code == 1745


def test_a_backend_that_cannot_parse_still_answers_a_status() -> None:
    # The capability is optional, and omitting it is the right answer for a
    # backend that cannot parse Oracle SQL at all -- the PostgreSQL and SQLite
    # demos. They must not break on a parse, only decline to validate it.
    from typing import cast

    from seerdb.common.tns import ExecRequest
    from seerdb.server.backend import Backend
    from seerdb.server.session import _answer_parse

    class _CannotParse:
        pass

    request = ExecRequest(
        sql='', cursor=0, bind_count=0, fetch=0, parse_only=True, describe_only=False
    )
    assert _answer_parse(
        cast(Backend, _CannotParse()), 'insert into t (v) values (:1)', request
    )


def test_an_ordinary_execute_is_not_taken_for_a_parse() -> None:
    # PARSE rides along with EXECUTE on every first execute of a statement, so
    # the PARSE bit alone can never be the test -- what makes a call a parse is
    # the ABSENCE of EXECUTE (see test_the_option_word_says_parse_by_its_absence).
    from seerdb.common.tns import _DECODE_FIELD_VERSION

    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        request = parse_exec(_DUAL_EXEC)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.parse_only is False


def test_the_option_word_says_parse_by_its_absence() -> None:
    # What makes a call a `cursor.parse()` is not the PARSE bit -- it is having
    # no EXECUTE. The two parses of ONE statement do not even agree on PARSE:
    # the first carries 0x1, and the second, after the client has the statement
    # cached, carries 0x0. Reading the PARSE bit alone therefore took the second
    # one for an ordinary execute and RAN it; a parse sends no bind values, so
    # the backend answered ORA-01008 (#984). Every option word below was
    # measured on a live 23ai.
    from seerdb.common.tns import parse_options

    assert parse_options(0x1) == (True, False)  # parse(), statement unseen
    assert parse_options(0x0) == (True, False)  # parse(), statement cached
    assert parse_options(0x20001) == (True, True)  # a QUERY parse: + DESCRIBE

    # Anything that actually runs the statement sets EXECUTE (0x20).
    assert parse_options(0x8029) == (False, False)  # cached re-execute
    assert parse_options(0x8021) == (False, False)  # DDL / first execute
    assert parse_options(0x8061) == (False, False)  # a SELECT

    # Two other calls have no EXECUTE either and are NOT parses. The define
    # round-trip is the client applying its fetch types and asking for the rows
    # already parked (PROTOCOL.md 14.5d); a scroll re-execute repositions an
    # open cursor, and must not set EXECUTE or the server would re-run the query
    # from the top (11.8). Calling either a parse answers a bare status and
    # strands the rows.
    assert parse_options(0x8010) == (False, False)  # define round-trip
    assert parse_options(0x8040) == (False, False)  # scroll re-execute


def test_a_temp_lob_answers_its_own_length_and_trim() -> None:
    # GET_LENGTH and TRIM both owe a real figure, so neither can be a
    # content-free ack and neither may fall through to the column-read path --
    # which answered with a read reply (token 0x0e) echoing the Mirror's
    # placeholder locator, the wrong token AND the wrong locator, so the first
    # `lob.size()` on anything the client created desynced (#826).
    from seerdb.common.tns import encode_lobops_length
    from seerdb.common.tns_consts import TTI_RPA

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x01'
    reply = encode_lobops_length(locator, 260)
    assert reply[0] == TTI_RPA
    assert locator in reply
    # 260 as a ub4: a length byte then the two value bytes, exactly as a live
    # 23ai sends it.
    assert b'\x02\x01\x04' in reply
    # An empty LOB sends a ub4 zero, not an absent field.
    assert b'\x00' in encode_lobops_length(locator, 0)


def test_a_temp_lob_read_echoes_the_clients_own_locator() -> None:
    # A column-LOB read may echo the Mirror's placeholder -- the client ignores
    # what comes back there. A temp LOB the client created itself may not: it
    # reads back exactly as many bytes as the locator it sent, so a placeholder
    # of a different length desyncs the reply (#826).
    from seerdb.common.tns import encode_lob_read_response_thin

    locator = b'\x00seerdb-mirror-temp-lob-\x00\x00\x00\x00\x07'
    mine = encode_lob_read_response_thin(b'ABCDE', locator=locator)
    assert locator in mine
    assert b'ABCDE' in mine
    # The default keeps the column placeholder, so the column path is unchanged.
    assert locator not in encode_lob_read_response_thin(b'ABCDE')


def test_implicit_results_round_trip_through_the_client_decoder() -> None:
    # A PL/SQL block that called DBMS_SQL.RETURN_RESULT hands its result sets back
    # as a TTI_IRD block naming one server cursor per set, which the client then
    # fetches like a REF CURSOR (#121/#826). The Mirror had no encoder for it at
    # all, so getimplicitresults() found nothing and raised DPY-1004.
    from seerdb.common.tns import decode_token_implicit, encode_implicit_results
    from seerdb.common.tns_consts import TTI_STA

    columns = [
        ColumnMeta(
            name=b'INTCOL', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=0
        )
    ]
    payload = encode_implicit_results([(columns, 7), (columns, 8)]) + bytes([TTI_STA])
    (_done, acc) = decode_token_implicit(payload, (0, [], []))
    (record,) = acc[2]
    results = record['implicit_results']
    assert [r['cursor_id'] for r in results] == [7, 8]
    assert [c['column_name'] for c in results[0]['row_format']] == [b'INTCOL']


def test_a_block_s_out_binds_come_before_its_implicit_results() -> None:
    # A block with OUT binds that also called DBMS_SQL.RETURN_RESULT: 23ai sends
    # the IOV and the values' RXD, then the TTI_IRD, then the status (#2295). A
    # Mirror sent one or the other, and the client lost the OUT values.
    from seerdb.common.tns import (
        ScalarOutBind,
        encode_implicit_results,
        encode_out_bind_response_thin,
        encode_status,
    )
    from seerdb.common.tns_consts import TNS_BIND_DIR_OUTPUT, TNS_TYPE_VARCHAR

    columns = [
        ColumnMeta(
            name=b'INTCOL', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=0
        )
    ]
    implicit = encode_implicit_results([(columns, 7)])
    binds: list = [ScalarOutBind(value='out-value', tns_type=TNS_TYPE_VARCHAR, csfrm=1)]
    both = encode_out_bind_response_thin(
        binds, (TNS_BIND_DIR_OUTPUT,), cursor_id=3, implicit_results=implicit
    )
    alone = encode_out_bind_response_thin(binds, (TNS_BIND_DIR_OUTPUT,), cursor_id=3)
    status = encode_status(0, cursor_id=3)
    assert both == alone[: -len(status)] + implicit + status
    assert both.index(b'out-value') < both.index(implicit)


def test_no_implicit_results_is_an_empty_block_not_a_missing_one() -> None:
    # A block that returned none still decodes -- a zero count, not an absent
    # token -- so the caller can emit it unconditionally if it wants to.
    from seerdb.common.tns import decode_token_implicit, encode_implicit_results
    from seerdb.common.tns_consts import TTI_STA

    (_done, acc) = decode_token_implicit(
        encode_implicit_results([]) + bytes([TTI_STA]), (0, [], [])
    )
    (record,) = acc[2]
    assert record['implicit_results'] == []


def test_a_national_out_bind_travels_as_utf_16be() -> None:
    # An NCHAR / NVARCHAR2 OUT bind carries its text as UTF-16BE, exactly as a
    # national COLUMN does in a row. Sent as UTF-8 the client reads two bytes per
    # character, so 'Called' came back as '䍍汬敤' -- readable
    # mojibake rather than an error, which is how it survived (#826).
    from seerdb.common.tns import (
        _CSFRM_DB,
        _CSFRM_NCHAR,
        ScalarOutBind,
        encode_out_bind_response_thin,
    )

    national = encode_out_bind_response_thin(
        [ScalarOutBind(value='Called', tns_type=TNS_TYPE_VARCHAR, csfrm=_CSFRM_NCHAR)]
    )
    assert 'Called'.encode('utf-16-be') in national
    assert b'Called' not in national
    # An ordinary bind is untouched, so the database-charset path is unchanged.
    ordinary = encode_out_bind_response_thin(
        [ScalarOutBind(value='Called', tns_type=TNS_TYPE_VARCHAR, csfrm=_CSFRM_DB)]
    )
    assert b'Called' in ordinary


def test_a_national_array_out_bind_converts_every_element() -> None:
    # The same rule element by element, for a bind registered with arrayvar.
    from seerdb.common.tns import (
        _CSFRM_NCHAR,
        ArrayOutBind,
        encode_out_bind_response_thin,
    )

    reply = encode_out_bind_response_thin(
        [
            ArrayOutBind(
                values=['one', 'two'], tns_type=TNS_TYPE_VARCHAR, csfrm=_CSFRM_NCHAR
            )
        ]
    )
    assert 'one'.encode('utf-16-be') in reply
    assert 'two'.encode('utf-16-be') in reply


def test_a_nested_cursor_column_carries_no_indicator_byte() -> None:
    # `select ..., CURSOR(select ...) from ...` returns a cursor per row. Its
    # value is the same inline describe + cursor id a REF CURSOR OUT bind
    # carries, but WITHOUT the trailing indicator / return code an OUT bind ends
    # on -- in a row the next byte is the following row's TTI_RXD token.
    # Consuming one there swallows that token, and the decoder then reports the
    # first byte of the row's data as an unknown response token (#826).
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        _ENCODE_FIELD_VERSION,
        _encode_describe_body,
        _read_refcursor_out,
        encode_sb4,
    )
    from seerdb.common.tns_consts import TTI_RXD

    columns = [
        ColumnMeta(
            name=b'INTCOL+1', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=0
        )
    ]
    enc = _ENCODE_FIELD_VERSION.set(24)
    dec = _DECODE_FIELD_VERSION.set(24)
    try:
        value = bytes([1]) + _encode_describe_body(columns) + encode_sb4(3)
        # A column value: the next byte belongs to the next row.
        record, rest = _read_refcursor_out(value + bytes([TTI_RXD]), indicator=False)
        assert record['cursor_id'] == 3
        assert [c['column_name'] for c in record['row_format']] == [b'INTCOL+1']
        assert rest[:1] == bytes([TTI_RXD]), 'the next row token must survive'
        # An OUT bind value: the indicator is real and is consumed.
        _record, rest = _read_refcursor_out(value + b'\x00' + bytes([TTI_RXD]))
        assert rest[:1] == bytes([TTI_RXD])
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)


def test_the_describe_length_of_a_nested_cursor_column() -> None:
    # A live 23ai describes a CURSOR(...) column with length 5. Zero here is the
    # same trap as BOOLEAN, ROWID/UROWID/ADT, VECTOR and JSON before it -- the
    # FIFTH occurrence: the client reads no bytes for the column and takes the
    # value's first byte for the next token (#826).
    from seerdb.common.tns import describe_wire_length
    from seerdb.common.tns_consts import TNS_TYPE_REFCURSOR

    column = ColumnMeta(
        name=b'CURSORVALUE', data_type=TNS_TYPE_REFCURSOR, data_length=0, max_size=0
    )
    assert describe_wire_length(column) == 5


def test_a_served_nested_cursor_round_trips_to_the_client_decoder() -> None:
    # The value the Mirror writes for a cursor column must read back through the
    # same decoder a real server's does, and must leave the NEXT row's token
    # untouched (#826).
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        _ENCODE_FIELD_VERSION,
        _read_refcursor_out,
        encode_refcursor_column_value,
    )
    from seerdb.common.tns_consts import TTI_RXD

    columns = [
        ColumnMeta(
            name=b'INTCOL+1', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=0
        )
    ]
    enc = _ENCODE_FIELD_VERSION.set(24)
    dec = _DECODE_FIELD_VERSION.set(24)
    try:
        wire = encode_refcursor_column_value(columns, 7) + bytes([TTI_RXD])
        record, rest = _read_refcursor_out(wire, indicator=False)
    finally:
        _ENCODE_FIELD_VERSION.reset(enc)
        _DECODE_FIELD_VERSION.reset(dec)
    assert record['cursor_id'] == 7
    assert [c['column_name'] for c in record['row_format']] == [b'INTCOL+1']
    assert rest[:1] == bytes([TTI_RXD])


def test_parking_a_nested_cursor_recurses() -> None:
    # A nested cursor may itself select a CURSOR(...) column. Each level needs a
    # parked id of its own, or the inner CursorResult reaches the row encoder and
    # the session dies with "no wire encoding for a column value of type
    # CursorResult" (#826).
    from seerdb.common.tns import NestedCursor
    from seerdb.common.tns_consts import TNS_TYPE_REFCURSOR
    from seerdb.server.backend import CursorResult
    from seerdb.server.session import _Cursors, _park_nested_cursors

    leaf_cols = [
        ColumnMeta(name=b'V', data_type=TNS_TYPE_VARCHAR, data_length=10, max_size=10)
    ]
    inner_cols = [
        ColumnMeta(
            name=b'INNER', data_type=TNS_TYPE_REFCURSOR, data_length=5, max_size=0
        )
    ]
    outer_cols = [
        ColumnMeta(
            name=b'OUTER', data_type=TNS_TYPE_REFCURSOR, data_length=5, max_size=0
        )
    ]
    deep = CursorResult(columns=leaf_cols, rows=[('x',)])
    middle = CursorResult(columns=inner_cols, rows=[(deep,)])
    cursors = _Cursors()
    (row,) = _park_nested_cursors([(middle,)], outer_cols, cursors)
    outer = row[0]
    assert isinstance(outer, NestedCursor)
    # The inner level was parked too, and under a DIFFERENT id.
    _cols, parked = cursors.take(outer.cursor_id, 10)
    inner = parked[0][0]
    assert isinstance(inner, NestedCursor)
    assert inner.cursor_id != outer.cursor_id
    # A result with no cursor column is returned untouched, allocating nothing.
    plain = [(1,), (2,)]
    assert _park_nested_cursors(plain, leaf_cols, cursors) is plain


def test_a_define_reexecute_honours_a_zero_prefetch() -> None:
    # The define round-trip of a LOB-class result is an EXECUTE, so its fetch
    # field is a PREFETCH: a zero means "send me no rows now", exactly as it does
    # on the opening execute (#856). Reading the zero as "all of them" delivered
    # the whole result inline, and a client that had set prefetchrows = 0 then
    # decoded its values inside execute() instead of on the fetch it was waiting
    # to issue -- python-oracledb's test_3509 catches it, because the DPY-3007 it
    # expects from fetchone() came out of execute() instead (#1113).
    from typing import Any

    from seerdb.common.tns import TTI_RXD, ExecRequest
    from seerdb.server.session import _answer_query, _Cursors

    class _Recorder:
        def __init__(self) -> None:
            self.packets: list[bytes] = []

        def write_packet(self, kind: int, body: bytes) -> None:
            self.packets.append(body)

    column = ColumnMeta(
        name=b'JSONCOL', data_type=TNS_TYPE_JSON, data_length=0, max_size=0
    )
    rows = [(b'{"a": 1}',), (b'{"a": 2}',)]

    def _reexecute(fetch: int) -> tuple[Any, _Cursors, int]:
        cursors = _Cursors()
        cursor_id = cursors.open([column], list(rows), sql='select j from t')
        stream: Any = _Recorder()
        backend: Any = None  # the parked-rows branch never reaches the backend
        _answer_query(
            stream,
            backend,
            ExecRequest(sql='', cursor=cursor_id, bind_count=0, fetch=fetch),
            cursors,
            None,
        )
        return stream, cursors, cursor_id

    # Prefetch 0: no row data goes out, and the rows stay parked for the fetch.
    stream, cursors, cursor_id = _reexecute(0)
    assert cursors.delivered(cursor_id) == 0
    assert bytes([TTI_RXD]) not in stream.packets[0]
    assert cursors.has(cursor_id)
    # A positive prefetch still takes that many...
    stream, cursors, cursor_id = _reexecute(1)
    assert cursors.delivered(cursor_id) == 1
    assert bytes([TTI_RXD]) in stream.packets[0]
    assert cursors.has(cursor_id)
    # ... and one large enough drains the cursor, as before.
    stream, cursors, cursor_id = _reexecute(10)
    assert cursors.delivered(cursor_id) == len(rows)
    assert not cursors.has(cursor_id)


def test_a_returned_value_takes_its_receiving_binds_type() -> None:
    # Oracle converts what RETURNING hands back into the declared variable's
    # type, and fails the statement when it cannot (#1370).
    from decimal import Decimal

    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server import BackendError, as_declared_type

    assert as_declared_type('0A0B', TNS_TYPE_RAW) == b'\n\x0b'
    assert as_declared_type('ABC', TNS_TYPE_RAW) == b'\n\xbc'  # an odd digit leads
    assert as_declared_type(' 42 ', TNS_TYPE_NUMBER) == Decimal(42)
    assert as_declared_type(b'\n\x0b', TNS_TYPE_VARCHAR) == '0A0B'
    # A value already of its kind, as a passthrough backend returns them all.
    assert as_declared_type(b'\x01', TNS_TYPE_RAW) == b'\x01'
    assert as_declared_type(None, TNS_TYPE_NUMBER) is None
    for value, tns_type, code in (
        ('Value for first row', TNS_TYPE_RAW, 1465),
        ('abc', TNS_TYPE_NUMBER, 1722),
    ):
        with pytest.raises(BackendError) as caught:
            as_declared_type(value, tns_type)
        assert caught.value.ora_code == code
