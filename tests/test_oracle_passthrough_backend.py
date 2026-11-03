# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline unit tests for the Oracle-passthrough example backend's error relay.

The passthrough is the Mirror's conformance harness (it relays each statement to
a real Oracle). A real Oracle error already reads ``ORA-NNNNN: ...``; the Mirror
(``BackendError``) re-adds that prefix from the code, so relaying the text
verbatim doubled it. ``_relay_error`` strips the leading prefix so exactly one is
emitted — the behaviour these tests pin without needing a database.
"""

from __future__ import annotations

import pytest

import seerdb
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_MAX,
)
from seerdb.server.backend import BindVar
from seerdb.server.backends.passthrough import (
    OraclePassthroughBackend,
    _relay_error,
)


def test_a_release_packs_by_its_own_layout():
    # The upstream's release as Oracle packs it, for the login and sqlplus's
    # version call (#2024): what 10g, 11g, 18c and 23ai report.
    from seerdb.server.backends.passthrough import _packed_release

    assert _packed_release('10.2.0.5.0') == 0x0A200500
    assert _packed_release('11.2.0.2.0') == 0x0B200200
    assert _packed_release('18.4.0.0.0') == 0x12040000
    assert _packed_release('23.26.2.0.0') == 0x171A2000
    assert _packed_release('23.0.0.0.0') == 0x17000000


@pytest.mark.parametrize(
    ('spoken', 'upstream'),
    [
        ('4', FIELD_VERSION_11_2),  # 10.2: 23ai serves none, so 11.2's forms
        ('6', FIELD_VERSION_11_2),
        ('7', FIELD_VERSION_12_1),
        ('27', FIELD_VERSION_MAX),  # sqlplus 23.26, above what seerdb speaks
        (None, None),  # not known: the client's default
    ],
)
def test_the_upstream_session_opens_at_the_clients_version(
    monkeypatch: pytest.MonkeyPatch, spoken: str | None, upstream: int | None
) -> None:
    # The upstream answers the client as it would directly: it maps the 23ai
    # types and refuses implicit results below 12.1. A client below 11.2 is
    # relayed at 11.2, which 23ai serves (#2430).
    opened: dict = {}
    monkeypatch.setattr(seerdb, 'connect', lambda **kwargs: opened.update(kwargs))
    backend = OraclePassthroughBackend(
        host='db', port=1521, service='S', credentials={'PYO': 'pyo123'}
    )
    backend.authenticate('PYO')
    backend.open_session({} if spoken is None else {'field_version': spoken})
    assert opened.get('field_version') == upstream


def test_a_character_bind_is_declared_with_its_buffer():
    # A character bind's declared buffer goes upstream with it (#2106): bound by
    # its value, a sqlplus VARCHAR2(30) variable (120 bytes) described at 32
    # where Oracle gives 128. The widest buffer a position is given across rows
    # is the one declared; an LTZ value is still declared LTZ (#1225), and a
    # plain value is left alone.
    import datetime

    import seerdb
    from seerdb.server import LtzValue, VarcharValue
    from seerdb.server.backends.passthrough import OraclePassthroughBackend

    class Cursor:
        declared = None

        def setinputsizes(self, *sizes):
            self.declared = sizes

    cursor = Cursor()
    ltz = LtzValue.of(datetime.datetime(2024, 1, 2))
    OraclePassthroughBackend._declare_value_binds(
        cursor,
        [
            [VarcharValue.of('hello', 120), ltz, 'plain', 5],
            [VarcharValue.of('x', 1012), ltz, 'plain', 6],
        ],
    )
    assert cursor.declared == (1012, seerdb.DB_TYPE_TIMESTAMP_LTZ, None, None)
    nothing = Cursor()
    OraclePassthroughBackend._declare_value_binds(nothing, [['plain', 5]])
    assert nothing.declared is None


def test_strips_the_redundant_ora_prefix():
    exc = seerdb.DatabaseError('ORA-00904: "X": invalid identifier', 904)
    err = _relay_error(exc)
    # The Mirror re-adds "ORA-00904: " from the code — the relayed message must be
    # bare so the final text carries the prefix exactly once.
    assert err.ora_code == 904
    assert err.ora_message == 'ORA-00904: "X": invalid identifier'


def test_recovers_the_code_from_the_prefix_when_absent():
    # Some client exceptions carry no numeric code; take it from the text.
    exc = seerdb.DatabaseError('ORA-01008: not all variables bound', None)
    err = _relay_error(exc)
    assert err.ora_code == 1008
    assert err.ora_message == 'ORA-01008: not all variables bound'


def test_message_without_a_prefix_is_left_alone():
    exc = seerdb.DatabaseError('some non-Oracle failure', None)
    err = _relay_error(exc)
    assert err.ora_code == 900  # ORA-00900, the BackendError default
    assert err.ora_message == 'ORA-00900: some non-Oracle failure'


def test_code_argument_wins_over_the_prefix_digits():
    # exc.code is authoritative when present, even if the text's digits differ.
    exc = seerdb.DatabaseError('ORA-00942: table or view does not exist', 942)
    err = _relay_error(exc)
    assert err.ora_code == 942
    assert err.ora_message == 'ORA-00942: table or view does not exist'


def test_relays_the_error_offset():
    # oracledb's DatabaseError.offset (the parse offset) is carried into the
    # BackendError so the Mirror draws its caret under the right column.
    exc = seerdb.DatabaseError('ORA-00904: "X": invalid identifier', 904)
    exc.offset = 7
    err = _relay_error(exc)
    assert err.error_offset == 7


def test_missing_offset_is_none():
    exc = seerdb.DatabaseError('ORA-00942: table or view does not exist', 942)
    # .offset defaults to None on a DatabaseError with no parse position.
    err = _relay_error(exc)
    assert err.error_offset is None


class _FakeVar:
    def __init__(self, value=None):
        self._value = value
        self.dbtype = None

    def setvalue(self, _pos, value):
        self._value = value

    def getvalue(self, _pos=0):
        # A real Var takes the iteration position; the RETURNING path passes it.
        return self._value


class _FakeCursor:
    """Records what _execute_plsql binds, without a database."""

    def __init__(self, out_values=None):
        self.bound = None
        self.declared = None
        self.description = None
        self.rowcount = 0
        self._out_values = out_values or {}

    def var(self, dbtype, size=None):
        # Keep the type asked for: which dbtype a bind resolves to is the thing
        # under test for a national bind (#990).
        var = _FakeVar()
        var.dbtype = dbtype
        var.size = size
        return var

    def arrayvar(self, dbtype, value_or_numelements, size=None):
        var = _FakeVar()
        var.dbtype = dbtype
        var.capacity = value_or_numelements
        return var

    def setinputsizes(self, *args):
        self.declared = args

    def execute(self, sql, variables):
        self.bound = list(variables)
        # Give each Var the fake OUT value the "block" assigned it; a Var the
        # block left alone keeps what it was seeded with, as on a real server.
        for i, v in enumerate(self.bound):
            if isinstance(v, _FakeVar) and i in self._out_values:
                v.setvalue(0, self._out_values[i])


def _plsql_binds(*binds):
    from seerdb.server.backend import BindVar

    return [BindVar(value=v, tns_type=t, max_size=m) for (v, t, m) in binds]


def test_typed_null_of_an_ordinary_statement_is_declared_upstream():
    # A NULL bind arrives as a BindVar with the type the client declared for
    # it (#699); the passthrough declares that type on its own cursor the same
    # way (setinputsizes) and binds the NULL, rather than taking the BindVar
    # for a PL/SQL OUT bind.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    (typed,) = _plsql_binds((None, TNS_TYPE_NUMBER, 22))
    result = backend.execute('SELECT id FROM t WHERE :1 IS NULL', [typed, 'x'])
    assert cursor.declared == (seerdb.DB_TYPE_NUMBER, None)
    assert cursor.bound == [None, 'x']
    assert result.rowcount == 0 and not result.out_binds
    assert not isinstance(cursor.bound[0], BindVar)


def test_an_ltz_bind_is_declared_upstream_as_one():
    # An LTZ bind arrives as an LtzValue (#1222); bound on as a bare datetime it
    # would be a TIMESTAMP, read in the session zone instead of the database's,
    # so the passthrough declares it LTZ -- alone, beside a typed NULL, and
    # across an array (#1225).
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import LtzValue

    value = datetime.datetime(2026, 9, 25, 13, 45, 6)
    ltz = LtzValue.of(value)

    class _ArrayCursor(_FakeCursor):
        def executemany(self, sql, rows, **kwargs):
            self.bound = [list(r) for r in rows]

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _ArrayCursor()
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()

    backend.execute('INSERT INTO t VALUES (:1, :2)', [ltz, value])
    assert cursor.declared == (seerdb.DB_TYPE_TIMESTAMP_LTZ, None)
    assert cursor.bound == [value, value]

    (typed,) = _plsql_binds((None, TNS_TYPE_NUMBER, 22))
    backend.execute('INSERT INTO t VALUES (:1, :2)', [typed, ltz])
    assert cursor.declared == (seerdb.DB_TYPE_NUMBER, seerdb.DB_TYPE_TIMESTAMP_LTZ)

    cursor.declared = None
    backend.execute_many('INSERT INTO t VALUES (:1, :2)', [[1, ltz], [2, None]])
    assert cursor.declared == (None, seerdb.DB_TYPE_TIMESTAMP_LTZ)

    cursor.declared = None
    backend.execute('INSERT INTO t VALUES (:1)', [value])
    assert cursor.declared is None


class _FakeLobConn:
    """An upstream connection that records the temp LOBs made on it."""

    def __init__(self, cursor, field_version):
        self._cursor = cursor
        self.field_version = field_version
        self.written: list = []

    def cursor(self):
        return self._cursor

    def create_temp_lob(self, is_blob=False):
        return b'LOC%d' % len(self.written)

    def write_temp_lob(self, locator, data, is_blob=False):
        self.written.append((locator, data, is_blob))


def test_a_plsql_lob_bind_below_12_1_is_a_plsql_string():
    # Below 12.1 the client has no LOB Var bind (#902), and a sqlplus CLOB
    # variable failed through the passthrough with "no bind encoding for data
    # type 112" (#2105). A block's CLOB / BLOB bind goes as PL/SQL's longest
    # VARCHAR2 / RAW instead, IN and OUT, which PL/SQL converts in an
    # assignment.
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        TNS_TYPE_BLOB,
        TNS_TYPE_CLOB,
    )

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor(out_values={0: 'clob var'})
    backend._conn = _FakeLobConn(cursor, FIELD_VERSION_11_2)
    binds = _plsql_binds(
        (None, TNS_TYPE_CLOB, 4000),
        ('in', TNS_TYPE_CLOB, 4000),
        (b'\x01', TNS_TYPE_BLOB, 4000),
    )
    result = backend._execute_plsql(cursor, 'BEGIN :1 := :2 || :3; END;', binds)
    assert [(v.dbtype, v.size) for v in cursor.bound] == [
        (str, 32767),
        (str, 32767),
        (bytes, 32767),
    ]
    assert result.out_binds == ['clob var', 'in', b'\x01']


def test_serveroutput_below_12_1_is_read_a_line_at_a_time():
    # sqlplus reads SERVEROUTPUT with DBMS_OUTPUT.GET_LINES into a collection,
    # which the client cannot bind below 12.1 (#2039), so sqlplus printed
    # nothing (#2104). The passthrough reads the lines with GET_LINE instead,
    # up to the count asked for, and hands them back as the collection.
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        TNS_TYPE_ADT,
        TNS_TYPE_NUMBER,
    )
    from seerdb.server.backend import BindVar

    class _LinesCursor(_FakeCursor):
        def __init__(self, lines):
            super().__init__()
            self.lines = list(lines)
            self.calls = 0

        def execute(self, sql, variables):
            assert sql == 'BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;'
            self.calls += 1
            (line, status) = variables
            if self.lines:
                line.setvalue(0, self.lines.pop(0))
                status.setvalue(0, 0)
            else:
                status.setvalue(0, 1)

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    backend._conn = type('Conn', (), {'field_version': FIELD_VERSION_11_2})()
    backend._gettype_by_oid = lambda oid: None
    binds = [
        BindVar(value=None, tns_type=TNS_TYPE_ADT, max_size=2000, toid=b'x' * 16),
        BindVar(value=2, tns_type=TNS_TYPE_NUMBER, max_size=22),
    ]
    call = 'BEGIN DBMS_OUTPUT.GET_LINES(:LINES, :NUMLINES); END;'
    cursor = _LinesCursor(['one', 'two', 'three'])
    assert backend._execute_plsql(cursor, call, binds).out_binds == [['one', 'two'], 2]
    assert cursor.calls == 2
    binds[1] = BindVar(value=5, tns_type=TNS_TYPE_NUMBER, max_size=22)
    assert backend._execute_plsql(cursor, call, binds).out_binds == [['three'], 1]
    assert backend._execute_plsql(cursor, call, binds).out_binds == [[], 0]


def test_a_lob_bound_into_plain_sql_is_bound_upstream_as_a_lob():
    # A LOB the client bound arrives as a ClobValue / BlobValue (#1067). Bound on
    # as a str it would be a VARCHAR2, which a real server refuses past 32 KB
    # (ORA-01461), so the passthrough puts it in an upstream temp LOB again.
    from seerdb.common.datatypes import TempLob
    from seerdb.server.backend import BlobValue, ClobValue

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    backend._conn = _FakeLobConn(cursor, FIELD_VERSION_12_1)
    text = 'x' * 40000
    backend.execute(
        'INSERT INTO t VALUES (:1, :2, :3)',
        [ClobValue(text), BlobValue(b'\x01'), 'plain'],
    )
    (c, b, plain) = cursor.bound
    assert isinstance(c, TempLob) and not c.is_blob
    assert isinstance(b, TempLob) and b.is_blob
    assert plain == 'plain' and not isinstance(plain, TempLob)
    assert backend._conn.written == [
        (c.locator, text, False),
        (b.locator, b'\x01', True),
    ]


def test_a_pre_12_1_upstream_keeps_the_lob_value():
    # 11g has no temp LOB to put it in (#91): bind the content, as before.
    from seerdb.server.backend import ClobValue

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    backend._conn = _FakeLobConn(cursor, FIELD_VERSION_12_1 - 1)
    backend.execute('INSERT INTO t VALUES (:1)', [ClobValue('short')])
    assert cursor.bound == ['short']
    assert backend._conn.written == []


def test_a_bc_date_is_carried_on_for_the_length_of_a_call():
    # Upstream rows are decoded inside execute(), and a date before year 1 must
    # come out as a BcDate there, not an error (#1069). The switch is set per
    # call -- the Mirror runs each call in a copied context -- and is gone after.
    from seerdb.common.datatypes import BcDate
    from seerdb.common.types import decode_date

    seen = []

    class _DecodingCursor(_FakeCursor):
        def execute(self, sql, variables):
            seen.append(decode_date(bytes.fromhex('35580101010101')))

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _DecodingCursor()
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    backend.execute('SELECT d FROM t')
    assert seen == [BcDate(-4712, 1, 1)]
    try:
        decode_date(bytes.fromhex('35580101010101'))
    except ValueError:
        pass
    else:
        raise AssertionError('the switch outlived the call')


def test_the_upstream_lastrowid_is_relayed():
    # A DML's touched row, single or array, as the upstream reported it (#1077).
    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    cursor.rowcount = 1
    cursor.lastrowid = 'AAAs/uAAAAAAWFFADg'
    cursor.executemany = lambda sql, rows: None
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    assert backend.execute('INSERT INTO t VALUES (1)').last_rowid == cursor.lastrowid
    many = backend.execute_many('INSERT INTO t VALUES (:1)', [[1], [2]])
    assert (many.rowcount, many.last_rowid) == (1, cursor.lastrowid)


def test_array_bind_registers_an_array_var_of_the_declared_capacity():
    # An associative-array BindVar (#743) becomes an arrayvar of the client's
    # capacity, seeded with the elements sent; its list comes back as the OUT.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor(out_values={1: [7, 8, 9]})
    binds = [
        BindVar(value=[1, 2], tns_type=TNS_TYPE_NUMBER, max_size=22, array_size=10),
        BindVar(value=[], tns_type=TNS_TYPE_NUMBER, max_size=22, array_size=4),
    ]
    result = backend._execute_plsql(cursor, 'BEGIN p(:1, :2); END;', binds)
    assert [getattr(v, 'capacity', None) for v in cursor.bound] == [10, 4]
    assert result.out_binds == [[1, 2], [7, 8, 9]]


def test_a_compilation_warning_is_relayed_from_upstream():
    # A CREATE whose PL/SQL object compiled with errors SUCCEEDED upstream and
    # said so on the upstream cursor. The passthrough relays it so the client
    # sees what the real server would; a backend that cannot tell leaves it
    # False and the client sees no warning, as before (#995).
    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})

    cursor = _FakeCursor()
    cursor.warning = object()  # the upstream driver's warning object
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    result = backend.execute('CREATE OR REPLACE PROCEDURE p AS BEGIN null END;')
    assert result.compilation_warning is True

    clean = _FakeCursor()
    clean.warning = None
    backend._conn = type('Conn', (), {'cursor': lambda self: clean})()
    assert backend.execute('CREATE TABLE t (n NUMBER)').compilation_warning is False


def test_an_array_bind_keeps_its_national_charset_form():
    # A national bind is the ordinary TNS type plus csfrm 2, so resolving a type
    # from tns_type alone binds NVARCHAR2 as VARCHAR2 upstream and a PL/SQL table
    # of the former rejects it with PLS-00418. The form rides on the BindVar
    # now, so the passthrough registers the right array type (#990).
    import seerdb
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    binds = [
        BindVar(
            value=['a'], tns_type=TNS_TYPE_VARCHAR, max_size=60, array_size=4, csfrm=2
        ),
        BindVar(
            value=['b'], tns_type=TNS_TYPE_VARCHAR, max_size=60, array_size=4, csfrm=1
        ),
    ]
    backend._execute_plsql(cursor, 'BEGIN p(:1, :2); END;', binds)
    assert [getattr(v, 'dbtype', None) for v in cursor.bound] == [
        seerdb.DB_TYPE_NVARCHAR,
        seerdb.DB_TYPE_VARCHAR,
    ]


def test_large_lob_in_bind_is_registered_as_a_lob_var():
    # A large CLOB / BLOB IN bind (#91) resolves to plain str / bytes. It used to
    # be bound as that value directly, which is IN-only -- a block that WRITES to
    # the bind then failed upstream with ORA-06502. It is registered as a LOB Var
    # instead, seeded with the value, so an IN OUT LOB comes back (#979).
    from seerdb.common.tns_consts import TNS_TYPE_CLOB, TNS_TYPE_NUMBER

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    backend._conn = type('Conn', (), {'field_version': FIELD_VERSION_12_1})()
    cursor = _FakeCursor(out_values={1: 42})
    binds = _plsql_binds(
        ('X' * 40000, TNS_TYPE_CLOB, 160000), (None, TNS_TYPE_NUMBER, 1)
    )
    result = backend._execute_plsql(cursor, 'BEGIN :r := f(:p); END;', binds)
    # Both positions are Vars now. The LOB one was seeded with the IN value, so
    # a block that leaves it alone still returns it -- and one that writes to it
    # returns what it wrote, which a bare string bind could never carry back.
    assert isinstance(cursor.bound[0], _FakeVar)
    assert isinstance(cursor.bound[1], _FakeVar)
    assert result.out_binds == ['X' * 40000, 42]


def test_a_printed_lob_variable_below_12_1_is_selected_as_a_lob():
    # sqlplus prints a CLOB variable with `SELECT :vc vc FROM DUAL`. Below 12.1
    # the value goes upstream as a plain str, which the upstream describes as
    # a VARCHAR2, and the column printed 32 wide, not a CLOB's 80 (#2124). The
    # lone bind goes as TO_CLOB / TO_BLOB of itself; anything else is left.
    from seerdb.common.tns_consts import FIELD_VERSION_11_2
    from seerdb.server.backend import BlobValue, ClobValue

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    backend._conn = type('Conn', (), {'field_version': FIELD_VERSION_11_2})()
    clob, blob = ClobValue('clob var'), BlobValue(b'\x01')
    assert (
        backend._lob_select_item('SELECT :vc vc FROM DUAL', [clob])
        == 'SELECT TO_CLOB(:vc) vc FROM DUAL'
    )
    assert (
        backend._lob_select_item('select :b from sys.dual', [blob])
        == 'select TO_BLOB(:b) from sys.dual'
    )
    for sql, binds in (
        ('SELECT :vc vc FROM DUAL', ['plain']),
        ('SELECT :a, :b FROM DUAL', [clob, clob]),
        ('SELECT :vc FROM t', [clob]),
    ):
        assert backend._lob_select_item(sql, binds) == sql
    backend._conn = type('Conn', (), {'field_version': FIELD_VERSION_12_1})()
    assert backend._lob_select_item('SELECT :vc vc FROM DUAL', [clob]) == (
        'SELECT :vc vc FROM DUAL'
    )


def test_large_lob_in_bind_stays_a_plain_value_below_12_1():
    # Below 12.1 a LOB Var has no bind encoding at all (#902), so the plain
    # str / bytes is all the upstream can take. IN-only, and its OUT slot is
    # None -- which the client discards anyway.
    from seerdb.common.tns_consts import TNS_TYPE_CLOB, TNS_TYPE_NUMBER

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    backend._conn = type('Conn', (), {'field_version': FIELD_VERSION_11_2})()
    cursor = _FakeCursor(out_values={1: 42})
    binds = _plsql_binds(
        ('X' * 40000, TNS_TYPE_CLOB, 160000), (None, TNS_TYPE_NUMBER, 1)
    )
    result = backend._execute_plsql(cursor, 'BEGIN :r := f(:p); END;', binds)
    assert cursor.bound[0] == 'X' * 40000
    assert isinstance(cursor.bound[1], _FakeVar)
    assert result.out_binds == [None, 42]


def test_returning_resolves_an_object_bind_like_execute_does():
    # An INSERT ... RETURNING with an object (ADT) IN bind: execute_returning
    # built its batch straight from the row, so an ObjectImage -- the row
    # decoder's placeholder, not a bindable value -- reached the upstream driver
    # and killed the Mirror connection (DPY-4011). execute() has always run its
    # binds through _resolve_object_binds; the RETURNING path must too (#826).
    # An unresolvable OID resolves to None, which the driver rejects cleanly with
    # ORA-00932 instead of dying.
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _FakeCursor()
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    # No type resolves for this OID, so _object_from_image yields None.
    backend._gettype_by_oid = lambda _oid: None
    image = ObjectImage(b'\x01' * 16, 'PYO', 'UDT_OBJ', 873, b'\x00\x01')
    receiver = BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)
    backend.execute_returning(
        'INSERT INTO t VALUES (:1) RETURNING id INTO :2', [[image, receiver]]
    )
    assert not isinstance(cursor.bound[0], ObjectImage)
    assert cursor.bound[0] is None
    assert isinstance(cursor.bound[1], _FakeVar)


def test_the_login_reply_carries_the_upstream_serial_without_v_session():
    # The serial has no sys_context equivalent. v$session needs a grant an
    # ordinary account lacks (ORA-00942), which left clients with the Mirror's
    # placeholder serial; DBMS_DEBUG_JDWP reports it to anyone (#1236).
    class _UpstreamCursor:
        def __init__(self, answers):
            self._answers, self._row = answers, None

        def execute(self, sql, *args):
            # The most specific needle first: the v$session query names
            # sys_context too.
            for needle, answer in self._answers.items():
                if needle in sql:
                    if isinstance(answer, Exception):
                        raise answer
                    self._row = answer
                    return
            raise AssertionError(sql)

        def fetchone(self):
            return self._row

    ident = ('62', 'FREE', 'FREE', None, 'freepdb1')
    no_view = seerdb.DatabaseError('ORA-00942: table or view does not exist')
    for answers, serial in (
        (
            {'dbms_debug_jdwp': (23073,), 'v$session': no_view, 'sys_context': ident},
            23073,
        ),
        ({'dbms_debug_jdwp': no_view, 'v$session': (77,), 'sys_context': ident}, 77),
        ({'dbms_debug_jdwp': no_view, 'v$session': no_view, 'sys_context': ident}, 0),
    ):
        cursor = _UpstreamCursor(answers)
        backend = OraclePassthroughBackend(
            host='h', port=1, service='s', credentials={}
        )
        backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
        info = backend.session_info()
        assert (info.session_id, info.serial_num) == (62, serial)


class _RecordingConn:
    """An upstream connection that records every statement its cursors run."""

    def __init__(self):
        self.statements = []
        self.closed_cursors = 0
        outer = self

        class _Cursor:
            def execute(self, sql, *args):
                outer.statements.append(sql)

            def close(self):
                outer.closed_cursors += 1

        self._cursor = _Cursor

    def cursor(self):
        return self._cursor()


def test_the_login_time_zone_reaches_the_upstream_session():
    # A 12.1+ client pins the session time zone to its own offset with an ALTER
    # SESSION in its login. The passthrough runs it upstream, so a client in
    # another zone than the Mirror's host sees its own offset (#1139). The offset
    # is deliberately one no test host is in.
    from seerdb.server.backends.passthrough import OraclePassthroughBackend

    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    backend._conn = _RecordingConn()
    statement = "ALTER SESSION SET TIME_ZONE='+05:45'"
    backend.alter_session(statement)
    assert backend._conn.statements == [statement]
    assert backend._conn.closed_cursors == 1


# DBMSOUTPUT_LINESARRAY as a live 23ai describes it: its id, and the type
# descriptor DBMS_PICKLER.GET_TYPE_SHAPE returns -- a VARRAY, bound 7fffffff,
# of VARCHAR2(32767) (#2016).
_LINESARRAY_OID = bytes.fromhex('508dca8ad30fc26ae06304bf6b64fdd6')
_LINESARRAY_TDS = bytes.fromhex(
    '00000021260100010001ff290000000000161c0000001d7fffffff032a077fff0100000007'
)


class _TypeShapeCursor:
    """Answers describe_type's catalog query and its DBMS_PICKLER block."""

    def __init__(self, row):
        self._row = row
        self.calls: list = []

    def var(self, dbtype, size=None):
        return _FakeVar()

    def execute(self, sql, variables):
        self.calls.append((sql, dict(variables)))
        if 'get_type_shape' in sql:
            variables['oid'].setvalue(0, _LINESARRAY_OID)
            variables['tds'].setvalue(0, _LINESARRAY_TDS)
            variables['status'].setvalue(0, 0)

    def fetchone(self):
        return self._row


def _type_backend(row):
    backend = OraclePassthroughBackend(host='h', port=1, service='s', credentials={})
    cursor = _TypeShapeCursor(row)
    backend._conn = type('Conn', (), {'cursor': lambda self: cursor})()
    return backend, cursor


def test_a_collection_type_is_described_from_upstream():
    # sqlplus describes DBMSOUTPUT_LINESARRAY before it reads SERVEROUTPUT's
    # lines; refused, it printed nothing through a passthrough (#2016). The id
    # and descriptor come from the upstream, the null-image descriptor is the
    # one every collection has.
    backend, cursor = _type_backend(('SYS', 'DBMSOUTPUT_LINESARRAY', 'VARYING ARRAY'))
    described = backend.describe_type('dbmsoutput_linesarray')
    assert described is not None
    assert (described.schema, described.name, described.kind) == (
        'SYS',
        'DBMSOUTPUT_LINESARRAY',
        'varray',
    )
    assert described.oid == _LINESARRAY_OID
    assert described.tds == _LINESARRAY_TDS
    assert described.null_tds == bytes.fromhex(
        '0000001226010001000100290000000000071a2a0007'
    )
    # A bare name: no schema, the type's own looked up by name.
    (_sql, binds) = cursor.calls[0]
    assert binds == {'type_owner': None, 'type_name': 'DBMSOUTPUT_LINESARRAY'}
    (_sql, binds) = cursor.calls[1]
    assert (binds['type_owner'], binds['type_name']) == ('SYS', 'DBMSOUTPUT_LINESARRAY')


def test_a_type_that_is_no_collection_is_not_described():
    # An object type, or no type at all, is not in ALL_COLL_TYPES; the describe
    # is then refused as before.
    backend, cursor = _type_backend(None)
    assert backend.describe_type('SCOTT.NO_SUCH_TYPE') is None
    assert cursor.calls[0][1] == {'type_owner': 'SCOTT', 'type_name': 'NO_SUCH_TYPE'}
