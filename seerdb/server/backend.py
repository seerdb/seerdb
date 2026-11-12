# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Backend contract — how the Mirror reaches an underlying database.

The Mirror speaks Oracle's wire protocol; a :class:`Backend` executes the SQL
behind it. One backend instance serves one client session. Concrete backends
(SQLite, PostgreSQL, …) live outside ``seerdb`` core, owning their driver
dependency; only this contract lives here.

Backends are **not** a least-common-denominator. Each declares its
:class:`Capability` set, and anything it cannot do is reported as a clean
``ORA-`` error (:class:`BackendError`) on a still-healthy connection — never a
desync. So SQLite legitimately refuses more than PostgreSQL, and that is
correct, not a failure.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum, auto
from typing import Protocol, runtime_checkable

from seerdb.common.tns import ColumnMeta
from seerdb.common.tns_consts import (
    ORA_INVALID_HEX_NUMBER,
    ORA_INVALID_NUMBER,
    ORA_INVALID_SQL_STATEMENT,
    ORA_UNIMPLEMENTED_FEATURE,
    TNS_TYPE_CHAR,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_VARCHAR,
)

# A username → secret map, the usual shape a backend authenticates against.
Credentials = Mapping[str, str]


def credential_lookup(credentials: Credentials, username: str) -> str | None:
    """Case-insensitive credential match — the usual body of a backend's
    :meth:`Backend.authenticate`. Oracle folds unquoted identifiers to
    upper-case, so ``PYO``, ``pyo`` and ``Pyo`` all match one entry. Returns the
    stored secret, or ``None`` when the user is unknown."""
    for name, secret in credentials.items():
        if name.upper() == username.upper():
            return secret
    return None


# What a listener refuses a connect with (#2471), the answers a backend's
# ``refuse_connect`` gives: a service it doesn't serve, an instance it isn't.
ORA_UNKNOWN_SERVICE = 12514
ORA_UNKNOWN_INSTANCE = 12521


class Capability(Enum):
    """A feature a backend may support. Absent → the Mirror answers a request
    that needs it with an ORA error instead of pretending."""

    TRANSACTIONS = auto()
    # Grow this as the Mirror's protocol surface does: LOBS, SEQUENCES,
    # PLSQL, SCROLLABLE_CURSORS, …


@dataclass(frozen=True)
class BindVar:
    """A PL/SQL bind the Mirror hands the backend with its declared type and
    return-buffer size, so the backend can register a correctly-sized OUT bind.

    The wire carries no bind direction — Oracle infers IN / OUT / IN OUT from the
    block itself — so the Mirror can't label binds up front. Instead it passes
    *every* bind of a PL/SQL block as a ``BindVar`` (the input ``value`` seeded,
    ``None`` for a pure OUT) and the backend binds each as an OUT-capable variable
    of ``tns_type`` sized ``max_size``. After execution the backend returns each
    variable's value in :attr:`Result.out_binds`; the ones the block wrote are the
    OUT / IN OUT results, and the client keeps only the positions it bound as
    ``Var`` (see ``_assign_out_binds``). ``max_size`` is the OAC buffer length the
    client declared (e.g. 32767 for a VARCHAR OUT) — the fix for the
    ``ORA-06502: buffer too small`` a value-only bind hit.

    An ordinary statement's NULL bind arrives the same way: ``value`` None and
    ``tns_type`` the type the client declared for it (``setinputsizes``). A NULL
    says nothing about its type, and a backend that has to know — a CASE arm, a
    parameter it cannot otherwise infer — reads it from here (#699). Every other
    bind of such a statement is passed as its bare value.

    A PL/SQL associative-array bind (``cursor.arrayvar``, #122) has
    ``array_size`` set to the capacity the client declared and ``value`` a list
    of its elements (empty for a pure OUT); the backend registers an array
    variable of that capacity and returns the list it holds afterwards (#743).
    A scalar bind has ``array_size`` 0.
    """

    value: object
    tns_type: int
    max_size: int
    array_size: int = 0
    # The bind's charset form, off the client's OAC. A national-charset bind is
    # not a distinct TNS type -- NVARCHAR2 is VARCHAR with csfrm 2, NCLOB is CLOB
    # with csfrm 2 -- so a backend that resolves a type from tns_type alone binds
    # the wrong one, and a PL/SQL table of NVARCHAR2 rejects it with PLS-00418
    # (#990). 1 (the database charset) for every ordinary bind.
    csfrm: int = 1
    # The referenced type's 16-byte OID for an object (ADT) bind, so the backend
    # can register a Var of that type for an object OUT / typed-NULL bind — the
    # value alone (None) carries no type identity (#888). Empty for every other
    # bind.
    toid: bytes = b''


class ClobValue(str):
    """A CLOB bind's content: a ``str`` that says it came from a LOB (#1067).

    A client that binds a real LOB -- a temp LOB it made and wrote, as
    python-oracledb's ``createlob`` does -- streams the content in over LOBOPS and
    binds the locator. The Mirror resolves that locator to the content, and a
    bare ``str`` would lose the fact that the client bound a LOB: a backend that
    binds it on to Oracle binds a VARCHAR2, which refuses anything over 32 KB
    (ORA-01461). This keeps it. It IS a ``str``, so a backend with no LOB
    binding of its own needs nothing new.
    """

    __slots__ = ()


class BlobValue(bytes):
    """A BLOB bind's content: the ``bytes`` twin of :class:`ClobValue` (#1067)."""

    __slots__ = ()


class VarcharValue(str):
    """A character bind's value: a ``str`` that carries the buffer size the
    client declared for it (#2063).

    Oracle describes a bind, and an expression over one, from that size rather
    than from the value: a sqlplus ``VARIABLE w VARCHAR2(253)`` declares 1012
    bytes, and ``SELECT :w || '!'`` describes 2001 wide however short ``:w`` is.
    It IS a ``str``, so a backend that does not care needs nothing new.
    """

    max_size: int

    @classmethod
    def of(cls, value: str, max_size: int) -> VarcharValue:
        text = cls(value)
        text.max_size = max_size
        return text


class LtzValue(datetime.datetime):
    """A TIMESTAMP WITH LOCAL TIME ZONE bind's value: a naive ``datetime`` that
    says it was bound as LTZ (#1222).

    An LTZ bind and a TIMESTAMP bind decode to the same naive ``datetime``, but
    Oracle reads them in different zones: an LTZ value is the instant in the
    database time zone, a TIMESTAMP a wall-clock time in the session's. A backend
    that stores both into an LTZ column has to know which it was handed. It IS a
    ``datetime``, so a backend that does not care needs nothing new.
    """

    __slots__ = ()

    @classmethod
    def of(cls, value: datetime.datetime) -> LtzValue:
        """The same wall-clock value, marked as bound as LTZ."""
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            value.tzinfo,
            fold=value.fold,
        )


class DateValue(datetime.datetime):
    """A DATE bind's value: a naive ``datetime`` that says it was bound as a
    DATE (#2593).

    A DATE and a TIMESTAMP bind with no fraction decode to the same
    ``datetime``, but Oracle types the bind, and every expression over it, by
    the type the client declared: the difference of two DATEs is a NUMBER of
    days, of two TIMESTAMPs an INTERVAL DAY TO SECOND. It IS a ``datetime``, so
    a backend that does not care needs nothing new.
    """

    __slots__ = ()

    @classmethod
    def of(cls, value: datetime.datetime) -> DateValue:
        """The same value, marked as bound as a DATE."""
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            value.tzinfo,
            fold=value.fold,
        )


class BinaryFloatValue(float):
    """A BINARY_FLOAT bind's value: a ``float`` that says it was bound as one
    (#2562).

    A BINARY_FLOAT, a BINARY_DOUBLE and a NUMBER bind can all decode to the
    same ``float``. Oracle types the bind, and every expression over it, by the
    type the client declared: ``SELECT :1 / 3 FROM dual`` describes a
    BINARY_FLOAT. A backend that binds the bare value on binds a NUMBER or a
    double. It IS a ``float``, so a backend that does not care needs nothing
    new.
    """

    __slots__ = ()


class BinaryDoubleValue(float):
    """A BINARY_DOUBLE bind's value: the double twin of
    :class:`BinaryFloatValue` (#2562)."""

    __slots__ = ()


@dataclass(frozen=True)
class CursorResult:
    """A REF CURSOR OUT bind's value: the nested result set the block opened, as
    columns + rows (#483). A backend returns one of these in
    :attr:`Result.out_binds` for a ``SYS_REFCURSOR`` OUT parameter; the Mirror
    parks the rows and hands the client a cursor id to fetch them from.
    """

    columns: list[ColumnMeta] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)


@dataclass(frozen=True)
class Result:
    """A backend execute outcome: query columns + rows, or a DML row count.

    ``out_binds`` carries the values a PL/SQL block assigned to its OUT binds,
    in bind order — the sqlplus ``VARIABLE`` / ``EXEC :v := ...`` flow, and the
    thin ``callproc`` / OUT-``Var`` flow (#483). Empty for an ordinary statement;
    when set, the Mirror returns them to the client instead of a plain status.
    """

    columns: list[ColumnMeta] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)
    rowcount: int = 0
    out_binds: list = field(default_factory=list)
    # What a `RETURNING ... INTO` statement gave back: one entry per execute
    # iteration, each the rows that iteration affected, each row holding one
    # value per return bind in bind order (#689). An iteration that matched
    # nothing contributes an empty list rather than being left out, so the
    # positions stay aligned with the rows the client sent.
    returned_rows: list[list[tuple]] = field(default_factory=list)
    # The result sets a PL/SQL block handed back through DBMS_SQL.RETURN_RESULT,
    # in the order it returned them, each as (columns, rows) (#121/#826). Empty
    # for everything else. The Mirror parks each on a cursor of its own and names
    # them in the reply, so the client fetches them like REF CURSORs.
    implicit_results: list[tuple[list[ColumnMeta], list[tuple]]] = field(
        default_factory=list
    )
    # True when the statement CREATED a PL/SQL object that compiled with errors
    # (#995). The call succeeded and the object exists, invalid -- there is no
    # error code to carry it, so it rides as bit 0x20 of the OER's warn byte,
    # which is the only thing in the reply that differs from a clean create. A
    # backend that cannot tell leaves it False and the client sees no warning,
    # which is what it saw before this existed.
    compilation_warning: bool = False
    # The rowid of the last row a DML statement touched, in Oracle's printable
    # extended form ('AAAs/uAAAAAAWFFADg'), which the client reports as
    # cursor.lastrowid (#1077). None for anything else, and for a backend with no
    # Oracle rowids -- which is what every backend reported before this existed.
    last_rowid: str | None = None
    # A PL/SQL block's bind directions, one per bind (16 OUT, 32 IN, 48 IN OUT),
    # as the server reported them. The wire carries no direction on the way in,
    # so a backend that cannot know leaves this empty and every bind is reported
    # OUT, as before -- which is what a client tolerates but not what a real
    # server says (#1064).
    bind_directions: tuple[int, ...] = ()


@dataclass(frozen=True)
class SessionInfo:
    """What a login reply tells the client about its session (#826).

    A client reads these ONLY from the auth reply -- `connection.session_id`,
    `.serial_num`, `.instance_name`, `.db_name`, `.service_name` never query for
    them -- so a Mirror that reports placeholders here leaves them wrong however
    correct the session otherwise is. Every field is optional: a backend fills in
    what it knows, and the reply carries only those.
    """

    session_id: int = 0
    serial_num: int = 0
    instance_name: str | None = None
    db_name: str | None = None
    db_domain: str | None = None
    service_name: str | None = None


@dataclass(frozen=True)
class TypeDescription:
    """An object or collection type, as an OCI client's type describe needs it
    (PROTOCOL.md §40, #1411).

    ``oid`` is the type's 16-byte id, the one its objects and binds carry.
    ``kind`` is ``'object'``, ``'varray'`` or ``'nested_table'``. ``tds`` and
    ``null_tds`` are its type descriptor and null-image descriptor, each with its
    ub4 length in front -- the pair ``DBMS_PICKLER.GET_TYPE_SHAPE`` returns.
    """

    schema: str
    name: str
    oid: bytes
    kind: str
    tds: bytes
    null_tds: bytes


class BackendError(Exception):
    """A backend failure surfaced to the client as an ORA error.

    The Mirror turns it into an OER (``ORA-<ora_code>: <message>``) and keeps
    the connection usable — the client sees a normal, recoverable error rather
    than a dropped connection. Defaults to ``ORA-00900`` (invalid SQL statement).
    """

    def __init__(
        self,
        message: str,
        *,
        ora_code: int = ORA_INVALID_SQL_STATEMENT,
        error_offset: int | None = None,
        rowcount: int = 0,
        row_counts: list[int] | None = None,
    ) -> None:
        super().__init__(message)
        self.ora_code = ora_code
        self.ora_message = f'ORA-{ora_code:05d}: {message}'
        # The 0-based parse offset of the error in the statement text (the column
        # sqlplus draws its caret under), when the backend knows it; None means
        # unknown and the Mirror uses its default.
        self.error_offset = error_offset
        # The rows this call applied BEFORE it failed. An executemany whose
        # batch aborts part-way really did write the earlier rows, and a real
        # server reports how many -- a caller deciding what to retry or roll
        # back is otherwise told nothing happened (#998). 0 for everything that
        # failed outright.
        self.rowcount = rowcount
        # The PER-ITERATION counts, for a batch that asked for them and then
        # aborted (#1031). The client asked for arraydmlrowcounts, so the rows
        # that did apply owe it their counts in the ERROR reply too -- without
        # them it reports the mode as never enabled, which is a worse answer
        # than the failure it is also being told about. Empty when unknown.
        self.row_counts = list(row_counts or [])


def as_declared_type(value: object, tns_type: int) -> object:
    """A RETURNING value converted to the type its receiving bind declared.

    Oracle converts what the clause returns into the variable's type, and fails
    the statement when it cannot: text returned into a RAW is read as hex
    (ORA-01465 if it is not), into a NUMBER as a number (ORA-01722), and bytes
    returned into a string become their hex text. A backend hands back its own
    column's value, so without this a VARCHAR2 into a RAW arrived as its raw
    bytes, and into a NUMBER was encoded as if its text were a NUMBER -- '42'
    read back as -5.1E+21 (#1370). A value already of the declared kind, which
    is all a passthrough backend returns, passes unchanged.

    A backend converts inside the statement's own savepoint, so a value that
    fails undoes the statement as Oracle does; raised once the statement is
    kept, it would leave the row Oracle does not.
    """
    if tns_type == TNS_TYPE_RAW and isinstance(value, str):
        text = value.strip()
        try:
            return bytes.fromhex(text if len(text) % 2 == 0 else '0' + text)
        except ValueError:
            raise BackendError(
                'invalid hex number', ora_code=ORA_INVALID_HEX_NUMBER
            ) from None
    if tns_type == TNS_TYPE_NUMBER and isinstance(value, str):
        try:
            return Decimal(value.strip())
        except ArithmeticError:
            raise BackendError('invalid number', ora_code=ORA_INVALID_NUMBER) from None
    if tns_type in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR) and isinstance(
        value, (bytes, bytearray)
    ):
        return bytes(value).hex().upper()
    return value


class UnsupportedFeature(BackendError):
    """The backend cannot fulfil a request — reported as ``ORA-03001``
    (unimplemented feature). A clean "no", not a crash."""

    def __init__(self, message: str) -> None:
        super().__init__(message, ora_code=ORA_UNIMPLEMENTED_FEATURE)


@runtime_checkable
class Backend(Protocol):
    """What the Mirror needs from an underlying database (one per session).

    The methods below are required. Beyond them the session probes for optional
    extensions and falls back cleanly when they are absent, so a backend
    implements only what it can do:

    ``execute_many(sql, rows) -> int | Result``
        Apply a whole array-DML batch in one call, returning the total
        affected-row count -- or a :class:`Result` carrying it, when there is a
        ``last_rowid`` to report too (#1077). Without it the session applies the
        rows one at a time.

    ``execute_many_rowcounts(sql, rows) -> tuple[int, list[int]]``
        The same, plus the per-iteration counts a 12c client can ask for.

    ``execute_returning(sql, rows) -> Result``
        Run a ``DML ... RETURNING col INTO :b`` statement and report what came
        back, in :attr:`Result.returned_rows` (#689). ``rows`` is one entry per
        execute iteration -- a plain execute has one, an array execute one per
        row submitted -- each holding the bind values in bind order with a
        :class:`BindVar` standing in at every position the RETURNING clause
        fills. Those carry no value from the client, and the BindVar says what
        type is wanted there. Without it such a statement is refused with an ORA
        error rather than breaking the connection.

    ``refuse_connect(service_name, instance_name) -> int | None``
        Asked once per connection, before anything else, with the
        ``SERVICE_NAME`` (or ``SID``) and ``INSTANCE_NAME`` the client's connect
        descriptor names, either ``None`` when it names none. Answer the ORA
        code a listener refuses the connect with -- 12514 for a service this
        backend doesn't serve, 12521 for an instance -- or None to serve it
        (#2471). Without it every name is served.

    ``session_info() -> SessionInfo``
        The session's real identity -- id, serial number, instance / database /
        service name -- which the Mirror reports in the login reply. A client
        exposes these as ``connection.session_id`` and friends, and reads them
        ONLY from that reply, never by querying (#826). Without it the Mirror
        reports a placeholder id of 0 and no names at all.

    ``session_release() -> ServerIdentity | None``
        The release of the server the session runs on, asked after
        :meth:`authenticate`: the packed release the login reports, and the
        banner and release sqlplus's version call is answered with (#2024). A
        passthrough answers with its upstream's, so a client sees the release
        it would see direct. Without it, or answering None, the Mirror presents
        the identity of its field version.

    ``refuse_implicit_results() -> None``
        Called once, after :meth:`authenticate`, for a client below 12.1, which
        can't take an implicit result (#2419). From then on the session's
        ``DBMS_SQL.RETURN_RESULT`` raises ORA-29481 where it is called, as 23ai
        does, so a handler in the block can catch it and, uncaught, it fails the
        block. Without it such a client is sent the results.

    ``apply_app_context(namespace, values) -> None``
        Set the attributes ``values`` (a dict) of an application context
        namespace, or clear the namespace when ``values`` is None -- what a
        client's ``set_app_context()`` / ``clear_app_context()`` sends with its
        next call (#1778). A namespace the session may not set raises
        :class:`BackendError` ORA-28267, which fails that call unrun, as a real
        server does. Without it the change is dropped.

    ``describe(sql) -> list[ColumnMeta]``
        Describe a statement without running it, for ``cursor.parse()`` (#826).
        Without it the Mirror runs the query with every bind NULL and drops the
        rows, which is side-effect free but does reach the database.

    ``open_ref_cursor(sql) -> object``
        Open a cursor on ``sql`` and return something :meth:`execute` will
        accept as a bind value — for a PL/SQL block that takes an open
        ``sys_refcursor`` IN parameter and fetches from it (#1048). The cursor
        must be left OPEN and UNREAD: the Mirror advances it itself, by serving
        the rows the client has already had, so that the block resumes exactly
        where the client stopped. Without it such a bind is refused with an ORA
        error rather than handing the block a cursor positioned wrongly.

    ``parse(sql) -> None``
        Validate a statement without running it — the other half of
        ``cursor.parse()``, for everything that is not a query and so owes no
        describe (#1019). Raise :class:`BackendError` for a statement that will
        not parse; return nothing for one that will. Without it the Mirror
        answers a bare success status, so every parse-time error is lost: a
        client asking whether a statement is valid is told yes whatever it sent.
        A backend that cannot parse Oracle SQL at all is right to omit it.

    ``describe_type(name) -> TypeDescription | None``
        The object or collection type ``name`` names, as the connected user
        would resolve it, or None if there is none. An OCI client (sqlplus)
        describes a type this way before it binds one -- sqlplus does it for
        ``DBMS_OUTPUT.GET_LINES`` under ``set serveroutput on`` (#1411). Without
        it the describe is refused with an ORA error.

    ``field_version`` (int) / ``tns_version`` (int)
        The Oracle protocol version this backend presents. A backend that
        declares ``field_version`` makes the Mirror advertise it -- its identity
        (banner / release), the negotiated wire formats, and the auth parsers all
        follow it -- so the version is the backend's to choose, not the server's
        launch flag: the PostgreSQL / SQLite demos pin 11.2 (they cannot back the
        12c+ formats a higher version invites), while a passthrough presents the
        release its upstream speaks. ``tns_version`` overrides the framing version
        derived from it (needed only above 12.2, where the derivation caps).
        Absent (or ``None``), the Mirror uses the version it was launched with. A
        plain class attribute satisfies these, like ``capabilities``.
    """

    @property
    def capabilities(self) -> frozenset[Capability]:
        """The features this backend supports. A plain class attribute
        satisfies this too; a property lets a wrapper defer to what it wraps."""
        ...

    def authenticate(self, username: str) -> str | None:
        """Return the O5LOGON secret (plaintext password) for ``username``, or
        ``None`` to reject the login.

        The Mirror stores no credentials of its own — auth lives with the
        backend, mirroring how Oracle keeps it. O5LOGON is *mutual*: the Mirror
        must know the secret to prove itself to the client (it never sees the
        client's password), so this returns the secret rather than validating a
        supplied one. :func:`credential_lookup` covers the common map-backed case.
        """
        ...

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        """Run ``sql`` and return its columns + rows (or a DML row count).

        Raise :class:`BackendError` (or :class:`UnsupportedFeature`) for
        anything the backend cannot do — the Mirror maps it to an ORA error.
        """
        ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...
