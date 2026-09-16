# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A Mirror backend that relays to a real Oracle database via seerdb thin.

Turns the Mirror into a transparent Oracle-to-Oracle relay: a client speaks to
the Mirror, the Mirror runs each statement on a real Oracle and returns the real
results. Its purpose is conformance testing — running the integration suite
against the Mirror so that any failure isolates a *Mirror protocol* gap rather
than a backend SQL-dialect limitation (which is what the SQLite backend hits).

One backend (and one upstream Oracle connection) per Mirror session; the
credential map supplies the O5LOGON secret the Mirror needs to authenticate the
client, and the same credentials open the upstream connection.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Sequence
from dataclasses import replace

import seerdb
from seerdb.common.datatypes import TempLob, dbtype_for_oracle_type
from seerdb.common.dbobject import (
    DbObject,
    DbObjectType,
    ObjectImage,
    decode_collection_image,
    decode_object_image,
)
from seerdb.common.sqltext import is_plsql
from seerdb.common.tns import AL16UTF16_CHARSET, ColumnMeta
from seerdb.common.tns_consts import (
    TNS_TYPE_ADT,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_REF,
    TNS_TYPE_REFCURSOR,
)
from seerdb.server.backend import (
    BackendError,
    BindVar,
    Capability,
    CursorResult,
    Result,
)


class OraclePassthroughBackend:
    """Relays statements to a real Oracle at ``(host, port, service)``."""

    capabilities: frozenset[Capability] = frozenset()

    @staticmethod
    def detect_version(
        host: str,
        port: int,
        service: str,
        user: str,
        password: str,
        *,
        timeout: int = 15000,
    ) -> int | None:
        """Probe the target once and return the field version it negotiates, so a
        Mirror in front of it presents the same release (§ ``Backend.field_version``).

        A session's own upstream connection opens in :meth:`authenticate`, which
        runs mid-login — too late to drive the handshake the Mirror already sent.
        So the version is learned once at startup instead, from one short-lived
        connection. Returns ``None`` if the probe fails (the target is down, the
        credentials are wrong); the caller then falls back to the Mirror's default.
        """
        try:
            conn = seerdb.connect(
                host=host,
                port=port,
                service_name=service,
                user=user,
                password=password,
                timeout=timeout,
            )
        except Exception:
            return None
        try:
            return conn.field_version
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def __init__(
        self,
        *,
        host: str,
        port: int,
        service: str,
        credentials: dict[str, str],
        field_version: int | None = None,
        tns_version: int | None = None,
    ) -> None:
        # The Oracle release this passthrough presents to its own clients — set
        # it to match the target so the Mirror advertises what the real server
        # behind it speaks (the Mirror reads these off the backend). Left None,
        # the Mirror falls back to its launch default.
        self.field_version = field_version
        self.tns_version = tns_version
        self._host = host
        self._port = port
        self._service = service
        # Held by reference (not copied) so a changepassword updates the same map
        # every session's backend authenticates against — a fresh connection then
        # sees the new password (#21/#486). Keys are upper-cased in place.
        self._credentials = credentials
        for name in list(self._credentials):
            if name != name.upper():
                self._credentials[name.upper()] = self._credentials.pop(name)
        self._conn: seerdb.OracleConnect | None = None

    def authenticate(self, username: str) -> str | None:
        password = self._credentials.get(username.upper())
        if password is None:
            return None
        # Open the upstream connection now, with the same credentials, so the
        # session is ready by the time the client runs its first statement.
        # autocommit=False so the client drives the upstream transaction through
        # the Mirror: an explicit commit / rollback reaches the backend, and an
        # autocommit client still commits because the Mirror calls backend.commit()
        # per statement. With the driver default (autocommit=True) every statement
        # would commit upstream and a client rollback would be a no-op.
        self._conn = seerdb.connect(
            host=self._host,
            port=self._port,
            user=username,
            password=password,
            service_name=self._service,
            autocommit=False,
        )
        return password

    def _gettype_by_oid(self, oid: bytes) -> DbObjectType | None:
        # Resolve a type's 16-byte OID to its DbObjectType via all_types (the bind
        # OAC carries only the OID, not the name). None if it cannot be resolved.
        assert self._conn is not None
        if not oid:
            return None
        # A value's toid is the constructed 36-byte form (00 22 02 08 + OID +
        # extent); the OAC carries the bare 16-byte OID. Accept either.
        if len(oid) >= 20:
            oid = oid[4:20]
        probe = self._conn.cursor()
        probe.execute(
            'SELECT owner, type_name FROM all_types WHERE type_oid = :1', [oid]
        )
        row = probe.fetchone()
        if row is None:
            return None
        owner, name = row
        return self._conn.gettype(f'{owner}.{name}')

    def _object_from_image(self, image: ObjectImage) -> object:
        # Turn an inbound object (ADT) bind's image back into a DbObject the
        # upstream connection can bind (#888): resolve the type, decode the image
        # against its layout, and rebuild the object (or collection). None if the
        # OID cannot be resolved -- the caller then binds NULL rather than
        # desyncing.
        typ = self._gettype_by_oid(image.type_oid or b'')
        if typ is None:
            return None
        lob_contents = getattr(image, 'lob_contents', None) or {}
        if getattr(typ, 'is_collection', False):
            elements = decode_collection_image(image.image, typ.element)
            obj = typ.newobject(list(elements))
        else:
            attrs = decode_object_image(image.image, typ.attrs)
            obj = typ.newobject(dict(attrs))
        self._materialize_bind_object_lobs(obj, lob_contents)
        return obj

    def _materialize_bind_object_lobs(self, value: object, lob_contents: dict) -> None:
        # Replace each LOB attribute's locator (a Mirror locator the client echoed
        # from a fetch or a createlob) with an upstream LOB carrying the content
        # the Mirror served, so the upstream bind sees a real LOB rather than a
        # dangling locator (#888). A locator with no known content binds NULL --
        # far better than an ORA-22275 desync. Nested objects / collections recurse.
        if not isinstance(value, DbObject):
            return
        typ = value._dbtype
        if typ is not None and typ.is_collection:
            element = typ.element or {}
            for idx, elem in enumerate(value._elements):
                value._elements[idx] = self._materialize_member_lob(
                    elem, element, lob_contents
                )
            return
        if typ is None:
            return
        for attr in typ.attrs:
            name = attr['name']
            value._attrs[name] = self._materialize_member_lob(
                value._attrs.get(name), attr, lob_contents
            )

    def _materialize_member_lob(
        self, value: object, attr: dict, lob_contents: dict
    ) -> object:
        from seerdb.common.lob import LOB

        if attr.get('object_type') is not None:
            if value is not None:
                self._materialize_bind_object_lobs(value, lob_contents)
            return value
        if value is None:
            return value
        data_type = attr.get('data_type')
        if data_type not in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) or not isinstance(
            value, (bytes, bytearray)
        ):
            return value
        # `value` is the LOB locator the client sent inside the image. Resolve it
        # to the content the Mirror served, then stream that into an upstream temp
        # LOB and bind the object attribute to it.
        entry = _lookup_bind_lob(lob_contents, bytes(value))
        if entry is None:
            return None
        content, _is_clob = entry
        is_blob = data_type == TNS_TYPE_BLOB
        assert self._conn is not None
        locator = self._conn.create_temp_lob(is_blob=is_blob)
        if content and isinstance(content, (str, bytes)):
            self._conn.write_temp_lob(locator, content, is_blob=is_blob)
        return LOB(data_type, locator, self._conn)

    def _resolve_fetched_object_lobs(self, columns: list, rows: list) -> list:
        # An object (ADT) column's LOB attributes decode upstream to bare locator
        # bytes (seerdb leaves a LOB attribute's content unread). The external
        # client, though, reads each such attribute back over TTI_LOBOPS against
        # the Mirror -- which serves LOB content it has already read, not upstream
        # locators -- so resolve every object LOB attribute to its content now,
        # while the upstream connection is in hand (#888). Non-object columns and
        # objects without LOB attributes are untouched.
        adt_positions = [
            i for i, col in enumerate(columns) if int(col.data_type) == TNS_TYPE_ADT
        ]
        if not adt_positions:
            return rows
        resolved: list = []
        for row in rows:
            cells = list(row)
            for i in adt_positions:
                if cells[i] is not None:
                    self._resolve_object_lobs(cells[i])
            resolved.append(tuple(cells))
        return resolved

    def _resolve_object_lobs(self, value: object) -> None:
        # Walk an object (or collection) value in place, replacing each LOB
        # attribute's locator bytes with the content read from upstream. Nested
        # objects and collections recurse. Mirrors _object_lob_contents' walk.
        if not isinstance(value, DbObject):
            return
        typ = value._dbtype
        if typ is not None and typ.is_collection:
            element = typ.element or {}
            for idx, elem in enumerate(value._elements):
                value._elements[idx] = self._resolve_member_lob(elem, element)
            return
        if typ is None:
            return
        for attr in typ.attrs:
            name = attr['name']
            value._attrs[name] = self._resolve_member_lob(value._attrs.get(name), attr)

    def _resolve_member_lob(self, value: object, attr: dict) -> object:
        # One attribute / element: recurse into a nested object / collection, read
        # a LOB attribute's content, or leave a plain scalar as-is.
        from seerdb.common.lob import LOB

        if attr.get('object_type') is not None:
            if value is not None:
                self._resolve_object_lobs(value)
            return value
        if value is None:
            return value
        data_type = attr.get('data_type')
        if data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) and isinstance(
            value, (bytes, bytearray)
        ):
            # The decoded attribute is the raw LOB locator; read its content over
            # the upstream connection so the Mirror can serve it back.
            return LOB(data_type, bytes(value), self._conn).read()
        return value

    def _resolve_object_binds(self, binds: Sequence) -> list:
        # Replace any object (ADT) bind -- a bare ObjectImage, or one wrapped in a
        # BindVar -- with the DbObject the upstream binds. A NULL object arrives
        # as None already, so only a populated image needs resolving (#888).
        out: list = []
        for b in binds:
            value = b.value if isinstance(b, BindVar) else b
            if isinstance(value, ObjectImage):
                obj = self._object_from_image(value)
                out.append(replace(b, value=obj) if isinstance(b, BindVar) else obj)
            else:
                out.append(b)
        return out

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        binds = self._resolve_object_binds(binds)
        # A PL/SQL block hands its binds over as BindVar (value + type + buffer
        # size) so OUT binds can be registered correctly (#483). Bind each as an
        # OUT-capable Var seeded with the input value, run, and return every Var's
        # value; the Mirror marks them OUT and the client keeps its own positions.
        if any(isinstance(b, BindVar) for b in binds):
            if is_plsql(sql):
                return self._execute_plsql(cursor, sql, binds)
            # An ordinary statement's BindVar is either a typed NULL (#699) or a
            # LOB the Mirror could not bind as a bare value -- an empty CLOB /
            # BLOB, which stores NULL when bound as a plain '' / b'' (#903).
            # Route a LOB-typed bind through an upstream temp LOB so it stores as
            # a non-NULL LOB (seerdb has no CLOB / BLOB Var-bind); declare every
            # other typed NULL the way the client did and bind its value.
            sizes: list = []
            resolved: list = []
            for b in binds:
                if isinstance(b, BindVar) and b.tns_type in (
                    TNS_TYPE_CLOB,
                    TNS_TYPE_BLOB,
                ):
                    is_blob = b.tns_type == TNS_TYPE_BLOB
                    locator = self._conn.create_temp_lob(is_blob=is_blob)
                    if b.value and isinstance(b.value, (str, bytes)):
                        self._conn.write_temp_lob(locator, b.value, is_blob=is_blob)
                    sizes.append(None)
                    resolved.append(TempLob(locator, is_blob))
                elif isinstance(b, BindVar):
                    sizes.append(dbtype_for_oracle_type(b.tns_type, 1))
                    resolved.append(b.value)
                else:
                    sizes.append(None)
                    resolved.append(b)
            cursor.setinputsizes(*sizes)
            binds = resolved
        try:
            cursor.execute(sql, list(binds))
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        if cursor.description:
            columns = [_to_column_meta(desc) for desc in cursor.description]
            rows = cursor.fetchall()
            columns = _enrich_ref_columns(columns, rows)
            rows = self._resolve_fetched_object_lobs(columns, rows)
            return Result(columns=columns, rows=rows)
        return Result(rowcount=cursor.rowcount or 0)

    def execute_many(self, sql: str, rows: Sequence[Sequence]) -> int:
        # Array DML (executemany): send the whole batch upstream in one round-trip
        # through seerdb's own cursor.executemany — one parse, len(rows) iterations
        # — instead of the Mirror's per-row fallback (one upstream round-trip per
        # bind row, which paid the network latency once per row). Returns the total
        # affected-row count. The Mirror calls this only for the non-batcherrors
        # path, where an upstream failure aborts the whole batch — exactly Oracle's
        # own non-batcherrors semantics.
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        try:
            cursor.executemany(sql, [list(row) for row in rows])
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        return cursor.rowcount or 0

    def execute_many_rowcounts(
        self, sql: str, rows: Sequence[Sequence]
    ) -> tuple[int, list[int]]:
        # Array DML with the per-iteration affected-row counts (arraydmlrowcounts,
        # #18): run the batch upstream asking for them, and return the total plus
        # the count list the client reads back through getarraydmlrowcounts().
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        try:
            cursor.executemany(sql, [list(row) for row in rows], arraydmlrowcounts=True)
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        return cursor.rowcount or 0, list(cursor.getarraydmlrowcounts())

    def execute_returning(self, sql: str, rows: Sequence[Sequence]) -> Result:
        # DML ... RETURNING col INTO :b (#689). The upstream is a real Oracle, so
        # the statement goes over unchanged; only the binds the clause fills need
        # building, as Vars of the type the client declared. One Var per return
        # bind is shared across the whole batch, which is how the driver reports
        # per-iteration values: getvalue(i) is what iteration i returned.
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        positions = [i for i, b in enumerate(rows[0]) if isinstance(b, BindVar)]
        receivers = {}
        for i in positions:
            bind = rows[0][i]
            dbtype = dbtype_for_oracle_type(bind.tns_type, 1)
            size = bind.max_size if bind.max_size and bind.max_size > 0 else None
            receivers[i] = (
                cursor.var(dbtype, size) if dbtype is not None else cursor.var(str)
            )
        batch = [
            [receivers[i] if i in receivers else value for i, value in enumerate(row)]
            for row in rows
        ]
        try:
            if len(batch) > 1:
                cursor.executemany(sql, batch)
            else:
                cursor.execute(sql, batch[0])
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        # Per iteration, each receiver yields the list of values for the rows that
        # iteration affected. Transpose to rows so every returned row carries one
        # value per return bind, in bind order.
        returned = []
        for iteration in range(len(batch)):
            columns = [receivers[i].getvalue(iteration) or [] for i in positions]
            returned.append([tuple(values) for values in zip(*columns)])
        return Result(rowcount=cursor.rowcount or 0, returned_rows=returned)

    def _execute_plsql(self, cursor, sql: str, binds: Sequence) -> Result:
        # Each PL/SQL bind is registered as an OUT-capable Var (the wire carries
        # no direction) except a large LOB IN value: a resolved temp-LOB CLOB /
        # BLOB (#91) is bound as its plain str / bytes, which seerdb re-promotes
        # through an upstream temp LOB. A cursor.var(LOB) has no client-side OAC,
        # and such a bind is only ever IN here, so it needs no Var — its OUT slot
        # is None (the client discards a non-Var position anyway).
        variables = []
        for bind in binds:
            if (
                bind.tns_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB)
                and bind.value is not None
            ):
                variables.append(bind.value)
                continue
            if bind.tns_type == TNS_TYPE_ADT:
                # An object (ADT) bind (#888). A populated IN value was already
                # turned into a DbObject by _resolve_object_binds and binds as a
                # plain value. A None value is an object OUT bind (a function
                # returning an object/collection) or a typed NULL: register a Var
                # of the type so the result comes back typed and a NULL carries
                # its type for overload resolution. The OAC's OID rides on the
                # BindVar; if it cannot be resolved, fall through to bind None.
                if bind.value is not None:
                    variables.append(bind.value)
                    continue
                objtype = self._gettype_by_oid(bind.toid)
                if objtype is not None:
                    variables.append(cursor.var(objtype))
                    continue
            dbtype = dbtype_for_oracle_type(bind.tns_type, 1)
            if bind.array_size:
                # An associative-array bind (#743): an array variable of the
                # declared capacity, seeded with the elements the client sent
                # (none for a pure OUT); getvalue() returns the list afterwards.
                var = cursor.arrayvar(
                    dbtype if dbtype is not None else str, bind.array_size
                )
                if bind.value:
                    var.setvalue(0, list(bind.value))
                variables.append(var)
                continue
            if bind.tns_type == TNS_TYPE_REFCURSOR:
                # A REF CURSOR OUT param: the DB opens the cursor, so bind a
                # cursor var and don't seed it.
                var = cursor.var(seerdb.DB_TYPE_CURSOR)
            else:
                size = bind.max_size if bind.max_size and bind.max_size > 0 else None
                var = (
                    cursor.var(dbtype, size) if dbtype is not None else cursor.var(str)
                )
                if bind.value is not None:
                    var.setvalue(0, bind.value)
            variables.append(var)
        try:
            cursor.execute(sql, variables)
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        # A plain-value (LOB IN) position has no OUT value — None; a Var yields
        # its assigned value (a nested cursor for a REF CURSOR).
        return Result(
            out_binds=[
                _out_value(v.getvalue()) if hasattr(v, 'getvalue') else None
                for v in variables
            ]
        )

    def sessionless_begin(self, transaction_id: bytes, timeout: int) -> None:
        # Start a sessionless transaction on the upstream connection so the
        # client's work is isolated there and resumable from another session.
        assert self._conn is not None
        try:
            self._conn.begin_sessionless_transaction(transaction_id, timeout=timeout)
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc

    def sessionless_resume(self, transaction_id: bytes, timeout: int) -> None:
        assert self._conn is not None
        try:
            self._conn.resume_sessionless_transaction(transaction_id, timeout=timeout)
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc

    def sessionless_suspend(self) -> None:
        assert self._conn is not None
        try:
            self._conn.suspend_sessionless_transaction()
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        # ALTER USER ... REPLACE validates the old password and sets the new one
        # on the real Oracle; the live upstream session stays authenticated. Then
        # update the shared credential map so a fresh Mirror session authenticates
        # (O5LOGON) with the new password and the old one is rejected (#21/#486).
        assert self._conn is not None  # authenticate() ran before any execute
        cursor = self._conn.cursor()
        quoted = new_password.replace('"', '""')
        old_quoted = old_password.replace('"', '""')
        try:
            cursor.execute(
                f'ALTER USER {username} IDENTIFIED BY "{quoted}" REPLACE "{old_quoted}"'
            )
        except seerdb.DatabaseError as exc:
            raise _relay_error(exc) from exc
        self._credentials[username.upper()] = new_password

    # The client's attribute names for the end-to-end tracing slots the Mirror
    # hands over; client_info is spelled clientinfo on the connection.
    _END_TO_END_ATTR = {'client_info': 'clientinfo'}

    def set_end_to_end(self, attrs: dict[str, str | None]) -> None:
        # Apply the session's end-to-end tracing attributes (module, action,
        # client_identifier, client_info, dbop) to the upstream connection, so
        # SYS_CONTEXT('USERENV', …) on the real Oracle reflects what the client
        # set through the Mirror. An upstream below 12.1 has no way to carry them
        # (the client raises NotSupportedError); that is a limit of the upstream,
        # not a Mirror failure, so it is ignored.
        assert self._conn is not None  # authenticate() ran before any call
        for name, value in attrs.items():
            try:
                setattr(self._conn, self._END_TO_END_ATTR.get(name, name), value)
            except seerdb.NotSupportedError:
                return

    def commit(self) -> None:
        if self._conn is not None:
            self._conn.commit()

    def rollback(self) -> None:
        if self._conn is not None:
            self._conn.rollback()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None


# Oracle's own error text already begins with "ORA-NNNNN: "; the Mirror
# (BackendError) re-adds that prefix from the code, so relaying str(exc) verbatim
# doubles it ("ORA-00904: ORA-00904: ..."). Strip the leading prefix and take the
# code from it (falling back to exc.code, then ORA-00900) so the Mirror emits
# exactly one, matching a real server.
_ORA_PREFIX = re.compile(r'^ORA-(\d{5}):\s*')


def _relay_error(exc: 'seerdb.DatabaseError') -> BackendError:
    text = str(exc)
    match = _ORA_PREFIX.match(text)
    code = getattr(exc, 'code', None)
    if code is None and match is not None:
        code = int(match.group(1))
    if match is not None:
        text = text[match.end() :]
    # Relay the parse offset (oracledb's DatabaseError.offset) so the Mirror draws
    # the error caret under the same column the real server flagged.
    return BackendError(
        text, ora_code=code or 900, error_offset=getattr(exc, 'offset', None)
    )


def _enrich_ref_columns(columns: list, rows: list) -> list:
    # A REF column's type identity (type_name / schema / OID) is not in the
    # PEP-249 description — only in the DbRef values — so copy it from the first
    # non-null value into the ColumnMeta the describe carries (#494).
    out = list(columns)
    for idx, col in enumerate(out):
        if col.data_type != TNS_TYPE_REF:
            continue
        for row in rows:
            ref = row[idx]
            if ref is not None and hasattr(ref, 'type_name'):
                out[idx] = replace(
                    col,
                    type_name=(ref.type_name or '').encode('ascii'),
                    type_schema=(ref.type_schema or '').encode('ascii'),
                    type_oid=getattr(ref, 'type_oid', b'') or b'',
                )
                break
    return out


def _lookup_bind_lob(lob_contents: dict, locator: bytes) -> tuple[object, bool] | None:
    # The content the Mirror served under an object-bind LOB attribute's locator.
    # A temp LOB's locator rides in the image behind a ub2 length prefix (the
    # server hands temp locators out ub2-prefixed, and the client echoes that
    # into the image), while a fetched column LOB's is bare -- so try the locator
    # as-is, then with a leading ub2 length prefix stripped (#888).
    entry = lob_contents.get(locator)
    if entry is not None:
        return entry
    if len(locator) >= 2 and struct.unpack('>H', locator[:2])[0] == len(locator) - 2:
        return lob_contents.get(locator[2:])
    return None


def _out_value(value: object) -> object:
    # A REF CURSOR OUT param resolves to a nested cursor; drain its describe +
    # rows into a CursorResult the Mirror can park and hand back. Any other OUT
    # value is a plain scalar the Mirror encodes by the bind's declared type.
    if hasattr(value, 'description') and hasattr(value, 'fetchall'):
        columns = [_to_column_meta(desc) for desc in value.description]
        return CursorResult(columns=columns, rows=value.fetchall())
    return value


def _to_column_meta(desc: tuple) -> ColumnMeta:
    # PEP-249 description tuple: (name, type_code, display_size, internal_size,
    # precision, scale, null_ok). type_code is a seerdb DB_TYPE carrying the raw
    # wire tns_type; the sizes give the declared/buffer length.
    name, type_code, display_size, internal_size, precision, scale, null_ok = desc
    tns_type = getattr(type_code, 'tns_type', type_code)
    csfrm = getattr(type_code, 'csfrm', 1)
    # A native VECTOR column's element format (FetchInfo.vector_format, #55) so the
    # Mirror re-encodes the value image with the right element type; None when the
    # upstream describe does not report it (falls back to FLOAT32).
    vector_format = getattr(desc, 'vector_format', None)
    vector_dimensions = getattr(desc, 'vector_dimensions', None)
    # An object (ADT) column carries its type identity in the describe (unlike a
    # REF, whose identity is enriched from values below); re-emit it so the
    # external client can resolve the object type (#888). FetchInfo exposes it.
    type_oid = type_schema = type_name = b''
    if int(tns_type) == TNS_TYPE_ADT:
        type_oid = getattr(desc, 'type_oid', None) or b''
        type_schema = (getattr(desc, 'type_schema', None) or '').encode('ascii')
        type_name = (getattr(desc, 'type_name', None) or '').encode('ascii')
        # DB_TYPE_OBJECT and DB_TYPE_XMLTYPE share one wire type number (ADT);
        # the external client tells them apart by the character-set form, mapping
        # csfrm 0 to a generic object and csfrm 1 (implicit) to XMLType (its later
        # SYS.XMLTYPE name check only tags the type, it never undoes that dbtype).
        # A real server describes an object column with csfrm 0 and charset 0, so
        # emit those here -- the FetchInfo's bare wire type carries no csfrm, and
        # the default (1) would surface every object as XMLType (#888).
        csfrm = 0
    byte_size = internal_size or display_size or 0
    if csfrm == 2:
        # National char (NCHAR / NVARCHAR2): UTF-16BE in AL16UTF16. data_length is
        # the byte buffer (internal_size), max_size the declared character length.
        data_length, max_size = byte_size, (display_size or byte_size)
        charset = AL16UTF16_CHARSET
    elif int(tns_type) == TNS_TYPE_ADT:
        data_length = max_size = byte_size
        charset = 0
    else:
        data_length = max_size = byte_size
        charset = ColumnMeta.charset
    return ColumnMeta(
        name=name.encode('utf-8'),
        data_type=int(tns_type),
        data_length=data_length,
        max_size=max_size,
        precision=precision or 0,
        scale=scale or 0,
        charset=charset,
        csfrm=csfrm,
        null_ok=int(bool(null_ok)),
        vector_format=vector_format,
        vector_dimensions=vector_dimensions,
        type_oid=type_oid,
        type_schema=type_schema,
        type_name=type_name,
    )
