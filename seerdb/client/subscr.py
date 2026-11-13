# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Continuous query notification and AQ notification, client-initiated (#2460).

As in python-oracledb 4.0's thin mode: ``Connection.subscribe()`` registers a
subscription on the session (TTI_KPN, function 125), and a second connection,
made with ``(SERVER=emon)``, sends NOTIFY (function 187) with the client id the
registration gave. The server then streams each notification down that
connection, read here on a daemon thread that calls the subscription's callback
with a :class:`Message`. ``Connection.unsubscribe()`` unregisters it and closes
the second connection. Only client-initiated subscriptions exist in thin mode:
``client_initiated=False`` is refused, as python-oracledb refuses it.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from seerdb.common.exceptions import (
    DatabaseError,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
    Truncated,
)

if TYPE_CHECKING:
    from seerdb.client.connection import OracleConnect

# The constants python-oracledb names, with its values.
EVENT_NONE = 0
EVENT_STARTUP = 1
EVENT_SHUTDOWN = 2
EVENT_SHUTDOWN_ANY = 3
EVENT_DEREG = 5
EVENT_OBJCHANGE = 6
EVENT_QUERYCHANGE = 7
EVENT_AQ = 100
OPCODE_ALLOPS = 0
OPCODE_ALLROWS = 0x01
OPCODE_INSERT = 0x02
OPCODE_UPDATE = 0x04
OPCODE_DELETE = 0x08
OPCODE_ALTER = 0x10
OPCODE_DROP = 0x20
SUBSCR_NAMESPACE_AQ = 1
SUBSCR_NAMESPACE_DBCHANGE = 2
SUBSCR_PROTO_CALLBACK = 0
SUBSCR_PROTO_MAIL = 1
SUBSCR_PROTO_SERVER = 2
SUBSCR_PROTO_HTTP = 3
SUBSCR_QOS_DEFAULT = 0
SUBSCR_QOS_RELIABLE = 0x01
SUBSCR_QOS_DEREG_NFY = 0x02
SUBSCR_QOS_ROWIDS = 0x04
SUBSCR_QOS_QUERY = 0x08
SUBSCR_QOS_BEST_EFFORT = 0x10
SUBSCR_GROUPING_CLASS_NONE = 0
SUBSCR_GROUPING_CLASS_TIME = 1
SUBSCR_GROUPING_TYPE_SUMMARY = 1
SUBSCR_GROUPING_TYPE_LAST = 2


class MessageRow:
    """A row a database-change notification names: its ROWID and what was
    done to it."""

    def __init__(self, operation: int, rowid: str) -> None:
        self.operation = operation
        self.rowid = rowid


class MessageTable:
    """A table a database-change notification names, with its rows unless
    the operation says all of them changed (OPCODE_ALLROWS)."""

    def __init__(self, operation: int, name: str, rows: list[MessageRow]) -> None:
        self.operation = operation
        self.name = name
        self.rows = rows


class MessageQuery:
    """A registered query a query-change notification names, with its
    tables."""

    def __init__(self, id: int, operation: int, tables: list[MessageTable]) -> None:
        self.id = id
        self.operation = operation
        self.tables = tables


class Message:
    """One notification, as the subscription's callback receives it."""

    def __init__(self, subscription: Subscription) -> None:
        self.subscription = subscription
        self.type = EVENT_NONE
        self.dbname: str | None = None
        self.tables: list[MessageTable] = []
        self.queries: list[MessageQuery] = []
        self.queue_name: str | None = None
        self.consumer_name: str | None = None
        self.msgid: bytes | None = None
        self.registered = False
        self.txid: bytes | None = None

    # python-oracledb's camel-case aliases.
    @property
    def queueName(self) -> str | None:  # noqa: N802 - python-oracledb's name
        return self.queue_name

    @property
    def consumerName(self) -> str | None:  # noqa: N802 - python-oracledb's name
        return self.consumer_name


def _tables(found: list[dict]) -> list[MessageTable]:
    return [
        MessageTable(
            t['operation'],
            t['name'],
            [MessageRow(r['operation'], r['rowid']) for r in t['rows']],
        )
        for t in found
    ]


class Subscription:
    """A client-initiated subscription (#2460), made by
    ``Connection.subscribe()``."""

    def __init__(
        self,
        connection: OracleConnect,
        namespace: int,
        protocol: int,
        callback: Callable | None,
        timeout: int,
        operations: int,
        port: int,
        qos: int,
        ip_address: str | None,
        grouping_class: int,
        grouping_value: int,
        grouping_type: int,
        name: str | None,
    ) -> None:
        self.connection = connection
        self.namespace = namespace
        self.protocol = protocol
        self.callback = callback
        self.timeout = timeout
        self.operations = operations
        self.port = port
        self.qos = qos
        self.ip_address = ip_address
        self.grouping_class = grouping_class
        self.grouping_value = grouping_value
        self.grouping_type = grouping_type
        self.name = name
        self.id = 0
        self._client_id = b''
        self._emon: OracleConnect | None = None
        self._thread: threading.Thread | None = None
        self._closing = False
        self.error: BaseException | None = None

    # python-oracledb's camel-case alias.
    @property
    def ipAddress(self) -> str | None:  # noqa: N802 - python-oracledb's name
        return self.ip_address

    def __repr__(self) -> str:
        return f'<seerdb.Subscription on {self.connection!r}>'

    # --- the wire -------------------------------------------------------

    def _wire_qos_and_flags(self) -> tuple[int, int]:
        # The QOS and flags the call carries, as python-oracledb computes them:
        # always secure, reliable and purge-on-notify when asked; the flags are
        # the operations, with the query and ROWID bits from the QOS.
        from seerdb.common.tns_consts import (
            TNS_SUBSCR_FLAGS_INCLUDE_ROWIDS,
            TNS_SUBSCR_FLAGS_QUERY,
            TNS_SUBSCR_QOS_PURGE_ON_NTFN,
            TNS_SUBSCR_QOS_RELIABLE,
            TNS_SUBSCR_QOS_SECURE,
        )

        Qos = TNS_SUBSCR_QOS_SECURE
        if self.qos & SUBSCR_QOS_RELIABLE:
            Qos |= TNS_SUBSCR_QOS_RELIABLE
        if self.qos & SUBSCR_QOS_DEREG_NFY:
            Qos |= TNS_SUBSCR_QOS_PURGE_ON_NTFN
        Flags = self.operations
        if self.qos & SUBSCR_QOS_QUERY:
            Flags |= TNS_SUBSCR_FLAGS_QUERY
        if self.qos & SUBSCR_QOS_ROWIDS:
            Flags |= TNS_SUBSCR_FLAGS_INCLUDE_ROWIDS
        return (Qos, Flags)

    def _call(self, operation: int) -> tuple[int, bytes]:
        # The TTI_KPN call on the session, and its reply's registration id and
        # client id.
        from seerdb.common.tns import decode_subscribe_reply, encode_subscribe

        Conn = self.connection
        (Qos, Flags) = self._wire_qos_and_flags()
        Register = operation == 1
        Data = encode_subscribe(
            Conn._next_seq(),
            Conn.field_version,
            operation,
            Conn.user.encode('utf-8') if Conn.user else None,
            None if Register else self._client_id,
            self.namespace,
            self.name.encode('utf-8') if self.name is not None else None,
            Qos,
            self.timeout,
            Flags,
            self.grouping_class,
            self.grouping_value,
            self.grouping_type,
            0 if Register else self.id,
        )
        Packet = Conn._function_call(Data)
        (Registration, ClientId, _) = Conn._function_reply(
            Packet, decode_subscribe_reply
        )
        return (Registration, ClientId)

    def _start(self) -> None:
        # Register, then open the second connection and start reading it.
        from seerdb.common.tns_consts import TNS_SUBSCR_OP_REGISTER

        if self.namespace == SUBSCR_NAMESPACE_AQ and not self.qos:
            # As python-oracledb: an AQ subscription's QOS is the secure flag,
            # whose bit is also SUBSCR_QOS_QUERY's.
            self.qos = 0x08
        (self.id, self._client_id) = self._call(TNS_SUBSCR_OP_REGISTER)
        Ready = threading.Event()
        self._thread = threading.Thread(
            target=self._listen, args=(Ready,), daemon=True, name='seerdb-subscr'
        )
        self._thread.start()
        Ready.wait()
        if self.error is not None:
            raise DatabaseError(
                f'the subscription failed: {self.error}'
            ) from self.error

    def _listen(self, Ready: threading.Event) -> None:
        # The second connection: (SERVER=emon), NOTIFY with the client id, then
        # the notifications as they come, until the STOP record, the end of
        # the registration, or unsubscribe() closing the socket.
        from seerdb.common.tns import encode_notify
        from seerdb.common.tns_consts import TNS_DATA

        try:
            Emon = self.connection._emon_connection()
            self._emon = Emon
            Emon.send(
                TNS_DATA,
                encode_notify(Emon._next_seq(), Emon.field_version, self._client_id),
            )
        except BaseException as Exc:  # noqa: BLE001 - reported to subscribe()
            self.error = Exc
            Ready.set()
            return
        Ready.set()
        try:
            self._read(Emon)
        except BaseException as Exc:  # noqa: BLE001 - only a failure is kept
            if not self._closing:
                self.error = Exc
        finally:
            self._emon = None
            try:
                Emon.disconnect()
            except Exception:  # noqa: BLE001 - the socket may be gone already
                pass  # closing a dead connection: nothing left to release

    def _read(self, Emon: OracleConnect) -> None:
        # Reads the stream: TNS DATA packets, their bodies joined, the leading
        # OAC token, then a record per notification.
        from seerdb.client.aq import MessageProperties
        from seerdb.client.connection import _parse_aq_msg_props
        from seerdb.common.tns import (
            assemble_packet,
            decode_error_reply,
            decode_notification,
        )
        from seerdb.common.tns_consts import TNS_DATA, TTI_OAC, TTI_OER

        FV = Emon.field_version

        def skip(Rest: bytes) -> bytes:
            return _parse_aq_msg_props(Rest, MessageProperties(), FV)

        (Raw, Stream, Started) = (b'', b'', False)
        Sock = Emon._sock
        while True:
            Chunk = Sock.recv(65536)
            if not Chunk:
                return  # the server closed it
            Raw += Chunk
            while len(Raw) >= 8:
                (Whole, Type, Body, Rest) = assemble_packet(
                    Raw, Emon.sdu, Emon._large_packets
                )
                if Body is None or Rest is None:
                    break  # the packet is not whole yet
                Raw = Rest
                if Type != TNS_DATA:
                    continue
                if Emon._ano is not None and Emon._ano.active:
                    Body = Emon._ano.unwrap(Body)
                Stream += Body
            if not Started:
                if not Stream:
                    continue
                if Stream[0] == TTI_OER:
                    (Code, Message) = decode_error_reply(Stream)
                    raise DatabaseError(Message or f'ORA-{Code:05d}', code=Code)
                if Stream[0] != TTI_OAC:
                    raise InterfaceError(
                        f'unexpected notification stream 0x{Stream[:1].hex()}'
                    )
                (Stream, Started) = (Stream[1:], True)
            while Stream:
                try:
                    (Record, After) = decode_notification(Stream, self.namespace, skip)
                except (Truncated, IndexError, ValueError, struct.error):
                    break  # the record is not whole yet
                Stream = After
                if Record is None:
                    return  # STOP: no more notifications
                if not self._deliver(Record, Emon):
                    return

    def _deliver(self, Record: dict, Emon: OracleConnect) -> bool:
        # One record as a Message to the callback; False once the registration
        # is gone and nothing more will come.
        from seerdb.common.tns import decode_cqn_payload

        Msg = Message(self)
        Msg.dbname = Emon.db_unique_name
        Msg.queue_name = Record['queue_name']
        Msg.consumer_name = Record['consumer_name']
        Msg.msgid = Record['msgid']
        Going = True
        if self.namespace == SUBSCR_NAMESPACE_AQ:
            Msg.type = EVENT_AQ
        elif Record['payload'] is None:
            Msg.type = EVENT_DEREG
            Going = False
        else:
            Msg.registered = not self.qos & SUBSCR_QOS_DEREG_NFY
            Going = Msg.registered
            Found = decode_cqn_payload(Record['payload'])
            Msg.type = Found['type']
            Msg.dbname = Found['dbname']
            Msg.tables = _tables(Found['tables'])
            Msg.queries = [
                MessageQuery(q['id'], q['operation'], _tables(q['tables']))
                for q in Found['queries']
            ]
        if self.callback is not None:
            self.callback(Msg)
        return Going

    # --- the API --------------------------------------------------------

    def registerquery(self, statement: str, args: Any = None) -> int | None:
        """Register the query for notification when the tables it reads
        change, as Cursor.execute() runs it; only a query is taken. With
        SUBSCR_QOS_QUERY, the id the server gave it is returned, else None."""
        from seerdb.common.tns import _DECODE_QUERY_IDS

        if self.namespace != SUBSCR_NAMESPACE_DBCHANGE:
            raise ProgrammingError(
                'only a database-change subscription registers queries'
            )
        if args is not None and not isinstance(args, (list, tuple, dict)):
            raise ProgrammingError('registerquery args must be a sequence or a dict')
        # Only a query registers; anything else with the registration in its
        # execute draws ORA-03137 from the server, so it is refused here, as
        # python-oracledb refuses it.
        from seerdb.common.sqltext import statement_head

        if not statement_head(statement).startswith(('SELECT', 'WITH')):
            raise ProgrammingError('registerquery takes a query')
        Conn = self.connection
        Cursor = Conn.cursor()
        Ids: list[int] = []
        Token = _DECODE_QUERY_IDS.set(Ids)
        Conn._registration_id = self.id
        try:
            Cursor.execute(statement, args or [])
        finally:
            Conn._registration_id = 0
            _DECODE_QUERY_IDS.reset(Token)
            Cursor.close()
        if self.qos & SUBSCR_QOS_QUERY and Ids:
            return Ids[-1]
        return None

    def _close(self) -> None:
        # Unregister on the session, then close the second connection, which
        # ends the reading thread.
        from seerdb.common.tns_consts import TNS_SUBSCR_OP_UNREGISTER

        self._closing = True
        try:
            self._call(TNS_SUBSCR_OP_UNREGISTER)
        finally:
            Emon = self._emon
            if Emon is not None and Emon.sock is not None:
                try:
                    Emon.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # already closed by the server
            if self._thread is not None:
                self._thread.join(timeout=10)


def subscription_arguments(
    client_initiated: bool, protocol: int, **kwargs: Any
) -> dict[str, Any]:
    """The checks subscribe() makes before anything is sent (#2460)."""
    if not client_initiated:
        raise NotSupportedError(
            'only a client-initiated subscription exists in thin mode: pass '
            'client_initiated=True, as python-oracledb thin requires'
        )
    if protocol != SUBSCR_PROTO_CALLBACK:
        raise NotSupportedError('a subscription notifies through its callback only')
    return {'protocol': protocol, **kwargs}
