# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Advanced Queuing (#128): enqueue / dequeue messages to/from Oracle AQ queues.
#
# A Queue is obtained from connection.queue(name[, payload_type]); its payload
# is RAW (bytes, the default), a SQL object (when payload_type is a DbObjectType
# from connection.gettype()), or JSON (payload_type=seerdb.JSON). Messages are
# carried by MessageProperties (connection.msgproperties(payload=...)); enqueue/
# dequeue behaviour is tuned via the queue's enqoptions / deqoptions. The wire
# framing is in seerdb.common.tns (encode_aq_enq / encode_aq_deq / encode_aq_array);
# the connection's _aq_* methods send and parse.

from seerdb.common.tns_consts import (
    TNS_AQ_DEQ_NEXT_MSG,
    TNS_AQ_DEQ_ON_COMMIT,
    TNS_AQ_DEQ_REMOVE,
    TNS_AQ_DEQ_WAIT_FOREVER,
    TNS_AQ_ENQ_ON_COMMIT,
    TNS_AQ_MSG_PERSISTENT,
)


class EnqOptions:
    """Enqueue options for a Queue (#128)."""

    def __init__(self):
        self.visibility = TNS_AQ_ENQ_ON_COMMIT
        self.delivery_mode = TNS_AQ_MSG_PERSISTENT


class DeqOptions:
    """Dequeue options for a Queue (#128)."""

    def __init__(self):
        self.consumer_name = None
        self.mode = TNS_AQ_DEQ_REMOVE
        self.navigation = TNS_AQ_DEQ_NEXT_MSG
        self.visibility = TNS_AQ_DEQ_ON_COMMIT
        self.wait = TNS_AQ_DEQ_WAIT_FOREVER
        self.correlation = None
        self.condition = None
        self.msgid = None
        self.delivery_mode = TNS_AQ_MSG_PERSISTENT


class MessageProperties:
    """A queued message and its properties (#128).

    For enqueue, set ``payload`` (and optionally correlation / delay /
    expiration / priority). For dequeue, these plus msgid / num_attempts /
    enq_time / state are filled in from the server.
    """

    def __init__(
        self,
        payload=None,
        correlation=None,
        delay=0,
        expiration=-1,
        priority=0,
        exceptionq=None,
        recipients=None,
    ):
        self.payload = payload
        self.correlation = correlation
        self.delay = delay
        self.expiration = expiration
        self.priority = priority
        self.state = 0
        self.exceptionq = exceptionq
        self.recipients = recipients
        self.msgid = None
        self.num_attempts = 0
        self.enq_time = None
        self.enq_txn_id = None
        self.delivery_mode = TNS_AQ_MSG_PERSISTENT

    def __repr__(self):
        return (
            f'<MessageProperties payload={self.payload!r} '
            f'correlation={self.correlation!r} priority={self.priority}>'
        )


class _QueueBase:
    """Shared construction + validation for the sync and async AQ handles
    (#128). The wire methods live on the concrete Queue / AsyncQueue so the two
    do not share (and cannot clash over) sync-vs-coroutine signatures."""

    def __init__(self, connection, name, payload_type=None, is_json=False):
        self._connection = connection
        self.name = name
        # payload_type is a DbObjectType for object-payload queues; None for RAW
        # / JSON. is_json marks a JSON-payload queue. payload_toid is the 16-byte
        # type OID (object queues) or 16 zero bytes (RAW / JSON).
        self.payload_type = payload_type
        self.is_json = is_json
        # 16-byte payload type OID written raw on the wire: the type's OID for an
        # object queue, or the fixed RAW (0x17) / JSON (0x47) sentinel otherwise.
        if payload_type is not None:
            self.payload_toid = bytes(payload_type.oid)[:16].ljust(16, b'\x00')
        elif is_json:
            self.payload_toid = bytes(15) + bytes([0x47])
        else:
            self.payload_toid = bytes(15) + bytes([0x17])
        self.enqoptions = EnqOptions()
        self.deqoptions = DeqOptions()

    def _check_array_version(self):
        # Array enqueue and dequeue (AQ_ARRAY) are measured from 12.1 only: an
        # 11g RAW queue takes single messages (#2697).
        from seerdb.common.tns_consts import FIELD_VERSION_12_1

        if self._connection.field_version < FIELD_VERSION_12_1:
            from seerdb.common.exceptions import NotSupportedError

            raise NotSupportedError(
                'array enqueue/dequeue (enqmany/deqmany) requires an Oracle 12.1+ '
                'server; use enqone/deqone'
            )

    def _check_array_json(self):
        # Array enqueue/dequeue of JSON payloads is not supported: the server
        # errors (ORA-00600 from python-oracledb too) on these editions, so it's
        # gated rather than shipped broken. Single enqone/deqone JSON works.
        if self.is_json:
            from seerdb.common.exceptions import NotSupportedError

            raise NotSupportedError(
                'array enqueue/dequeue (enqmany/deqmany) is not supported for '
                'JSON-payload queues; use enqone/deqone'
            )


class Queue(_QueueBase):
    """An Oracle Advanced Queue handle (#128). Obtain via connection.queue()."""

    def enqone(self, message: MessageProperties) -> MessageProperties:
        """Enqueue a single message; returns it with its msgid filled in."""
        self._connection._aq_enq_one(self, message)
        return message

    def deqone(self) -> MessageProperties | None:
        """Dequeue a single message, or None if none is available."""
        return self._connection._aq_deq_one(self)

    def enqmany(self, messages: list) -> list:
        """Enqueue several messages (each a MessageProperties)."""
        self._check_array_version()
        self._check_array_json()
        self._connection._aq_enq_many(self, list(messages))
        return messages

    def deqmany(self, max_messages: int) -> list:
        """Dequeue up to ``max_messages`` messages (empty list if none)."""
        self._check_array_version()
        self._check_array_json()
        return self._connection._aq_deq_many(self, max_messages)


class AsyncQueue(_QueueBase):
    """Async Advanced Queue handle (#128). Obtain via AsyncConnection.queue()."""

    async def enqone(self, message: MessageProperties) -> MessageProperties:
        await self._connection._aq_enq_one(self, message)
        return message

    async def deqone(self) -> MessageProperties | None:
        return await self._connection._aq_deq_one(self)

    async def enqmany(self, messages: list) -> list:
        self._check_array_version()
        self._check_array_json()
        await self._connection._aq_enq_many(self, list(messages))
        return messages

    async def deqmany(self, max_messages: int) -> list:
        self._check_array_version()
        self._check_array_json()
        return await self._connection._aq_deq_many(self, max_messages)
