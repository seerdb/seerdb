# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The instance_name and expire_time connect parameters (#2456).

Where each is read from (a keyword argument, Easy Connect, a connect
descriptor) and where it lands in the CONNECT's descriptor, in the places
python-oracledb 26.1 puts them, measured with its ConnectParams.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from seerdb.client.connection import OracleConnect
from seerdb.client.dsn import parse_dsn
from seerdb.common.exceptions import ProgrammingError
from seerdb.common.tns import encode_dictionary_description

_ADDR = '(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1523))'


@pytest.mark.parametrize(
    ('dsn', 'service', 'server_type', 'instance'),
    [
        ('db:1523/FREEPDB1/FREE', 'FREEPDB1', None, 'FREE'),
        ('db:1523/FREEPDB1:pooled/FREE', 'FREEPDB1', 'pooled', 'FREE'),
        ('db/FREEPDB1/FREE', 'FREEPDB1', None, 'FREE'),
        ('db:1523/FREEPDB1', 'FREEPDB1', None, ''),
    ],
)
def test_easy_connect_names_the_instance_last(
    dsn: str, service: str, server_type: str | None, instance: str
) -> None:
    found = parse_dsn(dsn)
    assert (found.service_name, found.server_type, found.instance_name) == (
        service,
        server_type,
        instance,
    )


@pytest.mark.parametrize('dsn', ['db/FREEPDB1/', 'db/FREEPDB1/FREE/more'])
def test_a_malformed_instance_segment_is_refused(dsn: str) -> None:
    with pytest.raises(ProgrammingError):
        parse_dsn(dsn)


def test_easy_connect_takes_expire_time() -> None:
    found = parse_dsn('db:1523/FREEPDB1?expire_time=3')
    assert found.parameters == {'expire_time': '3'}


def test_a_descriptor_names_both() -> None:
    found = parse_dsn(
        f'(DESCRIPTION=(EXPIRE_TIME=2){_ADDR}'
        '(CONNECT_DATA=(SERVICE_NAME=S)(INSTANCE_NAME=I)))'
    )
    assert (found.instance_name, found.expire_time) == ('I', 2)


def test_a_descriptor_with_a_bad_expire_time_is_refused() -> None:
    with pytest.raises(ProgrammingError):
        parse_dsn(f'(DESCRIPTION=(EXPIRE_TIME=soon){_ADDR})')


def _connection(**kwargs: Any) -> OracleConnect:
    # A connection object, never connected: the arguments as it keeps them.
    return OracleConnect(host='db', port=1523, service_name='FREEPDB1', **kwargs)


@pytest.mark.parametrize(
    ('kwargs', 'instance', 'expire'),
    [
        ({'instance_name': 'FREE'}, 'FREE', 0),
        ({'expire_time': 5}, '', 5),
        ({'dsn': 'db:1523/FREEPDB1/FREE?expire_time=3'}, 'FREE', 3),
        (
            {
                'dsn': f'(DESCRIPTION=(EXPIRE_TIME=2){_ADDR}'
                '(CONNECT_DATA=(SERVICE_NAME=S)(INSTANCE_NAME=I)))'
            },
            'I',
            2,
        ),
    ],
)
def test_the_connection_keeps_them(kwargs: dict, instance: str, expire: int) -> None:
    conn = _connection(**kwargs)
    assert (conn._instance_name_requested, conn.expire_time) == (instance, expire)


def _description(**env: object) -> bytes:
    base = {'host': 'h', 'port': 1521, 'user': 'u', 'service_name': 'svc'}
    base.update(env)
    return encode_dictionary_description({'env': base})


def test_the_descriptor_carries_them_where_python_oracledb_does() -> None:
    # (EXPIRE_TIME=n) opens the DESCRIPTION; (INSTANCE_NAME=...) follows the
    # service and comes before (SERVER=...).
    text = _description(instance_name='FREE', expire_time=3, server_type='pooled')
    assert text.startswith(b'(DESCRIPTION=(EXPIRE_TIME=3)(CONNECT_DATA=')
    assert b'(SERVICE_NAME=svc)(INSTANCE_NAME=FREE)(SERVER=pooled)' in text


def test_the_descriptor_leaves_them_out_by_default() -> None:
    text = _description()
    assert b'EXPIRE_TIME' not in text and b'INSTANCE_NAME' not in text


class _Socket:
    def __init__(self) -> None:
        self.options: dict[tuple[int, int], int] = {}

    def setsockopt(self, level: int, name: int, value: int) -> None:
        self.options[(level, name)] = value


def test_expire_time_turns_tcp_keepalive_on() -> None:
    sock = _Socket()
    _connection(expire_time=2)._apply_keepalive(sock)  # type: ignore[arg-type]
    assert sock.options[(socket.SOL_SOCKET, socket.SO_KEEPALIVE)] == 1
    idle = getattr(socket, 'TCP_KEEPIDLE', None) or getattr(socket, 'TCP_KEEPALIVE')
    assert sock.options[(socket.IPPROTO_TCP, idle)] == 120


def test_no_expire_time_leaves_the_socket_alone() -> None:
    sock = _Socket()
    _connection()._apply_keepalive(sock)  # type: ignore[arg-type]
    assert sock.options == {}
