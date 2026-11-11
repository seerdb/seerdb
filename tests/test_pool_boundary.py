# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The pool_boundary connect parameter, DRCP implicit pooling (#2542).

Where it is read from (a keyword argument, Easy Connect, a connect descriptor)
and where it lands in the CONNECT's descriptor: after (SERVER=...), where
python-oracledb 26.1 writes it, measured with its ConnectParams. The server
does the pooling, so nothing else in the client changes.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from seerdb.client.connection import OracleConnect
from seerdb.client.dsn import ConnectArguments, parse_dsn, resolve_dsn_arguments
from seerdb.client.netconfig import pool_boundary_value
from seerdb.common.exceptions import ProgrammingError
from seerdb.common.tns import encode_dictionary_description

_ADDR = '(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1523))'


@pytest.mark.parametrize(
    ('given', 'written'),
    [
        ('statement', 'statement'),
        ('transaction', 'transaction'),
        # The server takes either word in any case (measured on 23ai).
        ('TRANSACTION', 'transaction'),
        (' Statement ', 'statement'),
        (None, None),
    ],
)
def test_a_boundary_is_written_lower_cased(given: str | None, written: str | None):
    assert pool_boundary_value(given) == written


@pytest.mark.parametrize('given', ['bogus', '', 'request'])
def test_any_other_value_is_refused(given: str) -> None:
    # 23ai refuses it on a pooled connection with ORA-24545; seerdb says so
    # before connecting, as it does for server_type.
    with pytest.raises(ProgrammingError, match='pool_boundary'):
        pool_boundary_value(given)


def test_a_descriptor_names_it() -> None:
    found = parse_dsn(
        f'(DESCRIPTION={_ADDR}'
        '(CONNECT_DATA=(SERVICE_NAME=S)(SERVER=pooled)(POOL_BOUNDARY=Transaction)))'
    )
    assert (found.server_type, found.pool_boundary) == ('pooled', 'transaction')


def test_a_descriptor_with_a_bad_boundary_is_refused() -> None:
    with pytest.raises(ProgrammingError, match='pool_boundary'):
        parse_dsn(f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(POOL_BOUNDARY=bogus)))')


def test_every_address_of_a_descriptor_keeps_it() -> None:
    found = parse_dsn(
        '(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(HOST=a))(ADDRESS=(HOST=b)))'
        '(CONNECT_DATA=(SERVICE_NAME=S)(POOL_BOUNDARY=statement)))'
    )
    assert found.route is not None
    assert [a.pool_boundary for a in found.route.addresses] == ['statement'] * 2


def _connection(**kwargs: Any) -> OracleConnect:
    # A connection object, never connected: the arguments as it keeps them.
    return OracleConnect(host='db', port=1523, service_name='FREEPDB1', **kwargs)


@pytest.mark.parametrize(
    ('kwargs', 'boundary'),
    [
        ({}, None),
        ({'pool_boundary': 'Statement'}, 'statement'),
        ({'dsn': 'db:1523/FREEPDB1:pooled?pool_boundary=transaction'}, 'transaction'),
        # What the DSN names wins over the argument beside it.
        (
            {
                'dsn': 'db:1523/FREEPDB1?pool_boundary=transaction',
                'pool_boundary': 'statement',
            },
            'transaction',
        ),
        (
            {
                'dsn': f'(DESCRIPTION={_ADDR}'
                '(CONNECT_DATA=(SERVICE_NAME=S)(POOL_BOUNDARY=statement)))'
            },
            'statement',
        ),
    ],
)
def test_the_connection_keeps_it(kwargs: dict, boundary: str | None) -> None:
    assert _connection(**kwargs).pool_boundary == boundary


def test_a_bad_argument_is_refused_before_connecting() -> None:
    with pytest.raises(ProgrammingError, match='pool_boundary'):
        _connection(pool_boundary='bogus')


def test_a_bad_easy_connect_value_is_refused() -> None:
    with pytest.raises(ProgrammingError, match='pool_boundary'):
        _connection(dsn='db:1523/FREEPDB1?pool_boundary=bogus')


def test_retries_keep_it_on_the_address() -> None:
    # Easy Connect's retry_count builds a route of its one address (#1983).
    conn = _connection(dsn='db/S?pool_boundary=statement&retry_count=2')
    assert conn._route is not None
    assert conn._route.addresses[0].pool_boundary == 'statement'


def test_the_async_connection_keeps_it() -> None:
    from seerdb.client.aconnection import AsyncOracleConnect

    conn = AsyncOracleConnect(
        host='db', port=1523, service_name='S', pool_boundary='TRANSACTION'
    )
    assert conn.pool_boundary == 'transaction'


def _description(**env: object) -> bytes:
    base = {'host': 'h', 'port': 1521, 'user': 'u', 'service_name': 'svc'}
    base.update(env)
    return encode_dictionary_description({'env': base})


def test_the_descriptor_carries_it_after_the_server_type() -> None:
    # Where python-oracledb writes it: (SERVER=...), then (POOL_BOUNDARY=...).
    text = _description(server_type='pooled', pool_boundary='statement')
    assert b'(SERVICE_NAME=svc)(SERVER=pooled)(POOL_BOUNDARY=statement)(CID=' in text


def test_it_goes_in_whatever_the_server_type() -> None:
    # As in python-oracledb; a dedicated server ignores it.
    text = _description(pool_boundary='transaction')
    assert b'(SERVICE_NAME=svc)(POOL_BOUNDARY=transaction)(CID=' in text


def test_the_descriptor_leaves_it_out_by_default() -> None:
    assert b'POOL_BOUNDARY' not in _description(server_type='pooled')


def test_resolving_a_dsn_keeps_an_argument_it_does_not_name() -> None:
    given = ConnectArguments(
        'h', 1521, 's', '', 'u', 'p', None, None, 0, None, 0, 0, None, None, 0
    )
    given = replace(given, pool_boundary='statement')
    assert resolve_dsn_arguments('db/S', given).pool_boundary == 'statement'
