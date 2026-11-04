# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The ``dsn`` connect argument without a wallet: an Easy Connect string
(#1972) or a connect descriptor (#1976).

``connect(dsn='db.example.com:1521/FREEPDB1')`` is how most python-oracledb code
connects. Without a wallet seerdb used to drop the argument and dial
``localhost:1521``. This module reads the string the way python-oracledb does:

    [user[/password]@][//]host[:port][/service_name[:server_type][/instance_name]]

or a connect descriptor with one address,
``[user[/password]@](DESCRIPTION=(ADDRESS=...)(CONNECT_DATA=...))``
(:func:`seerdb.client.netconfig.parse_descriptor`).

The host may be a bracketed IPv6 address, the port defaults to 1521, and what
the string names wins over ``host`` / ``port`` / ``service_name`` passed beside
it, as it does in python-oracledb. A bare word is a tnsnames alias, read from
``config_dir``, ``TNS_ADMIN`` or ``$ORACLE_HOME/network/admin``
(:func:`seerdb.client.netconfig.resolve_alias`). A form seerdb does not read
yet -- ``?`` parameters, or a descriptor parameter seerdb does not act on --
raises NotSupportedError naming it, rather than being ignored. A ``tcps://``
prefix, or PROTOCOL=TCPS in a descriptor, turns TLS on, and a ``:server_type``
suffix or (SERVER=...) in CONNECT_DATA sets the server type (#1977). A third
segment or (INSTANCE_NAME=...) names the instance, and ``?expire_time=`` or
(EXPIRE_TIME=...) turns TCP keepalive on (#2456).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields, replace

from seerdb.client.netconfig import (
    Address,
    NetConfigError,
    Route,
    parse_descriptor,
    proxy_address,
    resolve_alias,
    server_type_value,
)
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.tns_consts import PURITY_DEFAULT, PURITY_NEW, PURITY_SELF

_DEFAULT_PORT = 1521


@dataclass(frozen=True)
class DsnTarget:
    """What a dsn names."""

    host: str
    port: int
    service_name: str
    user: str | None = None
    password: str | None = None
    sid: str = ''
    protocol: str = 'tcp'
    server_type: str | None = None
    parameters: dict[str, str] = field(default_factory=dict)
    route: Route | None = None
    https_proxy: str = ''
    https_proxy_port: int = 0
    instance_name: str = ''
    expire_time: int = 0


@dataclass(frozen=True)
class ConnectArguments:
    """The connect arguments a dsn can name, as passed and once it is applied."""

    host: str
    port: int
    service_name: str
    sid: str
    user: str
    password: str
    ssl: object
    server_type: str | None
    sdu: int
    cclass: str | None
    purity: int
    timeout: int
    route: Route | None
    https_proxy: str | None
    https_proxy_port: int
    # The transport the dsn named: 'tcp', 'tcps', or the seerdb WebSocket
    # extension 'ws' / 'wss' (#1988). Trailing with a default so a plain
    # ConnectArguments(...) positional build need not pass it.
    protocol: str = 'tcp'
    # The instance to reach (INSTANCE_NAME in CONNECT_DATA) and the minutes
    # between keepalive probes, 0 for none (#2456).
    instance_name: str = ''
    expire_time: int = 0

    def as_tuple(self) -> tuple:
        # In field order, for a constructor to unpack into its own arguments.
        return tuple(getattr(self, f.name) for f in fields(self))


def _parse_parameters(dsn: str, text: str) -> dict[str, str]:
    # Easy Connect `?` parameters: name=value pairs joined by '&', the names
    # case-insensitive, spaces around them free, a value optionally in double
    # quotes, and a repeated name taking its last value -- python-oracledb's
    # reading, measured (#1977).
    parameters: dict[str, str] = {}
    for item in text.split('&'):
        (name, equals, value) = item.partition('=')
        name = name.strip().lower()
        if not name or not equals:
            raise ProgrammingError(f'dsn {dsn!r}: {item.strip()!r} is not name=value')
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        parameters[name] = value
    return parameters


def parse_dsn(dsn: str, config_dir: str | None = None) -> DsnTarget:
    """Parse an Easy Connect string, a connect descriptor or a tnsnames alias
    (looked up from ``config_dir``, ``TNS_ADMIN`` or ``ORACLE_HOME``), each behind
    an optional ``user[/password]@``."""
    text = dsn.strip()
    user = password = None
    # The credentials end at the last '@' before any descriptor: a password can
    # hold an '@', the address cannot, and a descriptor's quoted values might.
    head = text[: text.find('(')] if '(' in text else text
    if '@' in head:
        credentials, _, _rest = head.rpartition('@')
        text = text[len(credentials) + 1 :]
        user, slash, secret = credentials.partition('/')
        password = secret if slash else None
        if not user:
            raise ProgrammingError(f'dsn {dsn!r} has an "@" but no user name before it')
    if text.startswith('('):
        found = parse_descriptor(text)
        return DsnTarget(
            found.host,
            found.port,
            found.service_name,
            user,
            password,
            found.sid,
            found.protocol,
            found.server_type,
            route=found.route,
            https_proxy=found.https_proxy,
            https_proxy_port=found.https_proxy_port,
            instance_name=found.instance_name,
            expire_time=found.expire_time,
        )
    protocol = 'tcp'
    scheme, separator, after = text.partition('://')
    if separator:
        protocol = scheme.lower()
        # ws / wss are the seerdb WebSocket transport extension (#1988). The
        # /segment after host:port stays the Oracle service name (Easy Connect),
        # so wss://host:port/FREEPDB1 names the same service tcps:// would; the
        # WebSocket resource path is '/'. See PROTOCOL.md 'Transports'.
        if protocol not in ('tcp', 'tcps', 'ws', 'wss'):
            raise ProgrammingError(
                f'dsn {dsn!r}: {scheme!r} is not tcp, tcps, ws or wss'
            )
        text = after
    (text, question, query) = text.partition('?')
    parameters = _parse_parameters(dsn, query) if question else {}
    easy = text.startswith('//')  # only Easy Connect opens with '//'
    text = text.removeprefix('//')
    if text.startswith('['):
        close = text.find(']')
        if close < 0:
            raise ProgrammingError(f'dsn {dsn!r}: an IPv6 address lacks its "]"')
        host, rest = text[1:close], text[close + 1 :]
    else:
        cut = min(
            (i for i in (text.find(':'), text.find('/')) if i >= 0), default=len(text)
        )
        host, rest = text[:cut], text[cut:]
    if not host:
        raise ProgrammingError(f'dsn {dsn!r} names no host')
    # A bare word is a tnsnames alias, as in python-oracledb, not a host name.
    if not (easy or rest or text.startswith('[')):
        found = resolve_alias(text, config_dir)
        return DsnTarget(
            found.host,
            found.port,
            found.service_name,
            user,
            password,
            found.sid,
            found.protocol,
            found.server_type,
            route=found.route,
            https_proxy=found.https_proxy,
            https_proxy_port=found.https_proxy_port,
            instance_name=found.instance_name,
            expire_time=found.expire_time,
        )
    port = _DEFAULT_PORT
    if rest.startswith(':'):
        digits, slash, after = rest[1:].partition('/')
        if not digits.isdigit():
            raise ProgrammingError(f'dsn {dsn!r}: the port is not a number')
        port = int(digits)
        rest = slash + after
    service_name = instance_name = ''
    server_type = None
    if rest.startswith('/'):
        # /service_name[:server_type][/instance_name], as python-oracledb
        # reads it (#2456).
        (service, slash, instance_name) = rest[1:].partition('/')
        if slash and (not instance_name or '/' in instance_name):
            raise ProgrammingError(
                f'dsn {dsn!r} is not [//]host[:port][/service_name[:server_type]'
                '[/instance_name]]'
            )
        (service_name, colon, kind) = service.partition(':')
        if colon:
            server_type = server_type_value(kind)
    elif rest:
        raise ProgrammingError(f'dsn {dsn!r} is not [//]host[:port][/service_name]')
    return DsnTarget(
        host,
        port,
        service_name,
        user,
        password,
        '',
        protocol,
        server_type,
        parameters,
        instance_name=instance_name,
    )


# The ? parameters with a seerdb argument, and how each value reads (#1977).
_PURITIES = {'default': PURITY_DEFAULT, 'new': PURITY_NEW, 'self': PURITY_SELF}
_NUMBER = re.compile(r'\d+(?:\.\d+)?')
_TIMEOUT_UNITS = {'': 1000, 'sec': 1000, 'ms': 1, 'min': 60000}
_TIMEOUT_VALUE = re.compile(r'(\d+(?:\.\d+)?)\s*(ms|sec|min)?', re.IGNORECASE)


def _timeout_ms(dsn: str, value: str) -> int:
    # transport_connect_timeout: seconds, or a number with ms / sec / min.
    match = _TIMEOUT_VALUE.fullmatch(value)
    if match is None:
        raise ProgrammingError(f'dsn {dsn!r}: transport_connect_timeout={value!r}')
    unit = _TIMEOUT_UNITS[(match.group(2) or '').lower()]
    return round(float(match.group(1)) * unit)


def _apply_parameters(
    dsn: str, parameters: dict[str, str], args: ConnectArguments
) -> ConnectArguments:
    unread = sorted(
        set(parameters)
        - {
            'sdu',
            'pool_connection_class',
            'pool_purity',
            'transport_connect_timeout',
            'retry_count',
            'retry_delay',
            'https_proxy',
            'https_proxy_port',
            'expire_time',
        }
    )
    if unread:
        raise NotSupportedError(
            f'dsn {dsn!r}: the ? parameter {", ".join(unread)} is not supported yet'
        )
    if 'sdu' in parameters:
        if not parameters['sdu'].isdigit():
            raise ProgrammingError(
                f'dsn {dsn!r}: sdu={parameters["sdu"]!r} is not a number'
            )
        args = replace(args, sdu=int(parameters['sdu']))
    if 'pool_connection_class' in parameters:
        args = replace(args, cclass=parameters['pool_connection_class'])
    if 'pool_purity' in parameters:
        purity = _PURITIES.get(parameters['pool_purity'].lower())
        if purity is None:
            raise ProgrammingError(
                f'dsn {dsn!r}: pool_purity={parameters["pool_purity"]!r}'
            )
        args = replace(args, purity=purity)
    if 'expire_time' in parameters:
        if not parameters['expire_time'].isdigit():
            raise ProgrammingError(
                f'dsn {dsn!r}: expire_time={parameters["expire_time"]!r} is not a number'
            )
        args = replace(args, expire_time=int(parameters['expire_time']))
    if 'transport_connect_timeout' in parameters:
        args = replace(
            args, timeout=_timeout_ms(dsn, parameters['transport_connect_timeout'])
        )
    if 'https_proxy' in parameters or 'https_proxy_port' in parameters:
        try:
            (proxy, proxy_port) = proxy_address(
                parameters.get('https_proxy'), parameters.get('https_proxy_port')
            )
        except NetConfigError as e:
            raise ProgrammingError(f'dsn {dsn!r}: {e}') from None
        args = replace(args, https_proxy=proxy, https_proxy_port=proxy_port)
    if 'retry_count' in parameters or 'retry_delay' in parameters:
        # Retries of the one address Easy Connect names (#1983).
        count = parameters.get('retry_count', '0')
        delay = parameters.get('retry_delay', '1')
        if not count.isdigit() or not _NUMBER.fullmatch(delay):
            raise ProgrammingError(
                f'dsn {dsn!r}: retry_count={count!r}, retry_delay={delay!r}'
            )
        # ws / wss (#1988) keep their own protocol; otherwise ssl picks TCPS.
        if args.protocol in ('ws', 'wss'):
            address_protocol = args.protocol
        else:
            address_protocol = 'tcps' if args.ssl else 'tcp'
        address = Address(
            args.host,
            args.port,
            address_protocol,
            args.service_name,
            args.sid,
            args.server_type,
            args.https_proxy or '',
            args.https_proxy_port,
            args.instance_name,
        )
        args = replace(
            args,
            route=Route((address,), retry_count=int(count), retry_delay=float(delay)),
        )
    return args


def resolve_dsn_arguments(
    dsn: str, args: ConnectArguments, config_dir: str | None = None
) -> ConnectArguments:
    """The connect arguments once ``dsn`` is applied: what the DSN names wins
    over the arguments passed beside it, and it supplies the credentials only
    when no ``user`` was passed. A TCPS address turns TLS on as ``ssl=True``
    does, and keeps an ``ssl=`` configuration passed beside it. Its ``?``
    parameters set ``sdu``, ``cclass``, ``purity`` and ``timeout``."""
    info = parse_dsn(dsn, config_dir)
    args = replace(
        args, host=info.host, port=info.port, route=info.route, protocol=info.protocol
    )
    if info.https_proxy:
        args = replace(
            args, https_proxy=info.https_proxy, https_proxy_port=info.https_proxy_port
        )
    if info.protocol == 'tcps' and not args.ssl:
        args = replace(args, ssl=True)
    # ws / wss (#1988) do TLS at the WebSocket layer, not the TNS layer, so they
    # leave args.ssl as given -- _open_transport branches on the protocol.
    if info.server_type is not None:
        args = replace(args, server_type=info.server_type)
    if info.instance_name:
        args = replace(args, instance_name=info.instance_name)
    if info.expire_time:
        args = replace(args, expire_time=info.expire_time)
    if info.service_name:
        args = replace(args, service_name=info.service_name, sid='')
    elif info.sid:
        args = replace(args, service_name='', sid=info.sid)
    if info.user is not None:
        if args.user:
            raise ProgrammingError(
                f'dsn {dsn!r} carries a user name, and user= was passed too'
            )
        args = replace(args, user=info.user)
        if info.password is not None:
            args = replace(args, password=info.password)
    return _apply_parameters(dsn, info.parameters, args)
