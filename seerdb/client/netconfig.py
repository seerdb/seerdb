# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Oracle Net configuration text: the descriptor grammar of ``tnsnames.ora`` and
``sqlnet.ora``, and a connect descriptor passed as ``dsn`` (#1976).

Pure functions over ``str``, with no third-party imports, so a descriptor can be
read without the ``wallet`` extra; :mod:`seerdb.client.wallet` builds on them.
"""

from __future__ import annotations

import os
import random
import re
from dataclasses import dataclass, replace
from typing import TypeAlias

from seerdb.common.exceptions import (
    NotSupportedError,
    OperationalError,
    ProgrammingError,
)

# A parsed descriptor node is either a leaf string or a *branch*: a list of
# ``(key, node)`` pairs. Keys are lower-cased; the list preserves order and
# duplicates (an ADDRESS_LIST may repeat ADDRESS), which a plain dict could not.
Node: TypeAlias = 'str | list[tuple[str, Node]]'


class NetConfigError(ProgrammingError):
    """Oracle Net configuration text could not be read."""


# --------------------------------------------------------------------------- #
# tnsnames.ora / sqlnet.ora descriptor grammar
# --------------------------------------------------------------------------- #
#
# Both files are the same nested S-expression-ish syntax Oracle Net uses
# everywhere::
#
#     alias = (DESCRIPTION = (ADDRESS = (PROTOCOL = tcps)(HOST = h)(PORT = 1522))
#                            (CONNECT_DATA = (SERVICE_NAME = svc)))
#
# A parameter is ``(NAME = VALUE)`` where VALUE is either a run of child
# parameters or a single atom (bareword or double-quoted string — the server
# certificate DN arrives quoted because it is full of spaces and commas).


def _tokenize(Text: str) -> list[tuple[str, str]]:
    """Split descriptor text into ``(kind, value)`` tokens.

    ``kind`` is one of ``lparen`` / ``rparen`` / ``eq`` / ``comma`` / ``atom``.
    ``#`` starts a comment to end-of-line; whitespace is insignificant.
    """
    Tokens: list[tuple[str, str]] = []
    i = 0
    N = len(Text)
    Punct = {'(': 'lparen', ')': 'rparen', '=': 'eq', ',': 'comma'}
    while i < N:
        Ch = Text[i]
        if Ch.isspace():
            i += 1
            continue
        if Ch == '#':
            # Comment: skip to (and including) the newline.
            End = Text.find('\n', i)
            i = N if End < 0 else End + 1
            continue
        if Ch in Punct:
            Tokens.append((Punct[Ch], Ch))
            i += 1
            continue
        if Ch == '"':
            End = Text.find('"', i + 1)
            if End < 0:
                raise NetConfigError('unterminated quoted string in descriptor')
            Tokens.append(('atom', Text[i + 1 : End]))
            i = End + 1
            continue
        # Bareword: everything up to whitespace or a structural character.
        Start = i
        while i < N and not Text[i].isspace() and Text[i] not in '()=,#"':
            i += 1
        Tokens.append(('atom', Text[Start:i]))
    return Tokens


def _parse_value(Tokens: list[tuple[str, str]], i: int) -> tuple[Node, int]:
    """Parse the VALUE that follows an ``=`` at ``Tokens[i]``.

    A value is either a sequence of child parameters (when it opens with
    ``(``) or a single atom. Returns ``(node, next_index)``.
    """
    if i < len(Tokens) and Tokens[i][0] == 'lparen':
        Children: list[tuple[str, Node]] = []
        while i < len(Tokens) and Tokens[i][0] == 'lparen':
            (Param, i) = _parse_param(Tokens, i)
            Children.append(Param)
        return (Children, i)
    if i < len(Tokens) and Tokens[i][0] == 'atom':
        return (Tokens[i][1], i + 1)
    raise NetConfigError('expected a value in descriptor')


def _parse_param(Tokens: list[tuple[str, str]], i: int) -> tuple[tuple[str, Node], int]:
    """Parse one ``(NAME = VALUE)`` parameter. Returns ``((name, node), next)``."""
    if i >= len(Tokens) or Tokens[i][0] != 'lparen':
        raise NetConfigError("expected '(' in descriptor")
    i += 1
    if i >= len(Tokens) or Tokens[i][0] != 'atom':
        raise NetConfigError('expected a parameter name in descriptor')
    Name = Tokens[i][1].lower()
    i += 1
    if i >= len(Tokens) or Tokens[i][0] != 'eq':
        raise NetConfigError(f"expected '=' after {Name!r} in descriptor")
    i += 1
    (Value, i) = _parse_value(Tokens, i)
    if i >= len(Tokens) or Tokens[i][0] != 'rparen':
        raise NetConfigError(f"expected ')' closing {Name!r} in descriptor")
    return ((Name, Value), i + 1)


def parse_tnsnames(Text: str) -> dict[str, Node]:
    """Parse a ``tnsnames.ora`` into ``{alias: descriptor_node}``.

    Aliases are lower-cased. A comma-separated alias list (``a, b = (...)``)
    binds every name to the same descriptor.
    """
    Tokens = _tokenize(Text)
    Entries: dict[str, Node] = {}
    i = 0
    while i < len(Tokens):
        # Left-hand side: one or more comma-separated alias names.
        Names: list[str] = []
        if Tokens[i][0] != 'atom':
            raise NetConfigError('expected an alias name in tnsnames.ora')
        Names.append(Tokens[i][1].lower())
        i += 1
        while i < len(Tokens) and Tokens[i][0] == 'comma':
            i += 1
            if i >= len(Tokens) or Tokens[i][0] != 'atom':
                raise NetConfigError('expected an alias name after comma')
            Names.append(Tokens[i][1].lower())
            i += 1
        if i >= len(Tokens) or Tokens[i][0] != 'eq':
            raise NetConfigError(f"expected '=' after alias {Names[-1]!r}")
        i += 1
        (Value, i) = _parse_value(Tokens, i)
        for Name in Names:
            Entries[Name] = Value
    return Entries


def parse_sqlnet(Text: str) -> dict[str, Node]:
    """Parse a ``sqlnet.ora`` into ``{param: node}`` (params lower-cased)."""
    Tokens = _tokenize(Text)
    Params: dict[str, Node] = {}
    i = 0
    while i < len(Tokens):
        if Tokens[i][0] != 'atom':
            raise NetConfigError('expected a parameter name in sqlnet.ora')
        Name = Tokens[i][1].lower()
        i += 1
        if i >= len(Tokens) or Tokens[i][0] != 'eq':
            raise NetConfigError(f"expected '=' after {Name!r} in sqlnet.ora")
        i += 1
        (Value, i) = _parse_value(Tokens, i)
        Params[Name] = Value
    return Params


def _find_all(Node_: Node, Key: str) -> list[Node]:
    """Every value bound to ``Key`` anywhere in the subtree, in document order."""
    Found: list[Node] = []
    if isinstance(Node_, list):
        for K, V in Node_:
            if K == Key:
                Found.append(V)
            Found.extend(_find_all(V, Key))
    return Found


def _find_first(Node_: Node, Key: str) -> Node | None:
    """The first value bound to ``Key`` in the subtree, or ``None``."""
    Matches = _find_all(Node_, Key)
    return Matches[0] if Matches else None


# --------------------------------------------------------------------------- #
# A connect descriptor passed as dsn
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DescriptorTarget:
    """What a single-address connect descriptor names."""

    host: str
    port: int
    service_name: str = ''
    sid: str = ''
    protocol: str = 'tcp'
    server_type: str | None = None
    # Every address the descriptor names, when there are several or it asks for
    # retries; the fields above are the first one's (#1983).
    route: Route | None = None
    # The HTTPS proxy a TCPS address is reached through (#1993).
    https_proxy: str = ''
    https_proxy_port: int = 0
    # The instance CONNECT_DATA names, and the DESCRIPTION's keepalive
    # interval in minutes (#2456).
    instance_name: str = ''
    expire_time: int = 0
    # The DRCP implicit pooling boundary CONNECT_DATA names (#2542).
    pool_boundary: str | None = None


@dataclass(frozen=True)
class Address:
    """One address a connection can try, with the connect data it goes with."""

    host: str
    port: int
    protocol: str = 'tcp'
    service_name: str = ''
    sid: str = ''
    server_type: str | None = None
    https_proxy: str = ''
    https_proxy_port: int = 0
    instance_name: str = ''
    pool_boundary: str | None = None


@dataclass(frozen=True)
class Route:
    """The addresses a connection tries and how, as python-oracledb tries them
    (#1983): in order; shuffled once per connect with LOAD_BALANCE; only the
    first with FAILOVER off; the whole list again RETRY_COUNT times, RETRY_DELAY
    seconds apart."""

    addresses: tuple[Address, ...]
    failover: bool = True
    load_balance: bool = False
    retry_count: int = 0
    retry_delay: float = 1.0

    def order(self) -> list[Address]:
        # The addresses one round tries.
        order = list(self.addresses)
        if self.load_balance:
            random.shuffle(order)
        return order if self.failover else order[:1]


_SERVER_TYPES = frozenset({'dedicated', 'shared', 'pooled'})


def server_type_value(value: str | None) -> str | None:
    """A server type as the reference client writes it into (SERVER=...):
    dedicated, shared or pooled, lower-cased; None for none (#1977)."""
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered not in _SERVER_TYPES:
        raise ProgrammingError(f'invalid server_type: {value}')
    return lowered


_POOL_BOUNDARIES = frozenset({'statement', 'transaction'})


def pool_boundary_value(value: str | None) -> str | None:
    """A DRCP implicit pooling boundary as written into (POOL_BOUNDARY=...):
    statement or transaction, lower-cased; None for none (#2542). The server
    refuses any other value with ORA-24545 on a pooled connection and ignores
    the parameter on a dedicated one, so it is checked here, as server_type is."""
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered not in _POOL_BOUNDARIES:
        raise ProgrammingError(f'invalid pool_boundary: {value}')
    return lowered


# The keys read, at each level. CID only describes the client, which seerdb
# reports itself, and FAILOVER means nothing with one address. Anything else is
# refused by name rather than ignored -- python-oracledb acts on most of them
# (RETRY_COUNT, SDU, SECURITY, ...), so dropping one would connect differently.
_ROUTE_KEYS = frozenset({'failover', 'load_balance'})
_DESCRIPTION_LIST_KEYS = _ROUTE_KEYS | {'description'}
_DESCRIPTION_KEYS = _ROUTE_KEYS | {
    'address',
    'address_list',
    'connect_data',
    'expire_time',
    'retry_count',
    'retry_delay',
}
_ADDRESS_LIST_KEYS = _ROUTE_KEYS | {'address'}
_ADDRESS_KEYS = frozenset(
    {'protocol', 'host', 'port', 'https_proxy', 'https_proxy_port'}
)
_CONNECT_DATA_KEYS = frozenset(
    {'service_name', 'sid', 'cid', 'server', 'instance_name', 'pool_boundary'}
)
_DEFAULT_PORT = 1521


def _branch(value: Node, name: str) -> list[tuple[str, Node]]:
    if not isinstance(value, list):
        raise NetConfigError(f'{name.upper()} must hold parameters, not {value!r}')
    return value


def _refuse_unread(
    entries: list[tuple[str, Node]], keys: frozenset, where: str
) -> None:
    unread = sorted({key.upper() for key, _ in entries if key not in keys})
    if unread:
        raise NotSupportedError(
            f'{where} {", ".join(unread)} in a connect descriptor is not supported yet'
        )


def parse_descriptor(text: str) -> DescriptorTarget:
    """Read a connect descriptor with one TCP address:
    ``(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=h)(PORT=p))(CONNECT_DATA=...))``.
    """
    tokens = _tokenize(text)
    ((name, value), end) = _parse_param(tokens, 0)
    if end != len(tokens):
        raise NetConfigError('text follows the connect descriptor')
    return descriptor_target(name, value)


def _on_off(value: Node, key: str) -> bool:
    if isinstance(value, str) and value.strip().lower() in ('on', 'yes', 'true'):
        return True
    if isinstance(value, str) and value.strip().lower() in ('off', 'no', 'false'):
        return False
    raise NetConfigError(f'{key.upper()}={value!r} is not ON or OFF')


def _number(value: Node, key: str) -> float:
    try:
        return float(value) if isinstance(value, str) else float('nan')
    except ValueError:
        return float('nan')


@dataclass
class _RouteOptions:
    # What a descriptor's levels say about the route, as read.
    failover: bool = True
    load_balance: bool = False
    retry_count: int | None = None
    retry_delay: float | None = None


def _route_options(entries: list[tuple[str, Node]], options: _RouteOptions) -> None:
    # FAILOVER / LOAD_BALANCE at this level. Any level turning failover off, or
    # load balancing on, decides it for the whole route -- coarser than Oracle
    # Net's per-list nesting, which applies each to its own list only.
    for key, value in entries:
        if key == 'failover' and not _on_off(value, key):
            options.failover = False
        elif key == 'load_balance' and _on_off(value, key):
            options.load_balance = True


def _address(node: Node, data: Address) -> Address:
    address = _branch(node, 'address')
    _refuse_unread(address, _ADDRESS_KEYS, 'ADDRESS parameter')
    found_protocol = _find_first(address, 'protocol')
    protocol = found_protocol.lower() if isinstance(found_protocol, str) else 'tcp'
    # ws / wss are the seerdb WebSocket transport extension (#1988), carried
    # beside TCP / TCPS so a descriptor can name them too.
    if protocol not in ('tcp', 'tcps', 'ws', 'wss'):
        raise NetConfigError(f'PROTOCOL={found_protocol} is not TCP, TCPS, WS or WSS')
    host = _find_first(address, 'host')
    if not isinstance(host, str) or not host:
        raise NetConfigError('the connect descriptor names no HOST')
    port = _find_first(address, 'port')
    if port is None:
        port_number = _DEFAULT_PORT
    elif isinstance(port, str) and port.isdigit():
        port_number = int(port)
    else:
        raise NetConfigError(f'PORT={port!r} in the connect descriptor is not a number')
    (proxy, proxy_port) = proxy_address(
        _find_first(address, 'https_proxy'), _find_first(address, 'https_proxy_port')
    )
    return replace(
        data,
        host=host,
        port=port_number,
        protocol=protocol,
        https_proxy=proxy,
        https_proxy_port=proxy_port,
    )


def proxy_address(proxy: Node | None, port: Node | None) -> tuple[str, int]:
    """An HTTPS proxy as given, checked: a host and a port, both or neither
    (#1993). python-oracledb took a proxy without a port as port 0 and failed
    at connect; this says so when the DSN is read."""
    if proxy is None or proxy == '':
        if port not in (None, ''):
            raise NetConfigError('HTTPS_PROXY_PORT without an HTTPS_PROXY')
        return ('', 0)
    if not isinstance(proxy, str) or not isinstance(port, str) or not port.isdigit():
        raise NetConfigError(f'HTTPS_PROXY={proxy!r} needs an HTTPS_PROXY_PORT')
    return (proxy, int(port))


def _connect_data(description: list[tuple[str, Node]]) -> Address:
    # The description's CONNECT_DATA, as an Address its addresses fill in.
    connect_data = [v for k, v in description if k == 'connect_data']
    service_name = sid = instance_name = ''
    server_type = pool_boundary = None
    if connect_data:
        data = _branch(connect_data[0], 'connect_data')
        _refuse_unread(data, _CONNECT_DATA_KEYS, 'CONNECT_DATA parameter')
        found = _find_first(data, 'service_name')
        service_name = found if isinstance(found, str) else ''
        found = _find_first(data, 'sid')
        sid = found if isinstance(found, str) else ''
        found = _find_first(data, 'instance_name')
        instance_name = found if isinstance(found, str) else ''
        found = _find_first(data, 'server')
        if found is not None:
            if not isinstance(found, str):
                raise NetConfigError('SERVER in CONNECT_DATA must be a word')
            server_type = server_type_value(found)
        found = _find_first(data, 'pool_boundary')
        if found is not None:
            if not isinstance(found, str):
                raise NetConfigError('POOL_BOUNDARY in CONNECT_DATA must be a word')
            pool_boundary = pool_boundary_value(found)
    return Address(
        '',
        0,
        'tcp',
        service_name,
        sid,
        server_type,
        instance_name=instance_name,
        pool_boundary=pool_boundary,
    )


def descriptor_target(name: str, value: Node) -> DescriptorTarget:
    """What a parsed ``(NAME = VALUE)`` descriptor names; the checks of
    :func:`parse_descriptor`, for a descriptor already read (a tnsnames alias).

    Every address is read, in order, across ADDRESS_LISTs and a
    DESCRIPTION_LIST, each with its description's CONNECT_DATA (#1983)."""
    options = _RouteOptions()
    if name == 'description_list':
        entries = _branch(value, name)
        _refuse_unread(entries, _DESCRIPTION_LIST_KEYS, 'DESCRIPTION_LIST parameter')
        _route_options(entries, options)
        descriptions = [v for k, v in entries if k == 'description']
    elif name == 'description':
        descriptions = [value]
    else:
        raise NetConfigError(
            f'a connect descriptor opens with DESCRIPTION, not {name.upper()}'
        )
    addresses: list[Address] = []
    expire_time: int | None = None
    for node in descriptions:
        description = _branch(node, 'description')
        _refuse_unread(description, _DESCRIPTION_KEYS, 'DESCRIPTION parameter')
        _route_options(description, options)
        for key, child in description:
            if key in ('retry_count', 'retry_delay'):
                number = _number(child, key)
                if not number >= 0:
                    raise NetConfigError(f'{key.upper()}={child!r} is not a number')
                if key == 'retry_count' and options.retry_count is None:
                    options.retry_count = int(number)
                elif key == 'retry_delay' and options.retry_delay is None:
                    options.retry_delay = number
            elif key == 'expire_time' and expire_time is None:
                # Minutes between keepalive probes; the first description's
                # holds for the connection (#2456).
                number = _number(child, key)
                if not number >= 0:
                    raise NetConfigError(f'EXPIRE_TIME={child!r} is not a number')
                expire_time = int(number)
        data = _connect_data(description)
        for key, child in description:
            if key == 'address':
                addresses.append(_address(child, data))
            elif key == 'address_list':
                entries = _branch(child, key)
                _refuse_unread(entries, _ADDRESS_LIST_KEYS, 'ADDRESS_LIST parameter')
                _route_options(entries, options)
                addresses.extend(
                    _address(v, data) for k, v in entries if k == 'address'
                )
    if not addresses:
        raise NetConfigError('the connect descriptor names no ADDRESS')
    first = addresses[0]
    route = None
    if len(addresses) > 1 or options.retry_count:
        route = Route(
            tuple(addresses),
            failover=options.failover,
            load_balance=options.load_balance,
            retry_count=options.retry_count or 0,
            retry_delay=1.0 if options.retry_delay is None else options.retry_delay,
        )
    return DescriptorTarget(
        first.host,
        first.port,
        first.service_name,
        first.sid,
        first.protocol,
        first.server_type,
        route,
        first.https_proxy,
        first.https_proxy_port,
        first.instance_name,
        expire_time or 0,
        first.pool_boundary,
    )


# --------------------------------------------------------------------------- #
# A tnsnames alias passed as dsn, without a wallet
# --------------------------------------------------------------------------- #

_IFILE = re.compile(r'^\s*ifile\s*=\s*(\S+)\s*$', re.IGNORECASE | re.MULTILINE)


def config_directory(config_dir: str | None) -> str:
    """Where ``tnsnames.ora`` is looked for: ``config_dir``, else ``TNS_ADMIN``,
    else ``$ORACLE_HOME/network/admin`` -- python-oracledb's order. Read at
    connect time, where python-oracledb reads the environment once, at import."""
    if config_dir:
        return config_dir
    if os.environ.get('TNS_ADMIN'):
        return os.environ['TNS_ADMIN']
    if os.environ.get('ORACLE_HOME'):
        return os.path.join(os.environ['ORACLE_HOME'], 'network', 'admin')
    raise NetConfigError(
        'a tnsnames alias needs a configuration directory: pass config_dir= '
        'or set TNS_ADMIN'
    )


def read_tnsnames(path: str, _seen: frozenset[str] = frozenset()) -> dict[str, Node]:
    """The aliases in the ``tnsnames.ora`` at ``path``, following its ``IFILE``
    includes (a relative one is relative to the including file). An alias the
    file defines itself wins over an included one."""
    real = os.path.realpath(path)
    if real in _seen:
        raise NetConfigError(f'{path} includes itself through IFILE')
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError as e:
        raise NetConfigError(f'cannot read {path}: {e.strerror}') from e
    includes = _IFILE.findall(text)
    entries = parse_tnsnames(_IFILE.sub('', text))
    for include in includes:
        target = os.path.join(os.path.dirname(path), include.strip('"'))
        for alias, node in read_tnsnames(target, _seen | {real}).items():
            entries.setdefault(alias, node)
    return entries


def resolve_alias(alias: str, config_dir: str | None) -> DescriptorTarget:
    """What tnsnames alias ``alias`` names, from the configuration directory."""
    path = os.path.join(config_directory(config_dir), 'tnsnames.ora')
    entries = read_tnsnames(path)
    node = entries.get(alias.lower())
    if node is None:
        raise NetConfigError(f'alias {alias!r} is not in {path}')
    if not isinstance(node, list) or len(node) != 1:
        raise NetConfigError(f'alias {alias!r} in {path} is not one connect descriptor')
    ((name, value),) = node
    return descriptor_target(name, value)


def holds_wallet(directory: str) -> bool:
    """Whether ``directory`` holds a client identity (``ewallet.pem`` or
    ``ewallet.p12``), which makes ``config_dir`` a wallet location too."""
    return any(
        os.path.isfile(os.path.join(directory, name))
        for name in ('ewallet.pem', 'ewallet.p12')
    )


# --------------------------------------------------------------------------- #
# The HTTP CONNECT tunnel to a TCPS address behind an HTTPS proxy (#1993)
# --------------------------------------------------------------------------- #


def proxy_connect_request(host: str, port: int) -> bytes:
    """The request python-oracledb sends an HTTPS proxy, byte for byte (measured):
    HTTP/1.0, no Host header, no proxy authentication."""
    target = f'[{host}]' if ':' in host else host
    return f'CONNECT {target}:{port} HTTP/1.0\r\n\r\n'.encode('ascii')


def check_proxy_reply(head: bytes, proxy: str, proxy_port: int) -> None:
    """Raise unless the proxy's reply opens the tunnel: a 2xx status line. A
    403 or a 407 (python-oracledb sends no credentials) fails at once."""
    line = head.split(b'\r\n', 1)[0].decode('latin-1').strip()
    parts = line.split(None, 2)
    if (
        b'\r\n\r\n' not in head
        or len(parts) < 2
        or not parts[0].startswith('HTTP/')
        or not parts[1].startswith('2')
    ):
        raise OperationalError(
            f'the HTTPS proxy {proxy}:{proxy_port} did not open a tunnel: '
            f'{line or "no reply"}'
        )
