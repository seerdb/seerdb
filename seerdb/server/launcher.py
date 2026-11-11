# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Start a Mirror: ``seerdb-mirror`` or ``python -m seerdb.server``.

    seerdb-mirror postgres 'host=127.0.0.1 dbname=mirror user=pyo password=...'
    seerdb-mirror passthrough db.example.com:1521/FREEPDB1
    seerdb-mirror --config mirror.ini
    seerdb-mirror observe
    seerdb-mirror profile compare oracle.json postgres.json --html report.html

Options come from the command line, then a config file (``--config``), then
the defaults; the command line wins. The config file is INI::

    [server]
    host = 127.0.0.1
    port = 1521
    encryption = requested      ; accepted | requested | required (ANO)
    log_level = INFO
    ; tls_cert = server.pem     ; TCPS: the server's certificate chain
    ; tls_key = server.key      ;       and its private key
    ; tls_ca = clients-ca.pem   ;       require client certificates from this CA
    ; ws_port = 1522            ; also serve the seerdb WebSocket transport here
    ; query_ws_port = 1523      ; also serve the JSON-over-WebSocket query endpoint
    ; ws_origins = https://app.example  ; browser Origins it admits (comma list)
    ; services = XE, APP       ; service names served besides the backend's own
    ; profile = profile.json    ; record per-statement statistics (SIGUSR1 writes)

    [clients]                   ; the Oracle logins the Mirror accepts
    SCOTT = tiger

    [backend]
    type = postgres             ; postgres | passthrough
    conninfo = host=... dbname=... user=... password=...
    presents = 23ai             ; postgres: 23ai | 12.1
    auth_conninfo = ...         ; postgres: accounts kept in the database
    translation_report = no     ; postgres: log each statement's translation
    native_sql = no             ; postgres: let clients run native PostgreSQL SQL
    per_user_roles = no         ; postgres: each user its own PostgreSQL role
    ; upstream = host:port/service   ; passthrough
    ; field_version = 24             ; passthrough: skip probing the upstream

More accounts come from ``MIRROR_USERS``, a comma-separated list of
``user:password`` pairs. Passwords are never taken from the command line, where
any local user could read them. The Mirror serves no account it was not given.
"""

from __future__ import annotations

import argparse
import configparser
import logging
import os
import signal
import ssl
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple, cast

from seerdb.server import lockout
from seerdb.server.backend import Backend

if TYPE_CHECKING:
    from seerdb.server.profile import Profile

_ENCRYPTION = ('accepted', 'requested', 'required')
_BACKENDS = ('postgres', 'passthrough')


class _Deprecation(NamedTuple):
    # What a deprecated option or config key gave way to -- None for one
    # removed with nothing in its place -- and the release that removes it.
    replacement: str | None
    removed_in: str


# The deprecated spellings (#1863): command-line options, as `--name`, and
# config-file keys, as (section, key). Each keeps working, with a warning, for
# at least one minor release, and the ChangeLog names it (docs/MIRROR.md,
# *Deprecations*). A renamed one becomes its replacement; a removed one stays
# defined where it was, and only warns.
_DEPRECATED_OPTIONS: dict[str, _Deprecation] = {}
_DEPRECATED_KEYS: dict[tuple[str, str], _Deprecation] = {}


def _deprecation_warning(old: str, deprecation: _Deprecation) -> str:
    instead = (
        f'use {deprecation.replacement} instead; '
        if deprecation.replacement is not None
        else ''
    )
    return (
        f'{old} is deprecated: {instead}it will be removed in seerdb '
        f'{deprecation.removed_in}'
    )


def _undeprecated_argv(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    # The command line with each renamed option spelled as its replacement,
    # `--old` and `--old=value` alike, and a warning for each deprecated one
    # given (#1863). Nothing after `--` is an option.
    out: list[str] = []
    warnings: list[str] = []
    options = True
    for arg in argv:
        if arg == '--':
            options = False
        (name, equals, value) = arg.partition('=')
        deprecation = _DEPRECATED_OPTIONS.get(name) if options else None
        if deprecation is None:
            out.append(arg)
            continue
        warnings.append(_deprecation_warning(name, deprecation))
        new = deprecation.replacement or name
        out.append(f'{new}{equals}{value}')
    return out, warnings


def _undeprecated_config(config: configparser.ConfigParser) -> list[str]:
    # The config file with each renamed key's value under its replacement --
    # the new key wins where both are set -- and a warning for each
    # deprecated key it sets (#1863).
    warnings: list[str] = []
    for (section, key), deprecation in _DEPRECATED_KEYS.items():
        if not config.has_option(section, key):
            continue
        warnings.append(_deprecation_warning(f'[{section}] {key}', deprecation))
        new = deprecation.replacement
        if new is not None:
            if not config.has_option(section, new):
                config.set(section, new, config.get(section, key))
            config.remove_option(section, key)
    return warnings


@dataclass
class Launch:
    """What a command line asks for: where to listen and what to serve."""

    host: str
    port: int
    log_level: str
    # None for the observer, which serves no backend.
    backend_factory: Callable[[], Backend] | None
    encryption: str = 'requested'
    field_version: int | None = None
    description: str = ''
    # TCPS (#1834): the server context, None for plain TCP.
    ssl_context: ssl.SSLContext | None = None
    # Where a migration profile is written (#1881), None for no profile.
    profile: str | None = None
    # How many connections are served at once (GHSA-5827-wqfh-x2v3), None
    # for no limit.
    max_sessions: int | None = None
    # The seerdb WebSocket listener (#1988/#1989): a port beside the TCP one,
    # None for none, and the browser Origin allow-list (None admits any).
    ws_port: int | None = None
    ws_origins: list[str] | None = None
    # The JSON-over-WebSocket query endpoint (#2371), None for none; shares
    # ws_origins, TLS and max_sessions with the raw-TNS WebSocket listener.
    query_ws_port: int | None = None
    # Failed logins in a row that lock a name (GHSA-742q-fjfr-w5x3); 0 never.
    failed_login_attempts: int = 10
    # A deprecated option or key the command line or the config file gave
    # (#1863), each to be logged as the Mirror starts.
    warnings: list[str] = field(default_factory=list)


class _Config(configparser.ConfigParser):
    # Keys keep their case: [clients] names are folded later, as Oracle's are.
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='seerdb-mirror',
        description='Serve Oracle clients from PostgreSQL or a real Oracle.',
        epilog='seerdb-mirror profile compare BASELINE CANDIDATE compares two '
        'profiles recorded with --profile.',
    )
    parser.add_argument('-c', '--config', help='an INI file of options')
    parser.add_argument(
        '--host',
        help='listen address, IPv4 or IPv6; :: serves both (default 127.0.0.1)',
    )
    parser.add_argument('--port', type=int, help='listen port (default 1521)')
    parser.add_argument(
        '--encryption',
        choices=_ENCRYPTION,
        help='native network encryption (ANO): requested (default) encrypts '
        'whenever the client offers it, required refuses a client that does not, '
        'accepted never encrypts',
    )
    parser.add_argument('--log-level', help='DEBUG, INFO (default), WARNING or ERROR')
    parser.add_argument(
        '--profile',
        metavar='FILE',
        help='record per-statement statistics, written to FILE as JSON at stop, '
        'on SIGUSR1 and as sessions end',
    )
    parser.add_argument(
        '--tls-cert', help="serve TCPS: the server's certificate chain (PEM)"
    )
    parser.add_argument('--tls-key', help="the certificate's private key (PEM)")
    parser.add_argument(
        '--tls-ca', help='require client certificates issued by this CA (PEM)'
    )
    parser.add_argument(
        '--max-sessions',
        type=int,
        help='serve at most this many connections at once (default: no limit)',
    )
    parser.add_argument(
        '--ws-port',
        type=int,
        help='also serve the seerdb WebSocket transport (#1988) on this port, '
        'beside the TCP/TCPS listener; wss when --tls-cert is given, else ws '
        '(a seerdb extension; no Oracle client speaks it)',
    )
    parser.add_argument(
        '--service',
        action='append',
        metavar='NAME',
        help="a service name the Mirror serves besides its backend's own (the "
        "PostgreSQL database's name, the upstream's service), repeatable; a "
        'client naming any other is refused with ORA-12514, as by a listener',
    )
    parser.add_argument(
        '--ws-origin',
        action='append',
        metavar='ORIGIN',
        help='a browser Origin the WebSocket listener admits (repeatable); '
        'without any, every origin may connect (not recommended -- a '
        'browser-facing endpoint still needs the security review, milestone 52). '
        'Applies to both --ws-port and --query-ws-port',
    )
    parser.add_argument(
        '--query-ws-port',
        type=int,
        help='also serve the thin JSON-over-WebSocket query endpoint (#2371) on '
        'this port; wss when --tls-cert is given, else ws (a seerdb extension)',
    )
    parser.add_argument(
        '--failed-login-attempts',
        type=int,
        help='lock a user name after this many failed logins in a row '
        '(default 10; 0 never locks)',
    )
    commands = parser.add_subparsers(dest='command', metavar='BACKEND')
    postgres = commands.add_parser('postgres', help='serve from PostgreSQL')
    postgres.add_argument('conninfo', nargs='?', help='a libpq connection string')
    postgres.add_argument(
        '--presents', help='the Oracle release presented: 23ai (default) or 12.1'
    )
    postgres.add_argument(
        '--auth-conninfo',
        help='keep the accounts in the database, connecting as this role',
    )
    postgres.add_argument(
        '--translation-report',
        action='store_true',
        default=None,
        help="log each statement's translation to sys.ora_translation_log",
    )
    postgres.add_argument(
        '--per-user-roles',
        action='store_true',
        default=None,
        help="run each user's sessions as a PostgreSQL role of its own "
        '(needs --auth-conninfo and PostgreSQL 16)',
    )
    postgres.add_argument(
        '--native-sql',
        action='store_true',
        default=None,
        help='let clients run native PostgreSQL SQL: a /*+ PG */ hint, or '
        "ALTER SESSION SET seerdb_dialect = 'postgres'",
    )
    passthrough = commands.add_parser(
        'passthrough', help='relay to a real Oracle database'
    )
    passthrough.add_argument('upstream', nargs='?', help='host:port/service')
    passthrough.add_argument(
        '--field-version',
        type=int,
        help="present this field version instead of probing the upstream's",
    )
    passthrough.add_argument(
        '--auth-conninfo',
        help='keep the accounts in a PostgreSQL database, connecting as this role',
    )
    commands.add_parser(
        'observe', help='log what a client puts on the wire (bring-up tool)'
    )
    return parser


def accounts(clients: dict[str, str], env: str | None) -> dict[str, str]:
    """The accounts to serve: the config file's, then ``MIRROR_USERS``'.

    Build it ONCE and hand the same dict to every session's backend, never a
    copy per session: a password changed on one connection has to reach the
    next login (#515).
    """
    credentials = {user.upper(): password for user, password in clients.items()}
    for pair in filter(None, (env or '').split(',')):
        user, colon, password = pair.partition(':')
        if not user.strip() or not colon:
            raise SystemExit(f'MIRROR_USERS entry is not user:password: {pair!r}')
        credentials[user.strip().upper()] = password
    return credentials


def _upstream(text: str) -> tuple[str, int, str]:
    hostport, slash, service = text.rpartition('/')
    host, colon, port = hostport.rpartition(':')
    if not slash or not colon or not host or not service or not port.isdigit():
        raise SystemExit(f'upstream is not host:port/service: {text!r}')
    return host, int(port), service


def _flag(value: str) -> bool:
    if value.lower() in ('1', 'yes', 'true', 'on'):
        return True
    if value.lower() in ('0', 'no', 'false', 'off', ''):
        return False
    raise SystemExit(f'not a yes/no value: {value!r}')


def _tls_context(cert: str, key: str, ca: str) -> ssl.SSLContext | None:
    # The TCPS server context (#1834), or None when no certificate is given.
    if not cert:
        if key or ca:
            raise SystemExit('--tls-key and --tls-ca need --tls-cert')
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(cert, key or None)
        if ca:
            context.load_verify_locations(ca)
            context.verify_mode = ssl.CERT_REQUIRED
    except (OSError, ssl.SSLError) as exc:
        raise SystemExit(f'cannot load the TLS certificate or key: {exc}') from None
    return context


def build(
    argv: Sequence[str] | None = None, env: dict[str, str] | None = None
) -> Launch:
    """Parse a command line (and its config file) into a :class:`Launch`."""
    env = dict(os.environ) if env is None else env
    (given_argv, warnings) = _undeprecated_argv(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(given_argv)
    config = _Config(interpolation=None)
    if args.config is not None and not config.read(args.config):
        raise SystemExit(f'cannot read config file {args.config!r}')
    warnings += _undeprecated_config(config)
    no_section: dict[str, str] = {}
    server: Mapping[str, str] = (
        config['server'] if config.has_section('server') else no_section
    )
    backend: Mapping[str, str] = (
        config['backend'] if config.has_section('backend') else no_section
    )

    def option(
        given: object, section: Mapping[str, str], key: str, default: str
    ) -> str:
        if given is not None:
            return str(given)
        return section.get(key, default)

    host = option(args.host, server, 'host', '127.0.0.1')
    port = int(option(args.port, server, 'port', '1521'))
    # requested by default (#1844): encrypt whenever the client offers ANO.
    encryption = option(args.encryption, server, 'encryption', 'requested')
    if encryption not in _ENCRYPTION:
        raise SystemExit(f'encryption must be one of {", ".join(_ENCRYPTION)}')
    log_level = option(args.log_level, server, 'log_level', 'INFO').upper()
    if not isinstance(logging.getLevelName(log_level), int):
        raise SystemExit(f'unknown log level {log_level!r}')

    ssl_context = _tls_context(
        option(args.tls_cert, server, 'tls_cert', ''),
        option(args.tls_key, server, 'tls_key', ''),
        option(args.tls_ca, server, 'tls_ca', ''),
    )
    profile = option(args.profile, server, 'profile', '') or None
    sessions = option(args.max_sessions, server, 'max_sessions', '')
    max_sessions = int(sessions) if sessions else None
    if max_sessions is not None and max_sessions < 1:
        raise SystemExit('max_sessions must be at least 1')
    attempts = int(
        option(
            args.failed_login_attempts,
            server,
            'failed_login_attempts',
            str(lockout.DEFAULT_ATTEMPTS),
        )
    )
    if attempts < 0:
        raise SystemExit('failed_login_attempts must be 0 or more')
    # The WebSocket listener (#1988/#1989): a port beside the TCP one, and a
    # browser Origin allow-list (--ws-origin, or a comma-separated ws_origins).
    ws = option(args.ws_port, server, 'ws_port', '')
    ws_port = int(ws) if ws else None
    if ws_port is not None and not 0 <= ws_port <= 65535:
        raise SystemExit('ws_port must be a port number')
    if args.ws_origin:
        ws_origins: list[str] | None = list(args.ws_origin)
    else:
        raw = option(None, server, 'ws_origins', '')
        ws_origins = [o.strip() for o in raw.split(',') if o.strip()] or None
    # The service names served besides the backend's own (#2471).
    if args.service:
        services = list(args.service)
    else:
        raw = option(None, server, 'services', '')
        services = [n.strip() for n in raw.split(',') if n.strip()]
    # The JSON-over-WebSocket query endpoint (#2371).
    qws = option(args.query_ws_port, server, 'query_ws_port', '')
    query_ws_port = int(qws) if qws else None
    if query_ws_port is not None and not 0 <= query_ws_port <= 65535:
        raise SystemExit('query_ws_port must be a port number')

    kind = args.command or str(backend.get('type', '')).strip().lower()
    if kind == 'observe':
        return Launch(
            host, port, log_level, None, description='observer', warnings=warnings
        )
    if kind not in _BACKENDS:
        raise SystemExit(
            'name a backend: postgres or passthrough (or observe), on the '
            'command line or as [backend] type in the config file'
        )
    clients = dict(config['clients']) if config.has_section('clients') else {}
    credentials = accounts(clients, env.get('MIRROR_USERS'))

    if kind == 'postgres':
        conninfo = option(getattr(args, 'conninfo', None), backend, 'conninfo', '')
        if not conninfo:
            raise SystemExit('postgres needs a libpq connection string')
        presents = option(getattr(args, 'presents', None), backend, 'presents', '23ai')
        auth_conninfo = (
            option(getattr(args, 'auth_conninfo', None), backend, 'auth_conninfo', '')
            or None
        )
        report = _flag(
            option(
                getattr(args, 'translation_report', None),
                backend,
                'translation_report',
                'no',
            )
        )
        native_sql = _flag(
            option(getattr(args, 'native_sql', None), backend, 'native_sql', 'no')
        )
        per_user_roles = _flag(
            option(
                getattr(args, 'per_user_roles', None), backend, 'per_user_roles', 'no'
            )
        )
        if per_user_roles and auth_conninfo is None:
            # Each role's password is kept with its account (#1857).
            raise SystemExit('--per-user-roles needs --auth-conninfo')
        if not credentials and auth_conninfo is None:
            raise SystemExit(
                'no accounts to serve: list them under [clients] or in '
                'MIRROR_USERS, or keep them in the database with --auth-conninfo'
            )

        def postgres_factory() -> Backend:
            # Imported here, so naming another backend needs no psycopg.
            from seerdb.server.backends.postgres import PostgresBackend

            return PostgresBackend(
                conninfo,
                credentials=credentials,
                translation_report=report,
                auth_conninfo=auth_conninfo,
                presents=presents,
                native_sql=native_sql,
                per_user_roles=per_user_roles,
                services=services,
            )

        return Launch(
            host,
            port,
            log_level,
            postgres_factory,
            encryption=encryption,
            description=f'PostgreSQL presenting {presents}',
            ssl_context=ssl_context,
            profile=profile,
            max_sessions=max_sessions,
            ws_port=ws_port,
            ws_origins=ws_origins,
            query_ws_port=query_ws_port,
            failed_login_attempts=attempts,
            warnings=warnings,
        )

    upstream = option(getattr(args, 'upstream', None), backend, 'upstream', '')
    if not upstream:
        raise SystemExit('passthrough needs an upstream host:port/service')
    up_host, up_port, service = _upstream(upstream)
    # Where the accounts live (#1703): the launcher's, or an auth database's.
    pass_auth = (
        option(getattr(args, 'auth_conninfo', None), backend, 'auth_conninfo', '')
        or None
    )
    if not credentials and pass_auth is None:
        raise SystemExit(
            'no accounts to serve: list them under [clients] or in MIRROR_USERS, '
            'or keep them in a database with --auth-conninfo'
        )
    if pass_auth is not None:
        try:
            import psycopg  # noqa: F401
        except ImportError:
            raise SystemExit(
                '--auth-conninfo needs psycopg: pip install "seerdb[mirror]"'
            ) from None
    given = option(getattr(args, 'field_version', None), backend, 'field_version', '')
    field_version = int(given) if given else None
    if field_version is None and not credentials:
        # The version is probed with a configured account.
        raise SystemExit(
            'give --field-version, or an account in [clients] or MIRROR_USERS '
            'for the Mirror to probe the upstream with'
        )

    def passthrough_factory() -> Backend:
        from seerdb.server.backends.passthrough import OraclePassthroughBackend

        return OraclePassthroughBackend(
            host=up_host,
            port=up_port,
            service=service,
            credentials=credentials,
            field_version=launch.field_version,
            auth_conninfo=pass_auth,
            services=services,
        )

    launch = Launch(
        host,
        port,
        log_level,
        passthrough_factory,
        encryption=encryption,
        field_version=field_version,
        description=f'passthrough to {up_host}:{up_port}/{service}',
        ssl_context=ssl_context,
        profile=profile,
        max_sessions=max_sessions,
        ws_port=ws_port,
        ws_origins=ws_origins,
        query_ws_port=query_ws_port,
        failed_login_attempts=attempts,
        warnings=warnings,
    )
    if field_version is None:
        # Present what the upstream speaks: probe it once, as the first account.
        from seerdb.server.backends.passthrough import OraclePassthroughBackend

        user, password = next(iter(credentials.items()))
        launch.field_version = OraclePassthroughBackend.detect_version(
            up_host, up_port, service, user, password
        )
    return launch


def main(argv: Sequence[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ['profile']:
        # Not a server: the migration profile's tools (#1882).
        from seerdb.server.profile_compare import main as profile_main

        profile_main(argv[1:])
        return
    launch = build(argv)
    logging.basicConfig(
        level=launch.log_level,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    for warning in launch.warnings:
        logging.getLogger('seerdb.server').warning('%s', warning)
    lockout.configure(launch.failed_login_attempts)
    if launch.backend_factory is None:
        from seerdb.server.listener import serve_observer

        try:
            serve_observer(launch.host, launch.port)
        except KeyboardInterrupt:
            pass
        return
    from seerdb.server.service import serve

    presenting = (
        f', field version {launch.field_version}'
        if launch.field_version is not None
        else ''
    )
    logging.getLogger('seerdb.server').info(
        'Mirror over %s%s, encryption %s',
        launch.description,
        presenting,
        launch.encryption,
    )
    backend_factory = launch.backend_factory
    profile = None
    if launch.profile is not None:
        backend_factory, profile = _profiled(launch, backend_factory)
    # The seerdb WebSocket listeners (#1989 raw TNS, #2371 JSON query) run beside
    # the TCP/TCPS one, each on its own thread, sharing the backend, TLS (wss
    # when a cert is set), the origin allow-list and the session limit.
    ws_servers = []
    ws_ports = [(launch.ws_port, 'tns'), (launch.query_ws_port, 'query')]
    if any(port is not None for port, _ in ws_ports):
        from seerdb.server.ws_service import WsServer

        for port, ws_protocol in ws_ports:
            if port is None:
                continue
            server = WsServer(
                launch.host,
                port,
                backend_factory=backend_factory,
                encryption=launch.encryption,
                ssl_context=launch.ssl_context,
                max_sessions=launch.max_sessions,
                allowed_origins=launch.ws_origins,
                protocol=ws_protocol,
            )
            ws_servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        serve(
            launch.host,
            launch.port,
            backend_factory=backend_factory,
            encryption=launch.encryption,
            ssl_context=launch.ssl_context,
            max_sessions=launch.max_sessions,
        )
    finally:
        for server in ws_servers:
            server.close()
        if profile is not None:
            profile.dump()


def _stop(_signum: int, _frame: object) -> None:
    raise SystemExit(0)


def _profiled(
    launch: Launch, factory: Callable[[], Backend]
) -> tuple[Callable[[], Backend], Profile]:
    # Every session's backend recorded into one migration profile (#1881),
    # written on SIGUSR1 as well as when the server stops.
    from seerdb.server.profile import Profile, ProfilingBackend

    assert launch.profile is not None
    profile = Profile(launch.profile, launch.description)
    if hasattr(signal, 'SIGUSR1'):
        signal.signal(signal.SIGUSR1, lambda _signum, _frame: profile.dump())
    # A stop by SIGTERM -- kill, a service manager -- unwinds as an interrupt
    # does, so the profile is written then too.
    signal.signal(signal.SIGTERM, _stop)
    logging.getLogger('seerdb.server').info(
        'recording a migration profile to %s (SIGUSR1 writes it)', launch.profile
    )

    def profiled() -> Backend:
        return cast(Backend, ProfilingBackend(factory(), profile))

    return (profiled, profile)
