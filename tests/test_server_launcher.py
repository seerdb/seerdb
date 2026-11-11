# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The packaged launcher: ``seerdb-mirror`` / ``python -m seerdb.server`` (#1685)."""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from seerdb.server import service
from seerdb.server.backend import Backend
from seerdb.server.launcher import accounts, build

_ROOT = Path(__file__).resolve().parent.parent
_USERS = {'MIRROR_USERS': 'scott:tiger'}


def _ini(tmp_path: Path, text: str) -> str:
    path = tmp_path / 'mirror.ini'
    path.write_text(text)
    return str(path)


def test_a_postgres_mirror_from_the_command_line() -> None:
    launch = build(['postgres', 'dbname=mirror'], env=_USERS)
    assert (launch.host, launch.port, launch.encryption) == (
        '127.0.0.1',
        1521,
        'requested',
    )
    assert launch.log_level == 'INFO'
    assert launch.backend_factory is not None
    assert launch.description == 'PostgreSQL presenting 23ai'


def test_the_command_line_wins_over_the_config_file(tmp_path: Path) -> None:
    config = _ini(
        tmp_path,
        '[server]\nhost = 0.0.0.0\nport = 1600\nencryption = required\n'
        '[clients]\nScott = tiger\n'
        '[backend]\ntype = postgres\nconninfo = dbname=mirror\npresents = 12.1\n',
    )
    launch = build(['--config', config, '--port', '1700'], env={})
    assert (launch.host, launch.port, launch.encryption) == (
        '0.0.0.0',
        1700,
        'required',
    )
    assert launch.description == 'PostgreSQL presenting 12.1'
    launch = build(['--config', config, 'postgres', '--presents', '23ai'], env={})
    assert launch.description == 'PostgreSQL presenting 23ai'


def test_accounts_come_from_the_config_file_and_mirror_users() -> None:
    # Names fold to upper case, as Oracle's do; MIRROR_USERS adds to the file's.
    assert accounts({'Scott': 'tiger'}, 'adams:wood, blake:paper') == {
        'SCOTT': 'tiger',
        'ADAMS': 'wood',
        'BLAKE': 'paper',
    }
    with pytest.raises(SystemExit, match='not user:password'):
        accounts({}, 'adams')


def test_a_mirror_with_no_accounts_does_not_start() -> None:
    # No default account: a Mirror serves only who it was told to.
    with pytest.raises(SystemExit, match='no accounts'):
        build(['postgres', 'dbname=mirror'], env={})
    with pytest.raises(SystemExit, match='no accounts'):
        build(['passthrough', 'db:1521/ORCL', '--field-version', '24'], env={})
    # Accounts kept in the database are enough.
    launch = build(['postgres', 'dbname=mirror', '--auth-conninfo', 'dbname=a'], env={})
    assert launch.backend_factory is not None


def test_per_user_roles_need_an_auth_database(tmp_path: Path) -> None:
    # Each user's role password is kept with its account (#1857), so per-user
    # mode needs the accounts in the database, on the command line or in the
    # config file.
    users = {'MIRROR_USERS': 'scott:tiger'}
    with pytest.raises(SystemExit, match='needs --auth-conninfo'):
        build(['postgres', 'dbname=mirror', '--per-user-roles'], env=users)
    launch = build(
        [
            'postgres',
            'dbname=mirror',
            '--per-user-roles',
            '--auth-conninfo',
            'dbname=a',
        ],
        env=users,
    )
    assert launch.backend_factory is not None
    ini = tmp_path / 'mirror.ini'
    ini.write_text('[backend]\ntype = postgres\nconninfo = x\nper_user_roles = yes\n')
    with pytest.raises(SystemExit, match='needs --auth-conninfo'):
        build(['--config', str(ini)], env=users)


@pytest.mark.parametrize(
    ('argv', 'message'),
    [
        ([], 'name a backend'),
        (['postgres'], 'connection string'),
        (['passthrough'], 'upstream'),
        (['passthrough', 'db/ORCL'], 'host:port/service'),
        (['--log-level', 'LOUD', 'observe'], 'log level'),
    ],
)
def test_what_a_launch_needs(argv: list[str], message: str) -> None:
    with pytest.raises(SystemExit, match=message):
        build(argv, env=_USERS)


def test_an_unknown_encryption_in_the_config_file_is_refused(tmp_path: Path) -> None:
    config = _ini(tmp_path, '[server]\nencryption = sometimes\n')
    with pytest.raises(SystemExit, match='encryption'):
        build(['--config', config, 'observe'], env={})


def test_a_given_field_version_skips_probing_the_upstream() -> None:
    launch = build(
        ['passthrough', 'db.example.com:1521/FREEPDB1', '--field-version', '24'],
        env=_USERS,
    )
    assert launch.field_version == 24
    assert launch.description == 'passthrough to db.example.com:1521/FREEPDB1'


def test_observe_serves_no_backend() -> None:
    launch = build(['--port', '1599', 'observe'], env={})
    assert launch.backend_factory is None
    assert launch.port == 1599


def test_every_session_shares_one_account_map(monkeypatch: pytest.MonkeyPatch) -> None:
    # A password changed on one connection has to reach the next login, so the
    # sessions' backends share the launcher's map rather than copy it (#515).
    pytest.importorskip('psycopg')
    from seerdb.server.backends import postgres

    seen: list[dict[str, str]] = []

    class _Recording:
        def __init__(
            self, conninfo: str, *, credentials: dict[str, str], **kw: Any
        ) -> None:
            seen.append(credentials)

    monkeypatch.setattr(postgres, 'PostgresBackend', _Recording)
    launch = build(['postgres', 'dbname=mirror'], env=_USERS)
    assert launch.backend_factory is not None
    launch.backend_factory()
    launch.backend_factory()
    assert seen[0] is seen[1]
    assert seen[0] == {'SCOTT': 'tiger'}


def test_the_server_hands_its_encryption_stance_to_each_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_session(stream: object, backend: object, **kw: object) -> str:
        seen.update(kw)
        return 'SCOTT'

    monkeypatch.setattr(service, 'serve_session', fake_session)
    server = service.Server(
        port=0,
        backend_factory=lambda: cast(Backend, _Closable()),
        encryption='required',
    )
    try:
        a, b = socket.socketpair()
        b.close()
        server._handle(a, ('127.0.0.1', 0))
    finally:
        server.close()
    assert seen['encryption'] == 'required'


class _Closable:
    def close(self) -> None:
        pass


def test_native_sql_is_the_operators_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Native PostgreSQL SQL is off unless the operator turns it on (#1859):
    # --native-sql on the command line, native_sql in the config file.
    pytest.importorskip('psycopg')
    from seerdb.server.backends import postgres

    seen: list[bool] = []

    class _Recording:
        def __init__(self, conninfo: str, *, native_sql: bool, **kw: Any) -> None:
            seen.append(native_sql)

    monkeypatch.setattr(postgres, 'PostgresBackend', _Recording)
    config = _ini(
        tmp_path,
        '[clients]\nScott = tiger\n'
        '[backend]\ntype = postgres\nconninfo = dbname=mirror\nnative_sql = yes\n',
    )
    for argv in (
        ['postgres', 'dbname=mirror'],
        ['postgres', 'dbname=mirror', '--native-sql'],
        ['--config', config],
    ):
        launch = build(argv, env=_USERS)
        assert launch.backend_factory is not None
        launch.backend_factory()
    assert seen == [False, True, True]


def test_python_dash_m_runs_the_launcher() -> None:
    result = subprocess.run(
        [sys.executable, '-m', 'seerdb.server', '--help'],
        capture_output=True,
        text=True,
        cwd=_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert 'seerdb-mirror' in result.stdout
    for command in ('postgres', 'passthrough', 'observe'):
        assert command in result.stdout


def test_a_renamed_option_keeps_working_and_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The deprecation policy (#1863): a renamed command-line option or config
    # key still works as its replacement, and says so, naming the replacement
    # and the release that removes it. The new spelling wins over the old.
    from seerdb.server import launcher

    old = launcher._Deprecation('--presents', '9.9.0')
    monkeypatch.setitem(launcher._DEPRECATED_OPTIONS, '--release', old)
    monkeypatch.setitem(
        launcher._DEPRECATED_KEYS,
        ('backend', 'release'),
        launcher._Deprecation('presents', '9.9.0'),
    )
    monkeypatch.setitem(
        launcher._DEPRECATED_OPTIONS,
        '--log-level',
        launcher._Deprecation(None, '9.9.0'),
    )
    for argv in (
        ['postgres', 'dbname=mirror', '--release', '12.1'],
        ['postgres', 'dbname=mirror', '--release=12.1'],
    ):
        launch = build(argv, env=_USERS)
        assert launch.description == 'PostgreSQL presenting 12.1'
        assert launch.warnings == [
            '--release is deprecated: use --presents instead; it will be '
            'removed in seerdb 9.9.0'
        ]
    config = _ini(
        tmp_path,
        '[backend]\ntype = postgres\nconninfo = dbname=mirror\nrelease = 12.1\n',
    )
    launch = build(['--config', config], env=_USERS)
    assert launch.description == 'PostgreSQL presenting 12.1'
    assert launch.warnings == [
        '[backend] release is deprecated: use presents instead; it will be '
        'removed in seerdb 9.9.0'
    ]
    both = _ini(
        tmp_path,
        '[backend]\ntype = postgres\nconninfo = dbname=mirror\nrelease = 12.1\n'
        'presents = 23ai\n',
    )
    assert build(['--config', both], env=_USERS).description == (
        'PostgreSQL presenting 23ai'
    )
    # One removed with nothing in its place still works, and warns.
    launch = build(['--log-level', 'debug', 'postgres', 'dbname=mirror'], env=_USERS)
    assert launch.log_level == 'DEBUG'
    assert launch.warnings == [
        '--log-level is deprecated: it will be removed in seerdb 9.9.0'
    ]
    # Logged at WARNING as the Mirror starts.
    monkeypatch.setattr(service, 'serve', lambda *a, **k: None)
    monkeypatch.setenv('MIRROR_USERS', 'scott:tiger')
    with caplog.at_level('WARNING', logger='seerdb.server'):
        launcher.main(['postgres', 'dbname=mirror', '--release', '12.1'])
    assert '--release is deprecated' in caplog.text


def test_every_deprecation_is_in_the_changelog() -> None:
    # Each deprecated option or key is named in the ChangeLog, with the word
    # deprecated (#1863).
    from seerdb.server import launcher

    lines = (_ROOT / 'ChangeLog').read_text().lower().splitlines()
    names = [*launcher._DEPRECATED_OPTIONS] + [
        f'[{section}] {key}' for (section, key) in launcher._DEPRECATED_KEYS
    ]
    for name in names:
        assert any(f'`{name}`' in line and 'deprecated' in line for line in lines), name


def test_max_sessions_comes_from_the_command_line_or_the_config(tmp_path: Path) -> None:
    # GHSA-5827-wqfh-x2v3: no limit unless the operator sets one.
    assert build(['postgres', 'dbname=mirror'], env=_USERS).max_sessions is None
    launch = build(['--max-sessions', '50', 'postgres', 'dbname=mirror'], env=_USERS)
    assert launch.max_sessions == 50
    config = _ini(
        tmp_path,
        '[server]\nmax_sessions = 7\n[backend]\ntype = postgres\nconninfo = dbname=m\n',
    )
    assert build(['--config', config], env=_USERS).max_sessions == 7
    with pytest.raises(SystemExit):
        build(['--max-sessions', '0', 'postgres', 'dbname=mirror'], env=_USERS)


def test_failed_login_attempts_default_to_oracles(tmp_path: Path) -> None:
    # GHSA-742q-fjfr-w5x3: 10, as Oracle's default profile; 0 never locks.
    assert build(['postgres', 'dbname=mirror'], env=_USERS).failed_login_attempts == 10
    launch = build(
        ['--failed-login-attempts', '0', 'postgres', 'dbname=mirror'], env=_USERS
    )
    assert launch.failed_login_attempts == 0
    with pytest.raises(SystemExit):
        build(
            ['--failed-login-attempts', '-1', 'postgres', 'dbname=mirror'], env=_USERS
        )


def test_the_ws_listener_is_off_by_default() -> None:
    launch = build(['postgres', 'dbname=mirror'], env=_USERS)
    assert launch.ws_port is None
    assert launch.ws_origins is None


def test_ws_options_on_the_command_line() -> None:
    launch = build(
        [
            '--ws-port',
            '1522',
            '--ws-origin',
            'https://a.example',
            '--ws-origin',
            'https://b.example',
            'postgres',
            'dbname=mirror',
        ],
        env=_USERS,
    )
    assert launch.ws_port == 1522
    assert launch.ws_origins == ['https://a.example', 'https://b.example']


def test_ws_options_from_the_config_file(tmp_path: Path) -> None:
    config = _ini(
        tmp_path,
        '[server]\nws_port = 1522\nws_origins = https://a.example, https://b.example\n'
        '[clients]\nScott = tiger\n'
        '[backend]\ntype = postgres\nconninfo = dbname=mirror\n',
    )
    launch = build(['--config', config], env={})
    assert launch.ws_port == 1522
    assert launch.ws_origins == ['https://a.example', 'https://b.example']


def test_a_bad_ws_port_is_refused() -> None:
    with pytest.raises(SystemExit):
        build(['--ws-port', '99999', 'postgres', 'dbname=mirror'], env=_USERS)


def test_query_ws_port_option() -> None:
    launch = build(['--query-ws-port', '1523', 'postgres', 'dbname=mirror'], env=_USERS)
    assert launch.query_ws_port == 1523
    assert launch.ws_port is None


def test_query_ws_port_from_the_config_file(tmp_path: Path) -> None:
    config = _ini(
        tmp_path,
        '[server]\nquery_ws_port = 1523\n'
        '[clients]\nScott = tiger\n'
        '[backend]\ntype = postgres\nconninfo = dbname=mirror\n',
    )
    launch = build(['--config', config], env={})
    assert launch.query_ws_port == 1523


def test_services_reach_the_backend() -> None:
    # --service, repeatable, or `services` in the config file (#2471): the
    # names the Mirror serves besides its backend's own.
    launch = build(
        [
            '--service',
            'XE',
            '--service',
            'app',
            'passthrough',
            'db.example.com:1521/FREEPDB1',
            '--field-version',
            '24',
        ],
        env=_USERS,
    )
    assert launch.backend_factory is not None
    backend = cast(Any, launch.backend_factory())
    assert backend.refuse_connect('APP', None) is None
    assert backend.refuse_connect('XE', None) is None
    assert backend.refuse_connect('OTHER', None) == 12514


def test_services_come_from_the_config_file(tmp_path: Path) -> None:
    config = _ini(tmp_path, '[server]\nservices = XE, app\n')
    launch = build(
        [
            '--config',
            str(config),
            'passthrough',
            'db:1521/ORCL',
            '--field-version',
            '24',
        ],
        env=_USERS,
    )
    assert launch.backend_factory is not None
    backend = cast(Any, launch.backend_factory())
    assert backend.refuse_connect('app', None) is None
    assert backend.refuse_connect('ORCL', None) is None
    assert backend.refuse_connect('OTHER', None) == 12514
