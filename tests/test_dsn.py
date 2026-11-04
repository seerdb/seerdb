# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""An Easy Connect ``dsn`` without a wallet names the address (#1972).

What the parser accepts, which side wins, and that both connection classes take
it. The precedence -- the DSN over host / port / service_name passed beside it
-- is what python-oracledb 26.0.1 does, measured with its ConnectParams.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect
from seerdb.client.dsn import (
    ConnectArguments,
    DsnTarget,
    parse_dsn,
    resolve_dsn_arguments,
)
from seerdb.client.netconfig import NetConfigError
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.tns_consts import PURITY_NEW, PURITY_SELF


def _resolve(dsn, *positional, config_dir=None):
    # resolve_dsn_arguments with the arguments given positionally, in the order
    # host, port, service_name, sid, user, password, ssl, server_type; the
    # rest at their defaults. The first eight fields come back.
    names = (
        'host',
        'port',
        'service_name',
        'sid',
        'user',
        'password',
        'ssl',
        'server_type',
    )
    given = {
        'host': 'localhost',
        'port': 1521,
        'service_name': '',
        'sid': '',
        'user': '',
        'password': '',
        'ssl': None,
        'server_type': None,
        'sdu': 8192,
        'cclass': None,
        'purity': 0,
        'timeout': 15000,
        'route': None,
        'https_proxy': None,
        'https_proxy_port': 0,
    }
    given.update(zip(names, positional))
    resolved = resolve_dsn_arguments(dsn, ConnectArguments(**given), config_dir)
    return resolved.as_tuple()[:8]


class Parameters(unittest.TestCase):
    # Easy Connect ? parameters (#1977), read as python-oracledb 26.0.1 reads
    # them: the DSN's value wins, names are case-insensitive, the last repeat
    # wins; those with a seerdb argument are applied, the rest refused by name.
    def _args(self, dsn, **given):
        base = {
            'host': 'localhost',
            'port': 1521,
            'service_name': '',
            'sid': '',
            'user': 'u',
            'password': 'p',
            'ssl': None,
            'server_type': None,
            'sdu': 8192,
            'cclass': None,
            'purity': 0,
            'timeout': 15000,
            'route': None,
            'https_proxy': None,
            'https_proxy_port': 0,
            **given,
        }
        return resolve_dsn_arguments(dsn, ConnectArguments(**base))

    def test_the_parameters_with_a_seerdb_argument(self):
        args = self._args(
            'db:1521/svc?SDU=32768 & pool_connection_class=K&pool_purity=self'
            '&transport_connect_timeout=3',
            sdu=16384,
            cclass='C',
        )
        self.assertEqual(
            (args.service_name, args.sdu, args.cclass, args.purity, args.timeout),
            ('svc', 32768, 'K', PURITY_SELF, 3000),
        )
        self.assertEqual(self._args('db/s?sdu=1000&sdu=2000').sdu, 2000)
        self.assertEqual(self._args('db/s?pool_purity=NEW').purity, PURITY_NEW)

    def test_a_timeout_takes_a_unit(self):
        for value, ms in (
            ('3', 3000),
            ('1.5', 1500),
            ('500ms', 500),
            ('2min', 120000),
            ('4 sec', 4000),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    self._args(f'db/s?transport_connect_timeout={value}').timeout, ms
                )

    def test_a_quoted_value_and_the_other_forms(self):
        args = self._args('tcps://db:2484/svc:pooled?pool_connection_class="A B"')
        self.assertEqual(
            (args.ssl, args.server_type, args.cclass), (True, 'pooled', 'A B')
        )

    def test_the_rest_are_refused_by_name(self):
        for name in (
            'connect_timeout',
            'wallet_location',
            'frobnicate',
        ):
            with self.subTest(name=name), self.assertRaises(NotSupportedError) as ctx:
                self._args(f'db/s?{name}=1')
            self.assertIn(name, str(ctx.exception))

    def test_a_malformed_value_is_a_programming_error(self):
        for dsn in (
            'db/s?sdu=abc',
            'db/s?pool_purity=x',
            'db/s?transport_connect_timeout=soon',
            'db/s?bad',
        ):
            with self.subTest(dsn=dsn), self.assertRaises(ProgrammingError):
                self._args(dsn)

    def test_both_connection_classes_apply_them(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(
                    user='u',
                    password='p',
                    dsn='db/s?sdu=32768&transport_connect_timeout=2',
                )
                self.assertEqual((conn.sdu, conn.timeout), (32768, 2000))


class ParseDsn(unittest.TestCase):
    def test_the_forms_it_reads(self):
        cases = {
            'db:1523/FREEPDB1': DsnTarget('db', 1523, 'FREEPDB1'),
            'db/FREEPDB1': DsnTarget('db', 1521, 'FREEPDB1'),
            '//db:1523/FREEPDB1': DsnTarget('db', 1523, 'FREEPDB1'),
            'db:1523': DsnTarget('db', 1523, ''),
            '//db': DsnTarget('db', 1521, ''),
            '[::1]:1523/FREEPDB1': DsnTarget('::1', 1523, 'FREEPDB1'),
            '[::1]': DsnTarget('::1', 1521, ''),
            'scott/tiger@db:1523/FREEPDB1': DsnTarget(
                'db', 1523, 'FREEPDB1', 'scott', 'tiger'
            ),
            'scott@db/FREEPDB1': DsnTarget('db', 1521, 'FREEPDB1', 'scott', None),
            # A password may hold '/' and '@'; the address cannot.
            'scott/p/w@x@db/FREEPDB1': DsnTarget(
                'db', 1521, 'FREEPDB1', 'scott', 'p/w@x'
            ),
        }
        for dsn, expected in cases.items():
            with self.subTest(dsn=dsn):
                self.assertEqual(parse_dsn(dsn), expected)

    def test_a_malformed_dsn_is_a_programming_error(self):
        for dsn in ('db:x/FREEPDB1', '@db/FREEPDB1', '[::1/FREEPDB1', ''):
            with self.subTest(dsn=dsn), self.assertRaises(ProgrammingError):
                parse_dsn(dsn)


_ADDR = '(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1523))'


class ParseDescriptor(unittest.TestCase):
    # A connect descriptor with one address (#1976). The shapes python-oracledb
    # 26.0.1 connects with, measured against 23ai, minus the ones refused below.
    def test_the_shapes_it_reads(self):
        cases = {
            f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SERVICE_NAME=svc)))': DsnTarget(
                'db', 1523, 'svc'
            ),
            # Keys are case-insensitive, whitespace is free.
            '(description = (address = (protocol = tcp)(host = db)(port = 1523))'
            ' (connect_data = (service_name = svc)))': DsnTarget('db', 1523, 'svc'),
            f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SID=ORCL)))': DsnTarget(
                'db', 1523, '', sid='ORCL'
            ),
            # No PROTOCOL means TCP, no PORT means 1521.
            '(DESCRIPTION=(ADDRESS=(HOST=db))(CONNECT_DATA=(SERVICE_NAME=svc)))': (
                DsnTarget('db', 1521, 'svc')
            ),
            f'(DESCRIPTION=(ADDRESS_LIST={_ADDR})(CONNECT_DATA=(SERVICE_NAME=svc)))': (
                DsnTarget('db', 1523, 'svc')
            ),
            f'(DESCRIPTION_LIST=(DESCRIPTION={_ADDR}(CONNECT_DATA=(SERVICE_NAME=svc))))': (
                DsnTarget('db', 1523, 'svc')
            ),
            # CID describes the client, FAILOVER means nothing with one address.
            f'(DESCRIPTION=(FAILOVER=ON){_ADDR}(CONNECT_DATA=(SERVICE_NAME=svc)'
            '(CID=(PROGRAM=app)(HOST=me)(USER=u))))': DsnTarget('db', 1523, 'svc'),
            f'scott/tiger@(DESCRIPTION={_ADDR}(CONNECT_DATA=(SERVICE_NAME=svc)))': (
                DsnTarget('db', 1523, 'svc', 'scott', 'tiger')
            ),
            # An '@' inside the descriptor is not a credentials separator.
            f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SERVICE_NAME=svc)(CID=(USER="a@b"))))': (
                DsnTarget('db', 1523, 'svc')
            ),
        }
        for dsn, expected in cases.items():
            with self.subTest(dsn=dsn):
                self.assertEqual(parse_dsn(dsn), expected)

    def test_what_seerdb_would_have_to_act_on_is_refused_by_name(self):
        cases = {
            f'(DESCRIPTION={_ADDR}(SECURITY=(SSL_SERVER_DN_MATCH=yes)))': 'SECURITY',
        }
        for dsn, named in cases.items():
            with self.subTest(dsn=dsn), self.assertRaises(NotSupportedError) as ctx:
                parse_dsn(dsn)
            self.assertIn(named, str(ctx.exception))

    def test_a_malformed_descriptor_is_a_programming_error(self):
        for dsn in (
            f'(DESCRIPTION={_ADDR}',  # unbalanced
            '(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=s)))',  # no address
            '(DESCRIPTION=(ADDRESS=(PORT=1)))',  # no host
            '(DESCRIPTION=(ADDRESS=(HOST=db)(PORT=x)))',
            f'(DESCRIPTION={_ADDR}) trailing',
            f'(ADDRESS_LIST={_ADDR})',  # not a DESCRIPTION
            '(DESCRIPTION=(ADDRESS=(HOST=db)(HTTPS_PROXY=p)))',  # a proxy, no port
        ):
            with self.subTest(dsn=dsn), self.assertRaises(ProgrammingError):
                parse_dsn(dsn)

    def test_a_sid_in_the_descriptor_replaces_a_service_passed(self):
        self.assertEqual(
            _resolve(
                f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SID=ORCL)))',
                'localhost',
                1521,
                'svc',
                '',
                'u',
                'p',
            ),
            ('db', 1523, '', 'ORCL', 'u', 'p', None, None),
        )


_TNS = """# a comment
mydb, other =
  (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = db)(PORT = 1523))
                 (CONNECT_DATA = (SERVICE_NAME = svc)))
IFILE = more.ora
"""


class ResolveAlias(unittest.TestCase):
    # A tnsnames alias without a wallet (#1976), looked up as python-oracledb
    # 26.0.1 does: config_dir, then TNS_ADMIN, then $ORACLE_HOME/network/admin.
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        with open(os.path.join(self.dir, 'tnsnames.ora'), 'w') as f:
            f.write(_TNS)
        with open(os.path.join(self.dir, 'more.ora'), 'w') as f:
            f.write(
                'inc = (DESCRIPTION=(ADDRESS=(HOST=h2)(PORT=1))(CONNECT_DATA=(SID=S)))\n'
            )
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in ('TNS_ADMIN', 'ORACLE_HOME'):
            os.environ.pop(name, None)

    def test_an_alias_from_config_dir(self):
        self.assertEqual(parse_dsn('mydb', self.dir), DsnTarget('db', 1523, 'svc'))
        # Case-insensitive, a shared definition, credentials in front.
        self.assertEqual(parse_dsn('OTHER', self.dir), DsnTarget('db', 1523, 'svc'))
        self.assertEqual(
            parse_dsn('u/p@mydb', self.dir), DsnTarget('db', 1523, 'svc', 'u', 'p')
        )

    def test_an_ifile_include_is_followed(self):
        self.assertEqual(parse_dsn('inc', self.dir), DsnTarget('h2', 1, '', sid='S'))

    def test_tns_admin_then_oracle_home(self):
        os.environ['TNS_ADMIN'] = self.dir
        self.assertEqual(parse_dsn('mydb').host, 'db')
        del os.environ['TNS_ADMIN']
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        os.makedirs(os.path.join(home, 'network', 'admin'))
        for name in ('tnsnames.ora', 'more.ora'):
            shutil.copy(
                os.path.join(self.dir, name), os.path.join(home, 'network', 'admin')
            )
        os.environ['ORACLE_HOME'] = home
        self.assertEqual(parse_dsn('mydb').host, 'db')

    def test_config_dir_comes_first_and_does_not_fall_back(self):
        os.environ['TNS_ADMIN'] = self.dir
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty)
        with self.assertRaises(NetConfigError):
            parse_dsn('mydb', empty)

    def test_the_failures_name_what_is_missing(self):
        with self.assertRaises(NetConfigError) as ctx:
            parse_dsn('mydb')
        self.assertIn('config_dir', str(ctx.exception))
        with self.assertRaises(NetConfigError) as ctx:
            parse_dsn('nope', self.dir)
        self.assertIn("'nope'", str(ctx.exception))

    def test_an_include_cycle_is_refused(self):
        with open(os.path.join(self.dir, 'more.ora'), 'w') as f:
            f.write('IFILE = tnsnames.ora\n')
        with self.assertRaises(NetConfigError):
            parse_dsn('mydb', self.dir)

    def test_the_alias_wins_and_config_dir_without_a_wallet_is_not_one(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(
                    user='pyo',
                    password='p',
                    dsn='mydb',
                    config_dir=self.dir,
                    host='other',
                    port=2,
                )
                self.assertEqual(
                    (conn.host, conn.port, conn.service_name), ('db', 1523, 'svc')
                )
                self.assertIsNone(conn.ssl)


class Tcps(unittest.TestCase):
    # tcps:// or PROTOCOL=TCPS names a TLS address (#1977); python-oracledb
    # 26.0.1 reads the prefix case-insensitively and refuses any other.
    def test_the_protocol_is_read_from_every_form(self):
        for dsn, protocol in (
            ('tcps://db:2484/svc', 'tcps'),
            ('TCPS://db:2484/svc', 'tcps'),
            ('tcp://db:1521/svc', 'tcp'),
            ('u/p@tcps://db:2484/svc', 'tcps'),
            ('db:1521/svc', 'tcp'),
            ('(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db)(PORT=2484)))', 'tcps'),
        ):
            with self.subTest(dsn=dsn):
                self.assertEqual(parse_dsn(dsn).protocol, protocol)

    def test_another_protocol_is_refused(self):
        for dsn in (
            'http://db:1521/svc',
            '(DESCRIPTION=(ADDRESS=(PROTOCOL=IPC)(HOST=db)))',
        ):
            with self.subTest(dsn=dsn), self.assertRaises(ProgrammingError):
                parse_dsn(dsn)

    def test_tcps_turns_tls_on_and_keeps_a_configuration_passed(self):
        args = ('localhost', 1521, '', '', 'u', 'p', None)
        self.assertIs(_resolve('tcps://db:2484/svc', *args)[6], True)
        self.assertIsNone(_resolve('tcp://db:1521/svc', *args)[6])
        config = {'ca_certs': '/ca.pem'}
        self.assertIs(_resolve('tcps://db/svc', *args[:-1], config)[6], config)

    def test_both_connection_classes_turn_tls_on(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(user='pyo', password='p', dsn='tcps://db:2484/svc')
                self.assertEqual((conn.host, conn.port, conn.ssl), ('db', 2484, True))


class ServerType(unittest.TestCase):
    # server_type as python-oracledb 26.0.1 reads it (#1977): dedicated, shared
    # or pooled, case-insensitive, from the argument, a :server_type suffix or
    # (SERVER=...) in CONNECT_DATA; anything else is refused (DPY-4028).
    def test_every_form_names_it(self):
        for dsn, kind in (
            ('db:1521/svc:dedicated', 'dedicated'),
            ('db/svc:POOLED', 'pooled'),
            ('tcps://db:2484/svc:shared', 'shared'),
            ('db/svc', None),
            (
                f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SERVICE_NAME=s)(SERVER=DEDICATED)))',
                'dedicated',
            ),
        ):
            with self.subTest(dsn=dsn):
                self.assertEqual(parse_dsn(dsn).server_type, kind)

    def test_an_unknown_type_is_refused(self):
        for dsn in ('db/svc:bogus', f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SERVER=x)))'):
            with self.subTest(dsn=dsn), self.assertRaises(ProgrammingError):
                parse_dsn(dsn)
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__), self.assertRaises(ProgrammingError):
                cls(server_type='bogus')

    def test_the_dsn_wins_over_the_argument(self):
        args = ('localhost', 1521, '', '', 'u', 'p', None, 'shared')
        self.assertEqual(_resolve('db/s:pooled', *args)[7], 'pooled')
        self.assertEqual(_resolve('db/s', *args)[7], 'shared')

    def test_both_connection_classes_take_it(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                self.assertEqual(cls(server_type='Dedicated').server_type, 'dedicated')
                self.assertEqual(cls(dsn='db/svc:pooled').server_type, 'pooled')
                self.assertIsNone(cls().server_type)


class HttpsProxy(unittest.TestCase):
    # An HTTPS proxy in front of a TCPS address (#1993), named as
    # python-oracledb names it: arguments, ? parameters, descriptor ADDRESS.
    def test_every_form_names_it(self):
        info = parse_dsn('tcps://db:2484/s?https_proxy=px&https_proxy_port=8080')
        self.assertEqual(
            (info.parameters['https_proxy'], info.parameters['https_proxy_port']),
            ('px', '8080'),
        )
        target = parse_dsn(
            '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db)(PORT=2484)'
            '(HTTPS_PROXY=px)(HTTPS_PROXY_PORT=8080))(CONNECT_DATA=(SERVICE_NAME=s)))'
        )
        self.assertEqual((target.https_proxy, target.https_proxy_port), ('px', 8080))
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(
                    user='u',
                    password='p',
                    dsn='tcps://db:2484/s?https_proxy=px&https_proxy_port=8080',
                )
                self.assertEqual(
                    (conn.https_proxy, conn.https_proxy_port, conn.ssl),
                    ('px', 8080, True),
                )
                conn = cls(
                    user='u',
                    password='p',
                    host='db',
                    https_proxy='px',
                    https_proxy_port=3128,
                )
                self.assertEqual(
                    (conn.https_proxy, conn.https_proxy_port), ('px', 3128)
                )

    def test_a_proxy_without_a_port_is_refused(self):
        with self.assertRaises(ProgrammingError):
            resolve_dsn_arguments('tcps://db/s?https_proxy=px', _resolve_args())


def _resolve_args() -> ConnectArguments:
    return ConnectArguments(
        'localhost',
        1521,
        '',
        '',
        'u',
        'p',
        None,
        None,
        8192,
        None,
        0,
        15000,
        None,
        None,
        0,
    )


class ResolveDsnArguments(unittest.TestCase):
    def test_the_dsn_wins_over_host_port_and_service_passed_beside_it(self):
        self.assertEqual(
            _resolve('db:1523/A', 'other', 2, 'B', '', 'u', 'p'),
            ('db', 1523, 'A', '', 'u', 'p', None, None),
        )

    def test_a_dsn_without_a_port_means_1521(self):
        self.assertEqual(
            _resolve('db/A', 'localhost', 2, '', '', 'u', 'p')[:2],
            ('db', 1521),
        )

    def test_a_dsn_without_a_service_keeps_the_one_passed(self):
        self.assertEqual(
            _resolve('db:1523', 'localhost', 1521, 'B', '', 'u', 'p'),
            ('db', 1523, 'B', '', 'u', 'p', None, None),
        )

    def test_a_service_in_the_dsn_replaces_a_sid(self):
        self.assertEqual(
            _resolve('db/A', 'localhost', 1521, '', 'ORCL', 'u', 'p')[2:4],
            ('A', ''),
        )

    def test_credentials_in_the_dsn_fill_an_absent_user(self):
        self.assertEqual(
            _resolve('scott/tiger@db/A', 'localhost', 1521, '', '', '', ''),
            ('db', 1521, 'A', '', 'scott', 'tiger', None, None),
        )

    def test_a_user_in_the_dsn_and_in_user_is_refused(self):
        with self.assertRaises(ProgrammingError):
            _resolve('scott@db/A', 'localhost', 1521, '', '', 'u', '')


class ConnectionTakesTheDsn(unittest.TestCase):
    def test_both_connection_classes_take_the_address_from_the_dsn(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(user='pyo', password='p', dsn='db.example.com:1523/FREEPDB1')
                self.assertEqual(
                    (conn.host, conn.port, conn.service_name),
                    ('db.example.com', 1523, 'FREEPDB1'),
                )

    def test_both_connection_classes_take_a_descriptor(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(
                    user='pyo',
                    password='p',
                    dsn=f'(DESCRIPTION={_ADDR}(CONNECT_DATA=(SID=ORCL)))',
                )
                self.assertEqual(
                    (conn.host, conn.port, conn.service_name, conn.sid),
                    ('db', 1523, '', 'ORCL'),
                )

    def test_a_proxy_user_in_the_dsn_is_split_as_in_user(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                conn = cls(dsn='proxy[schema]/p@db/FREEPDB1')
                self.assertEqual((conn.user, conn.proxy_user), ('proxy', 'schema'))
                self.assertEqual(conn.password, 'p')


if __name__ == '__main__':
    unittest.main()
