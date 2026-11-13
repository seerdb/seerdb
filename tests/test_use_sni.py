# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""use_sni (#2467): over TCPS, the service goes as the TLS server name, as
python-oracledb 26.1 sends it -- ``S8.freepdb1.V3.319``, measured against Oracle
26ai Free -- and (USE_SNI=ON) goes in the descriptor. The stdlib's hostname check
is then off, and seerdb matches the host against the certificate itself."""

import asyncio
import socket
import ssl
import threading
import unittest
from types import SimpleNamespace

import seerdb
from seerdb.client._conn_logic import _ConnectionLogic, certificate_names_host
from seerdb.client.dsn import parse_dsn
from seerdb.client.netconfig import NetConfigError, parse_descriptor
from seerdb.common.exceptions import ProgrammingError
from seerdb.common.tns import encode_dictionary_description
from tests._tls_proxy import CERT_PATH, KEY_PATH
from tests.test_tls_renegotiate import _read_connect


class TestTheServerName(unittest.TestCase):
    def _sni(self, **kw):
        values = {'use_sni': True, 'service_name': 'freepdb1', 'server_type': None}
        return _ConnectionLogic._sni(SimpleNamespace(**{**values, **kw}))  # type: ignore[arg-type]

    def test_the_service_and_the_tns_version(self):
        self.assertEqual(self._sni(), 'S8.freepdb1.V3.319')

    def test_a_server_type_adds_its_initial(self):
        self.assertEqual(self._sni(server_type='dedicated'), 'S8.freepdb1.T1.d.V3.319')
        self.assertEqual(self._sni(server_type='pooled'), 'S8.freepdb1.T1.p.V3.319')

    def test_none_without_use_sni_or_a_service(self):
        self.assertIsNone(self._sni(use_sni=False))
        self.assertIsNone(self._sni(service_name=''))


class TestTheHostMatch(unittest.TestCase):
    def test_a_dns_name_and_a_wildcard(self):
        cert = {'subjectAltName': (('DNS', 'db.example'), ('DNS', '*.pool.example'))}
        self.assertTrue(certificate_names_host(cert, 'db.example'))
        self.assertTrue(certificate_names_host(cert, 'DB.Example.'))
        self.assertTrue(certificate_names_host(cert, 'a.pool.example'))
        self.assertFalse(certificate_names_host(cert, 'a.b.pool.example'))
        self.assertFalse(certificate_names_host(cert, 'other.example'))

    def test_an_address_matches_only_an_address(self):
        cert = {'subjectAltName': (('DNS', '10.0.0.1'), ('IP Address', '10.0.0.2'))}
        self.assertTrue(certificate_names_host(cert, '10.0.0.2'))
        self.assertFalse(certificate_names_host(cert, '10.0.0.1'))

    def test_the_common_name_only_without_dns_names(self):
        cert = {'subject': ((('commonName', 'db.example'),),)}
        self.assertTrue(certificate_names_host(cert, 'db.example'))
        with_san = {**cert, 'subjectAltName': (('DNS', 'other.example'),)}
        self.assertFalse(certificate_names_host(with_san, 'db.example'))
        self.assertFalse(certificate_names_host(None, 'db.example'))


class TestTheDescriptor(unittest.TestCase):
    _DESCRIPTOR = (
        '(DESCRIPTION=(USE_SNI={})(ADDRESS=(PROTOCOL=TCPS)(HOST=db)(PORT=2484))'
        '(CONNECT_DATA=(SERVICE_NAME=svc)))'
    )

    def test_it_is_read(self):
        self.assertTrue(parse_descriptor(self._DESCRIPTOR.format('ON')).use_sni)
        self.assertTrue(parse_descriptor(self._DESCRIPTOR.format('yes')).use_sni)
        self.assertFalse(parse_descriptor(self._DESCRIPTOR.format('off')).use_sni)
        with self.assertRaises(NetConfigError):
            parse_descriptor(self._DESCRIPTOR.format('maybe'))

    def test_easy_connect_reads_it(self):
        from seerdb.client.dsn import ConnectArguments, resolve_dsn_arguments

        given = ConnectArguments(
            'h', 1521, '', '', 'u', 'p', None, None, 0, None, 0, 0, None, None, 0
        )
        args = resolve_dsn_arguments('tcps://db:2484/svc?use_sni=on', given)
        self.assertTrue(args.use_sni)
        with self.assertRaises(ProgrammingError):
            resolve_dsn_arguments('tcps://db:2484/svc?use_sni=maybe', given)
        self.assertTrue(parse_dsn(self._DESCRIPTOR.format('ON')).use_sni)

    def test_it_is_written_after_expire_time(self):
        env = {
            'user': 'u',
            'service_name': 'svc',
            'host': 'db',
            'port': 2484,
            'expire_time': 3,
            'use_sni': True,
        }
        out = encode_dictionary_description({'env': env})
        self.assertTrue(
            out.startswith(b'(DESCRIPTION=(EXPIRE_TIME=3)(USE_SNI=ON)(CONNECT_DATA=')
        )
        env['use_sni'] = False
        self.assertNotIn(b'USE_SNI', encode_dictionary_description({'env': env}))


class _NamingServer:
    """A TLS server that records the server name the client sends and its
    CONNECT, then closes, so the login fails there."""

    def __init__(self, host: str = '127.0.0.1'):
        self.name: str | None = None
        self.connect: bytes | None = None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_PATH, KEY_PATH)
        context.sni_callback = self._record
        self._context = context
        self._sock = socket.socket()
        self._sock.bind((host, 0))
        self._sock.listen(1)
        self._sock.settimeout(10)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _record(self, _sock, name, _context):
        self.name = name

    def _serve(self) -> None:
        try:
            (raw, _) = self._sock.accept()
            raw.settimeout(10)
            with self._context.wrap_socket(raw, server_side=True) as tls:
                self.connect = _read_connect(tls)
        except (OSError, EOFError):
            pass  # a client that refused the handshake sends no CONNECT
        finally:
            self._sock.close()

    def join(self) -> None:
        self._thread.join(timeout=15)


def _kwargs(port: int, **kw) -> dict:
    return {
        'user': 'u',
        'password': 'p',
        'host': '127.0.0.1',
        'port': port,
        'service_name': 'svc',
        'ssl': {'ca_certs': CERT_PATH},
        'use_sni': True,
        **kw,
    }


class TestTheHandshake(unittest.TestCase):
    def test_the_server_name_and_the_descriptor(self):
        server = _NamingServer()
        with self.assertRaises((seerdb.Error, OSError)):
            seerdb.connect(**_kwargs(server.port))
        server.join()
        self.assertEqual(server.name, 'S3.svc.V3.319')
        self.assertIn(b'(USE_SNI=ON)', server.connect or b'')

    def test_without_it_the_host_goes(self):
        # A name, not an address, so the stdlib sends it.
        server = _NamingServer()
        with self.assertRaises((seerdb.Error, OSError)):
            seerdb.connect(**_kwargs(server.port, host='localhost', use_sni=False))
        server.join()
        self.assertEqual(server.name, 'localhost')

    def test_a_host_the_certificate_does_not_name_is_refused(self):
        try:
            server = _NamingServer('127.0.0.2')
        except OSError:
            self.skipTest('127.0.0.2 is not a loopback address here')
        with self.assertRaises(ssl.SSLCertVerificationError):
            seerdb.connect(**_kwargs(server.port, host='127.0.0.2'))
        server.join()
        self.assertIsNone(server.connect)

    def test_a_given_context_checking_host_names_is_refused(self):
        context = ssl.create_default_context(cafile=CERT_PATH)
        server = _NamingServer()
        with self.assertRaises(ProgrammingError):
            seerdb.connect(**_kwargs(server.port, ssl=context))
        self.assertTrue(context.check_hostname)  # not changed
        socket.create_connection(('127.0.0.1', server.port)).close()
        server.join()


class TestTheAsyncHandshake(unittest.IsolatedAsyncioTestCase):
    async def test_the_server_name_and_the_descriptor(self):
        server = _NamingServer()
        with self.assertRaises((seerdb.Error, OSError)):
            await seerdb.connect_async(**_kwargs(server.port))
        await asyncio.get_running_loop().run_in_executor(None, server.join)
        self.assertEqual(server.name, 'S3.svc.V3.319')
        self.assertIn(b'(USE_SNI=ON)', server.connect or b'')

    async def test_a_host_the_certificate_does_not_name_is_refused(self):
        try:
            server = _NamingServer('127.0.0.2')
        except OSError:
            self.skipTest('127.0.0.2 is not a loopback address here')
        with self.assertRaises(ssl.SSLCertVerificationError):
            await seerdb.connect_async(**_kwargs(server.port, host='127.0.0.2'))
        await asyncio.get_running_loop().run_in_executor(None, server.join)
        self.assertIsNone(server.connect)


if __name__ == '__main__':
    unittest.main()
