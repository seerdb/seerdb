# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Kerberos login over the ANO authentication service (#2378).

``connect(externalauth=True)`` offers the KERBEROS5 method in the ANO
negotiation. When the server selects it, the client and server run the
method's own rounds, each a container with the authentication service alone:

1. the client echoes the two words the server's selection carried;
2. the server names its service and host, which the client builds the
   service principal from (``oracle/<host>``), whatever host it connected to;
3. the client sends its address and the AP-REQ for that principal;
4. the server answers with its AP-REP, which completes mutual authentication;
5. the client sends the credentials to forward: none, so the user's ticket is
   never delegated to the database.

The login then skips O5LOGON: the server knows the user from the ticket.

The AP-REQ and AP-REP are the Kerberos messages themselves. A GSS-API
mechanism frames them in its own token (RFC 1964, RFC 4121), which this module
removes before sending and restores before handing a reply back. GSS-API
comes from the optional ``gssapi`` package, the ``kerberos`` extra, imported
only when a Kerberos login is made. It reads the credential cache and the
Kerberos configuration the environment names (``KRB5CCNAME``,
``KRB5_CONFIG``), as any Kerberos client does.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from seerdb.common import ano
from seerdb.common.exceptions import InterfaceError, OperationalError

# The Kerberos mechanism's object identifier, 1.2.840.113554.1.2.2, as DER.
_KRB5_MECH_OID = bytes.fromhex('06092a864886f712010202')
# A GSS-API Kerberos token's identifier, before the message it carries.
_TOK_AP_REQ = b'\x01\x00'
_TOK_AP_REP = b'\x02\x00'


def _der_length(Length: int) -> bytes:
    # A DER length: one byte below 128, else 0x80 + its byte count, big-endian.
    if Length < 0x80:
        return bytes([Length])
    Body = Length.to_bytes((Length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(Body)]) + Body


def gss_unwrap(Token: bytes, TokenId: bytes = _TOK_AP_REQ) -> bytes:
    """The Kerberos message a GSS-API Kerberos token carries: past its
    application tag, its length, the mechanism's OID and the token's id."""
    if not Token or Token[0] != 0x60:
        raise InterfaceError('not a GSS-API token')
    Pos = 2 if Token[1] < 0x80 else 2 + (Token[1] & 0x7F)
    if Token[Pos : Pos + len(_KRB5_MECH_OID)] != _KRB5_MECH_OID:
        raise InterfaceError('not a Kerberos GSS-API token')
    Pos += len(_KRB5_MECH_OID)
    if Token[Pos : Pos + 2] != TokenId:
        raise InterfaceError(
            f'unexpected GSS-API token id {Token[Pos : Pos + 2].hex()}'
        )
    return Token[Pos + 2 :]


def gss_wrap(Message: bytes, TokenId: bytes = _TOK_AP_REP) -> bytes:
    """A Kerberos message framed as a GSS-API Kerberos token."""
    Inner = _KRB5_MECH_OID + TokenId + Message
    return b'\x60' + _der_length(len(Inner)) + Inner


def _gssapi() -> Any:
    # The optional dependency, imported only for a Kerberos login.
    try:
        import gssapi
    except ImportError:
        raise InterfaceError(
            "externalauth=True needs the gssapi package: pip install 'seerdb[kerberos]'"
        ) from None
    return gssapi


def _address(Local: tuple) -> tuple[int, bytes]:
    # The client's own address, as Kerberos types it (RFC 4120).
    Address = ipaddress.ip_address(Local[0])
    if Address.version == 6:
        return (ano.KRB5_ADDRESS_INET6, Address.packed)
    return (ano.KRB5_ADDRESS_INET, Address.packed)


def _subpackets(Response: dict) -> list:
    # The authentication service's sub-packets in a decoded container.
    for Service in Response['services']:
        if Service['type'] == ano.SERVICE_AUTH:
            return Service['subpackets']
    raise OperationalError('Kerberos login: the server sent no authentication service')


def kerberos_selected(Response: dict) -> bool:
    """Whether the server's negotiation reply selected the KERBEROS5 method."""
    try:
        SubPackets = _subpackets(Response)
    except OperationalError:
        return False
    Values = [Value for _Type, Value in SubPackets]
    return ano.AUTH_STATUS_SELECTED in Values and ano.AUTH_KERBEROS5_NAME in Values


class KerberosExchange:
    """The client's side of the KERBEROS5 rounds after the negotiation.

    Fed each decoded server container in turn, :meth:`next` returns the next
    container to send. The caller sends the first one, :meth:`first`, after
    the negotiation reply, then answers each server container with
    :meth:`next` until :attr:`done`: the server answers the last one with
    nothing, and the login goes on."""

    def __init__(self, LocalAddress: tuple) -> None:
        self._local = LocalAddress
        self._context: Any = None
        self._state = 0

    @property
    def done(self) -> bool:
        """Whether the client has sent its last round: nothing follows it."""
        return self._state == 3

    def first(self, Response: dict) -> bytes:
        # The echo of the two words the server's selection carried after its
        # version: what sqlplus answers with, then a status byte of 0.
        SubPackets = _subpackets(Response)
        Words = [Value for Type, Value in SubPackets if Type == ano.SP_UB4]
        if len(Words) < 2:
            raise OperationalError(
                'Kerberos login: the server selected KERBEROS5 oddly'
            )
        self._state = 1
        return ano.auth_round(
            [
                ano.sp_version(),
                ano.sp_ub4(Words[0]),
                ano.sp_ub4(Words[1]),
                ano.sp_ub1(0),
            ]
        )

    def next(self, Response: dict) -> bytes | None:
        SubPackets = _subpackets(Response)
        if self._state == 1:
            # The server's service and host: the service principal's parts.
            Names = [Value for Type, Value in SubPackets if Type == ano.SP_STRING]
            if len(Names) < 2:
                raise OperationalError('Kerberos login: the server named no service')
            (Service, Host) = (Names[0].decode('ascii'), Names[1].decode('ascii'))
            gssapi = _gssapi()
            try:
                self._context = gssapi.SecurityContext(
                    name=gssapi.Name(
                        f'{Service}@{Host}', gssapi.NameType.hostbased_service
                    ),
                    usage='initiate',
                    mech=gssapi.MechType.kerberos,
                    flags=[gssapi.RequirementFlag.mutual_authentication],
                )
                ApReq = gss_unwrap(self._context.step())
            except gssapi.exceptions.GSSError as exc:
                raise OperationalError(
                    f'Kerberos login: no ticket for {Service}/{Host}: {exc}'
                ) from exc
            (AddressType, Address) = _address(self._local)
            self._state = 2
            return ano.auth_round(
                [
                    ano.sp_ub2(AddressType),
                    ano.sp_ub4(len(Address)),
                    ano.sp_bytes(Address),
                    ano.sp_bytes(ApReq),
                ]
            )
        if self._state == 2:
            # The AP-REP: the server proving it holds the service's key.
            Replies = [Value for Type, Value in SubPackets if Type == ano.SP_BYTES]
            if not Replies:
                raise OperationalError('Kerberos login: the server sent no AP-REP')
            gssapi = _gssapi()
            try:
                self._context.step(gss_wrap(Replies[0]))
            except gssapi.exceptions.GSSError as exc:
                raise OperationalError(
                    f'Kerberos login: the server failed mutual authentication: {exc}'
                ) from exc
            if not self._context.complete:
                raise OperationalError(
                    'Kerberos login: mutual authentication incomplete'
                )
            # No credentials to forward: the ticket stays the client's.
            self._state = 3
            return ano.auth_round([ano.sp_bytes(b'')])
        return None
