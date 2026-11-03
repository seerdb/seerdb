# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Oracle Advanced Networking (ANO) negotiation codec (#437).

Oracle negotiates *native network encryption* and *data integrity* (the
"Advanced Security" / ANO options) right after the protocol accept and before
the PRO / DTY / auth exchange, using a self-contained packet format that is
distinct from the rest of TTC.

This module is the **sans-io codec** only: pure encode/decode of the negotiation
container, its four services, and their typed sub-packets, plus the algorithm-ID
tables. The Diffie-Hellman key exchange, the ciphers / MACs, and the wiring into
the connection handshake are separate, later phases.

Wire layout
-----------
A negotiation packet is a *container* followed by N *services*::

    container: magic(0xDEADBEEF, 4) | length(2) | version(4) | count(2) | err(1)
    service:   type(2) | subpacket_count(2) | err(4) | subpacket*

``length`` is the whole packet (``13`` container bytes + every service). Each
sub-packet is ``length(2) | type(2) | payload``; the type tags are:

    0 string   1 bytes   2 UB1   3 UB2   4 UB4   5 version   6 status

with a special UB2-array riding on the ``bytes`` tag (a ``0xDEADBEEF|3|count``
prefix). All integers are big-endian.

The layouts are protocol facts the Oracle server enforces on the wire.
"""

import struct
from dataclasses import dataclass
from secrets import token_bytes

from seerdb.common.tns_consts import VERSION_11_2_0_2, VERSION_23_26_2_0

ANO_MAGIC = 0xDEADBEEF
# The ANO protocol version advertised in the container header and echoed per
# service. The server keys its data-packet wire format off this value: it must
# match what a real client sends (0x0B200200) byte-for-byte, or the server
# completes the negotiation but then closes the connection when it decodes the
# first encrypted packet with a different (unexpected) format. Verified against
# a live 26ai server requiring AES256 (#437).

# The big-endian wire forms of the two values above. The magic and the modern
# version both appear as raw byte prefixes on the wire (a negotiation container
# leads with the magic; a modern thin client's container carries the version at
# body offset 6), so a client or server that only needs to *recognise* them wants
# the bytes, not the ints.
ANO_MAGIC_BYTES = ANO_MAGIC.to_bytes(4, 'big')  # b'\xde\xad\xbe\xef'
VERSION_BYTES = VERSION_11_2_0_2.to_bytes(4, 'big')  # b'\x0b\x20\x02\x00'

# Service types.
SERVICE_AUTH = 1
SERVICE_ENCRYPTION = 2
SERVICE_DATA_INTEGRITY = 3
SERVICE_SUPERVISOR = 4

# Sub-packet type tags.
SP_STRING = 0
SP_BYTES = 1
SP_UB1 = 2
SP_UB2 = 3
SP_UB4 = 4
SP_VERSION = 5
SP_STATUS = 6

# Supervisor service payload.
SUPERVISOR_CID = bytes([0, 0, 16, 28, 102, 236, 40, 234])
SUPERVISOR_SERVICE_LIST = [
    SERVICE_SUPERVISOR,
    SERVICE_AUTH,
    SERVICE_ENCRYPTION,
    SERVICE_DATA_INTEGRITY,
]  # the {4, 1, 2, 3} the supervisor announces
SUPERVISOR_STATUS_OK = 31

# Encryption algorithm name -> wire ID.
ENCRYPTION_ALGO_IDS = {
    'RC4_40': 1,
    'RC4_56': 8,
    'RC4_128': 10,
    'RC4_256': 6,
    'DES40C': 3,
    'DES56C': 2,
    '3DES112': 11,
    '3DES168': 12,
    'AES128': 15,
    'AES192': 16,
    'AES256': 17,
}

# Data-integrity algorithm name -> wire ID.
INTEGRITY_ALGO_IDS = {
    'MD5': 1,
    'SHA1': 3,
    'SHA512': 4,
    'SHA256': 5,
    'SHA384': 6,
}

# The container header is a fixed 13 bytes: magic|length|version|count|err.
_HEADER = struct.Struct('>IHIHB')
_HEADER_LEN = _HEADER.size  # 13
# A service header is 8 bytes: type|subpacket_count|err.
_SERVICE_HEADER = struct.Struct('>HHI')


class AnoError(Exception):
    """A malformed ANO packet, or a server-signalled negotiation error."""


# --------------------------------------------------------------------------- #
# Sub-packet encoders — each is length(2) | type(2) | payload.
# --------------------------------------------------------------------------- #


def _subpacket(Type: int, Payload: bytes) -> bytes:
    return struct.pack('>HH', len(Payload), Type) + Payload


def sp_string(Value: bytes) -> bytes:
    return _subpacket(SP_STRING, Value)


def sp_bytes(Value: bytes) -> bytes:
    return _subpacket(SP_BYTES, Value)


def sp_ub1(Value: int) -> bytes:
    return _subpacket(SP_UB1, bytes([Value & 0xFF]))


def sp_ub2(Value: int) -> bytes:
    return _subpacket(SP_UB2, struct.pack('>H', Value))


def sp_ub4(Value: int) -> bytes:
    return _subpacket(SP_UB4, struct.pack('>I', Value))


def sp_version(Value: int = VERSION_11_2_0_2) -> bytes:
    return _subpacket(SP_VERSION, struct.pack('>I', Value))


def sp_status(Value: int) -> bytes:
    return _subpacket(SP_STATUS, struct.pack('>H', Value))


def sp_ub2_array(Values: list[int]) -> bytes:
    # A UB2 array rides on the `bytes` tag: a 0xDEADBEEF | 3 | count prefix, then
    # each element as a UB2. The header length is 10 + 2*count.
    Payload = struct.pack('>IHI', ANO_MAGIC, 3, len(Values))
    Payload += b''.join(struct.pack('>H', V) for V in Values)
    return _subpacket(SP_BYTES, Payload)


def parse_ub2_array(Payload: bytes) -> list[int]:
    """Decode the payload of a UB2-array sub-packet (see :func:`sp_ub2_array`)."""
    (Magic, Tag, Count) = struct.unpack_from('>IHI', Payload, 0)
    if Magic != ANO_MAGIC or Tag != 3:
        raise AnoError('malformed ANO UB2 array')
    Ints = struct.unpack_from(f'>{Count}H', Payload, 10)
    return list(Ints)


# --------------------------------------------------------------------------- #
# Service + container assembly.
# --------------------------------------------------------------------------- #


def encode_service(ServiceType: int, SubPackets: list[bytes]) -> bytes:
    """A service header (type | count | err=0) followed by its sub-packets."""
    Body = b''.join(SubPackets)
    return _SERVICE_HEADER.pack(ServiceType, len(SubPackets), 0) + Body


def encode_ano(
    Services: list[bytes], ContainerVersion: int = VERSION_11_2_0_2
) -> bytes:
    """Wrap already-encoded services (in wire order) in a container header.

    ``ContainerVersion`` is the version stamped in the container header; it
    defaults to :data:`VERSION_11_2_0_2` (what a modern thin client sends). The classic
    sqlplus / thick-OCI null-negotiation reply stamps ``0x00000000`` here instead
    (its per-service versions stay :data:`VERSION_11_2_0_2`) — see the Mirror's
    ``build_ano_null_reply``.
    """
    Body = b''.join(Services)
    Total = _HEADER_LEN + len(Body)
    return _HEADER.pack(ANO_MAGIC, Total, ContainerVersion, len(Services), 0) + Body


# --------------------------------------------------------------------------- #
# Standard client services.
# --------------------------------------------------------------------------- #


def supervisor_service() -> bytes:
    """The supervisor service: version, control-ID, and the announced services."""
    return encode_service(
        SERVICE_SUPERVISOR,
        [
            sp_version(),
            sp_bytes(SUPERVISOR_CID),
            sp_ub2_array(SUPERVISOR_SERVICE_LIST),
        ],
    )


def encryption_service(AlgoNames: list[str]) -> bytes:
    """The encryption service: version, offered algorithm IDs, and a driver flag.

    The offered list is prefixed with the null algorithm (ID 0) — the "no
    service" fallback the server expects at the head of the list.
    """
    Ids = bytes([0]) + bytes(ENCRYPTION_ALGO_IDS[Name] for Name in AlgoNames)
    return encode_service(
        SERVICE_ENCRYPTION,
        [sp_version(), sp_bytes(Ids), sp_ub1(1)],
    )


def data_integrity_service(AlgoNames: list[str]) -> bytes:
    """The data-integrity service: version and the offered checksum algorithm IDs."""
    Ids = bytes([0]) + bytes(INTEGRITY_ALGO_IDS[Name] for Name in AlgoNames)
    return encode_service(
        SERVICE_DATA_INTEGRITY,
        [sp_version(), sp_bytes(Ids)],
    )


# Authentication service markers (no NTS/Kerberos selected by a thin client).
AUTH_MARKER = 0xE0E1
AUTH_STATUS_NONE = 0xFCFF
# The auth-service status the server returns in the classic sqlplus / thick-OCI
# (deadbeef) null-negotiation reply, in place of the thin AUTH_STATUS_NONE.
AUTH_STATUS_DEADBEEF = 0xFBFF
# The status a server answers with when it selected an offered method (#2378),
# and the Kerberos one: offered as its number and name, as sqlplus offers it.
AUTH_STATUS_SELECTED = 0xFAFF
AUTH_KERBEROS5 = 1
AUTH_KERBEROS5_NAME = b'KERBEROS5'
# A Kerberos address's type in the AP-REQ round: Kerberos's own numbers
# (RFC 4120), an IPv4 address 2 and an IPv6 one 24.
KRB5_ADDRESS_INET = 2
KRB5_ADDRESS_INET6 = 24


def auth_service(kerberos: bool = False) -> bytes:
    """The authentication service: no method offered, or with ``kerberos``
    the KERBEROS5 method (#2378)."""
    SubPackets = [sp_version(), sp_ub2(AUTH_MARKER), sp_status(AUTH_STATUS_NONE)]
    if kerberos:
        SubPackets += [sp_ub1(AUTH_KERBEROS5), sp_string(AUTH_KERBEROS5_NAME)]
    return encode_service(SERVICE_AUTH, SubPackets)


def auth_round(SubPackets: list[bytes]) -> bytes:
    """One round of an authentication method's own exchange: a container with
    the authentication service alone (#2378)."""
    return encode_ano([encode_service(SERVICE_AUTH, SubPackets)])


def dh_public_key_round(PublicKey: bytes) -> bytes:
    """The second negotiation round: the client's DH public key.

    A one-service container (data-integrity, a single ``bytes`` sub-packet) that
    the client sends after the server's response supplies the DH parameters.
    """
    return encode_ano([encode_service(SERVICE_DATA_INTEGRITY, [sp_bytes(PublicKey)])])


# --------------------------------------------------------------------------- #
# Parsing a negotiation response.
# --------------------------------------------------------------------------- #


def read_subpacket(Data: bytes, Offset: int) -> tuple[int, object, int]:
    """Read one sub-packet at ``Offset``; return ``(type, value, next_offset)``.

    Integer tags decode to ``int``; string/bytes (and the UB2-array) return the
    raw payload ``bytes`` — use :func:`parse_ub2_array` for the latter.
    """
    (Length, Type) = struct.unpack_from('>HH', Data, Offset)
    Offset += 4
    Payload = Data[Offset : Offset + Length]
    if len(Payload) != Length:
        raise AnoError('truncated ANO sub-packet')
    Offset += Length
    if Type == SP_UB1:
        return (Type, Payload[0], Offset)
    if Type in (SP_UB2, SP_STATUS):
        return (Type, struct.unpack('>H', Payload)[0], Offset)
    if Type in (SP_UB4, SP_VERSION):
        return (Type, struct.unpack('>I', Payload)[0], Offset)
    return (Type, Payload, Offset)


def decode_ano(Data: bytes) -> dict:
    """Parse a negotiation container into ``{version, services}``.

    ``services`` is a list of ``{type, error, subpackets}`` where ``subpackets``
    is a list of ``(type, value)`` from :func:`read_subpacket`. Raises
    :class:`AnoError` on a bad magic or a non-zero error flag.
    """
    if len(Data) < _HEADER_LEN:
        raise AnoError('ANO packet shorter than its header')
    (Magic, _Length, Version, Count, ErrFlag) = _HEADER.unpack_from(Data, 0)
    if Magic != ANO_MAGIC:
        raise AnoError(f'bad ANO magic 0x{Magic:08x}')
    if ErrFlag != 0:
        raise AnoError(f'ANO negotiation error flag {ErrFlag}')
    Offset = _HEADER_LEN
    Services = []
    for _ in range(Count):
        (SType, SubCount, SErr) = _SERVICE_HEADER.unpack_from(Data, Offset)
        Offset += _SERVICE_HEADER.size
        SubPackets = []
        for _ in range(SubCount):
            (Type, Value, Offset) = read_subpacket(Data, Offset)
            SubPackets.append((Type, Value))
        Services.append({'type': SType, 'error': SErr, 'subpackets': SubPackets})
    return {'version': Version, 'services': Services}


def decode_container(Payload: bytes) -> dict:
    """Locate the ANO negotiation container inside ``Payload`` and decode it.

    A negotiation packet arrives behind a leading header (the TNS/TTC bytes the
    magic follows), so seek to the :data:`ANO_MAGIC_BYTES` prefix before handing
    the container to :func:`decode_ano`. Raises :class:`ValueError` if the magic
    is absent."""
    return decode_ano(Payload[Payload.index(ANO_MAGIC_BYTES) :])


# --------------------------------------------------------------------------- #
# Diffie-Hellman key exchange (carried in the data-integrity service).
# --------------------------------------------------------------------------- #
#
# When the server's data-integrity service reply has 8 sub-packets, the tail
# carries a DH exchange: after (version, algo-id) come the generator bit-length
# and prime bit-length (UB2), then the generator, the prime, the server's public
# key, and the old IV (all `bytes`). The client picks a random private key of the
# same byte length, and computes:
#
#     public_key = generator ** private       (mod prime)   -> sent back
#     session_key = server_public ** private   (mod prime)   -> the shared secret
#     iv = session_key[32:64]
#
# The session key then folds into the crypto/MAC key (a later phase).


@dataclass
class DiffieHellman:
    """The result of the client-side DH computation."""

    # The client public key to send back, left-padded to the prime's byte length.
    public_key: bytes
    # The shared secret — the negotiation session key.
    session_key: bytes
    # The initial IV: bytes 32..64 of the session key.
    iv: bytes


def extract_dh_params(Service: dict) -> tuple[bytes, bytes, bytes, bytes]:
    """Pull ``(generator, prime, server_public, old_iv)`` from a decoded
    data-integrity service that carried a DH exchange (8 sub-packets)."""
    Sub = Service['subpackets']
    if len(Sub) < 8:
        raise AnoError('data-integrity service carries no DH exchange')
    # Sub = version, algo-id, gen-bitlen, prime-bitlen, gen, prime, server-pub, iv.
    return (Sub[4][1], Sub[5][1], Sub[6][1], Sub[7][1])


def compute_dh(
    Generator: bytes,
    Prime: bytes,
    ServerPublic: bytes,
    Private: bytes | None = None,
) -> DiffieHellman:
    """Run the client half of the DH exchange.

    ``Private`` (the client's random secret, one prime-length block) is generated
    when omitted; pass it only for deterministic tests. Keys are left-padded to
    the prime's byte length, matching what the server expects on the wire.
    """
    ByteLen = len(Prime)
    if ByteLen == 0:
        raise AnoError('empty DH prime')
    G = int.from_bytes(Generator, 'big')
    P = int.from_bytes(Prime, 'big')
    if Private is None:
        Private = token_bytes(ByteLen)
    Priv = int.from_bytes(Private, 'big')
    ServerPub = int.from_bytes(ServerPublic, 'big')
    Public = pow(G, Priv, P)
    Shared = pow(ServerPub, Priv, P)
    SessionKey = Shared.to_bytes(ByteLen, 'big')
    return DiffieHellman(
        public_key=Public.to_bytes(ByteLen, 'big'),
        session_key=SessionKey,
        iv=SessionKey[0x20:0x40],
    )


# --------------------------------------------------------------------------- #
# Server side — the DH group + negotiation response (the Mirror, #448).
# --------------------------------------------------------------------------- #
#
# A server that offers encryption emits the group (generator 2, the RFC 3526
# 2048-bit MODP prime), its own public key, and the fixed IV constant; the client
# replies with its public key and both derive the same shared secret. This is the
# inverse of the client half above.

# The 2048-bit MODP prime (RFC 3526 group 14) a real Oracle server sends.
DH_PRIME = bytes.fromhex(
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74'
    '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437'
    '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
    'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05'
    '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb'
    '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
    'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718'
    '3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff'
)
DH_GROUP_BITS = len(DH_PRIME) * 8  # 2048; both bit-length fields carry this
DH_GENERATOR = (2).to_bytes(len(DH_PRIME), 'big')  # generator 2, prime-padded
# The constant IV a real server supplies as the 8th data-integrity sub-packet;
# it keys the data-integrity MAC (not the cipher). ASCII, 20 bytes.
DH_SERVER_IV = b'foo bar baz bat quux'

# The per-service version a real server echoes in its negotiation response: the
# 26ai testbed's release. The client ignores it, but a faithful Mirror sends what
# the wire showed.
_RESPONSE_VERSION = VERSION_23_26_2_0


@dataclass
class ServerDiffieHellman:
    """The server-side DH result: the public key to advertise + the shared key
    once the client's public key arrives."""

    private: int
    public_key: bytes  # sent to the client in the round-1 response
    session_key: bytes | None = None  # filled by :meth:`derive` at round 2

    def derive(self, ClientPublic: bytes) -> bytes:
        """Compute the shared secret from the client's public key (round 2)."""
        P = int.from_bytes(DH_PRIME, 'big')
        Shared = pow(int.from_bytes(ClientPublic, 'big'), self.private, P)
        self.session_key = Shared.to_bytes(len(DH_PRIME), 'big')
        return self.session_key


def server_dh_keypair(Private: bytes | None = None) -> ServerDiffieHellman:
    """Generate the server's DH keypair over the standard group.

    ``Private`` (one prime-length block) is random when omitted; pass it only for
    deterministic tests. The shared key is derived later via
    :meth:`ServerDiffieHellman.derive` once the client's public key arrives.
    """
    ByteLen = len(DH_PRIME)
    if Private is None:
        Private = token_bytes(ByteLen)
    Priv = int.from_bytes(Private, 'big')
    Public = pow(
        int.from_bytes(DH_GENERATOR, 'big'), Priv, int.from_bytes(DH_PRIME, 'big')
    )
    return ServerDiffieHellman(private=Priv, public_key=Public.to_bytes(ByteLen, 'big'))


def encryption_service_response(AlgoId: int) -> bytes:
    """The server's encryption-service reply: version + the selected algorithm."""
    return encode_service(
        SERVICE_ENCRYPTION, [sp_version(_RESPONSE_VERSION), sp_ub1(AlgoId)]
    )


def data_integrity_service_response(AlgoId: int, ServerPublic: bytes) -> bytes:
    """The server's data-integrity reply carrying the DH exchange (8 sub-packets):
    version, selected algorithm, the two bit-length fields, then generator, prime,
    the server public key, and the IV constant."""
    return encode_service(
        SERVICE_DATA_INTEGRITY,
        [
            sp_version(_RESPONSE_VERSION),
            sp_ub1(AlgoId),
            sp_ub2(DH_GROUP_BITS),
            sp_ub2(DH_GROUP_BITS),
            sp_bytes(DH_GENERATOR),
            sp_bytes(DH_PRIME),
            sp_bytes(ServerPublic),
            sp_bytes(DH_SERVER_IV),
        ],
    )


def supervisor_service_response() -> bytes:
    """The server's supervisor reply: version, an OK status, and the service
    list (mirrors what a real 11g/26ai server sends)."""
    return encode_service(
        SERVICE_SUPERVISOR,
        [
            sp_version(_RESPONSE_VERSION),
            sp_status(SUPERVISOR_STATUS_OK),
            sp_ub2_array([SERVICE_SUPERVISOR, SERVICE_AUTH]),
        ],
    )


def auth_service_response() -> bytes:
    """The server's authentication reply: version + the no-method status."""
    return encode_service(
        SERVICE_AUTH, [sp_version(_RESPONSE_VERSION), sp_status(AUTH_STATUS_NONE)]
    )


def encode_ano_response(EncId: int, IntId: int, ServerPublic: bytes) -> bytes:
    """Assemble the full server negotiation response advertising the selected
    encryption + data-integrity algorithms and the DH exchange (#448)."""
    return encode_ano(
        [
            supervisor_service_response(),
            auth_service_response(),
            encryption_service_response(EncId),
            data_integrity_service_response(IntId, ServerPublic),
        ]
    )


def offered_algorithm_ids(Request: dict, ServiceType: int) -> list[int]:
    """The algorithm IDs a client offered for a service in its round-1 request
    (the service's second sub-packet is the id list, null-prefixed)."""
    ByType = {S['type']: S for S in Request['services']}
    Service = ByType.get(ServiceType)
    if Service is None or len(Service['subpackets']) < 2:
        return []
    (_Type, Ids) = Service['subpackets'][1]
    return list(Ids) if isinstance(Ids, bytes | bytearray) else []


def client_public_key(Round2: dict) -> bytes:
    """Pull the client's DH public key from a decoded round-2 container (a lone
    data-integrity service whose first sub-packet is the key bytes)."""
    ByType = {S['type']: S for S in Round2['services']}
    Service = ByType.get(SERVICE_DATA_INTEGRITY)
    if Service is None or not Service['subpackets']:
        raise AnoError('round-2 container carries no client public key')
    (_Type, Key) = Service['subpackets'][0]
    if not isinstance(Key, bytes | bytearray):
        raise AnoError('client public key is not a byte string')
    return bytes(Key)
