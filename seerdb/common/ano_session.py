# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Bridge from the ANO negotiation result to the session cipher + MAC (#437).

After the negotiation (:mod:`seerdb.common.ano`) selects an encryption and a
data-integrity algorithm and the DH exchange yields a shared secret, these
helpers instantiate the per-session :class:`~seerdb.common.ano_cipher.AnoAESCipher`
and :class:`~seerdb.common.ano_mac.AnoMac`.

Key material (validated byte-for-byte against a live go-ora session on a 26ai
server requiring AES256 + SHA256):
  * AES key   = ``shared_secret[:keysize]`` (16/24/32 for AES-128/192/256),
  * cipher IV = **16 zero bytes** (go-ora passes a nil IV; the DH IV is *not*
    used by the cipher),
  * MAC key   = the full ``shared_secret`` (the MAC takes its own 5-byte prefix),
  * MAC IV    = the **server-supplied DH IV** — the constant
    ``b"foo bar baz bat quux"`` from the negotiation's 8th data-integrity
    sub-packet.

No auth-key folding happens on the wire: the trailing per-packet "key-fold" flag
byte is always ``0``. The AES ciphers, the SHA-2 MACs and the legacy MD5 and
SHA1 MACs (#2865) are wired up; the legacy RC4/DES ciphers are deferred (see
the cipher/MAC modules).
"""

from seerdb.common.ano import ENCRYPTION_ALGO_IDS, INTEGRITY_ALGO_IDS
from seerdb.common.ano_cipher import AnoAESCipher, AnoCipherError
from seerdb.common.ano_mac import LEGACY_ALGORITHMS, AnoLegacyMac, AnoMac, AnoMacError

# Selected encryption algorithm ID -> AES key length.
_AES_KEYSIZE = {
    ENCRYPTION_ALGO_IDS['AES128']: 16,
    ENCRYPTION_ALGO_IDS['AES192']: 24,
    ENCRYPTION_ALGO_IDS['AES256']: 32,
}
# Selected data-integrity algorithm ID -> hashlib name.
_INTEGRITY_NAME = {
    INTEGRITY_ALGO_IDS['SHA256']: 'SHA256',
    INTEGRITY_ALGO_IDS['SHA384']: 'SHA384',
    INTEGRITY_ALGO_IDS['SHA512']: 'SHA512',
    INTEGRITY_ALGO_IDS['MD5']: 'MD5',
    INTEGRITY_ALGO_IDS['SHA1']: 'SHA1',
}

_ZERO_IV = bytes(16)  # the AES-CBC cipher runs with an all-zero IV


def make_cipher(AlgoId: int, SharedSecret: bytes) -> AnoAESCipher | None:
    """Build the session cipher for the negotiated encryption algorithm.

    The AES key is the DH shared secret's leading ``keysize`` bytes and the IV is
    all zeros. Returns ``None`` when no encryption was selected (algorithm 0).
    Raises for a non-AES algorithm (RC4/DES are not implemented).
    """
    if AlgoId == 0:
        return None
    KeySize = _AES_KEYSIZE.get(AlgoId)
    if KeySize is None:
        raise AnoCipherError(f'unsupported encryption algorithm id {AlgoId} (AES only)')
    return AnoAESCipher(SharedSecret[:KeySize], _ZERO_IV)


def make_mac(
    AlgoId: int, SharedSecret: bytes, ServerIv: bytes, ClientSide: bool = True
) -> AnoMac | AnoLegacyMac | None:
    """Build the session MAC for the negotiated data-integrity algorithm.

    Keys off the DH shared secret and the server-supplied DH IV (``ServerIv``).
    Returns ``None`` when no integrity was selected (algorithm 0). MD5 and SHA1
    run the RC4-keystream MAC, the SHA-2 checksums the AES-keystream one (#2865).
    """
    if AlgoId == 0:
        return None
    Name = _INTEGRITY_NAME.get(AlgoId)
    if Name is None:
        raise AnoMacError(f'unsupported integrity algorithm id {AlgoId}')
    if Name in LEGACY_ALGORITHMS:
        return AnoLegacyMac(SharedSecret, ServerIv, Name, ClientSide=ClientSide)
    return AnoMac(SharedSecret, ServerIv, Name, ClientSide=ClientSide)


class AnoChannel:
    """The active per-packet encryption + data-integrity applied after nego.

    Mirrors go-ora's ``newDataPacket`` / ``newDataPacketFromData`` for a modern
    server. Each outbound TTC data payload becomes::

        AES-CBC( plaintext || MAC(plaintext) ) || 0x00

    i.e. the SHA-2 MAC (when a checksum algorithm was negotiated) is computed
    over the plaintext and appended, the whole is AES-CBC encrypted, and a single
    trailing "key-fold" flag byte — always ``0``: this server folds no auth key
    into the crypto key — is appended. Receive reverses it: strip the flag byte,
    decrypt, then verify + strip the MAC.

    Every field below is validated byte-for-byte against a real go-ora session on
    a 26ai server requiring AES256 + SHA256 (#437):

      * the AES key is the DH shared secret's first 16/24/32 bytes and the cipher
        IV is **all zeros** (go-ora's ``OracleNetworkCBCEncrypter`` passes a nil
        IV → 16 zero bytes; the DH IV is not used by the cipher);
      * the MAC keys off the shared secret + the **server-supplied DH IV** — the
        constant ``b"foo bar baz bat quux"`` the server sends as the negotiation's
        8th data-integrity sub-packet.
    """

    def __init__(
        self,
        EncAlgoId: int,
        IntegrityAlgoId: int,
        SharedSecret: bytes,
        ServerIv: bytes,
        ClientSide: bool = True,
    ):
        # ``ClientSide`` swaps the MAC send/recv keystreams so a server channel
        # (``ClientSide=False``) inter-operates with a client one — its send
        # keystream equals the peer's receive keystream. The cipher is symmetric.
        self._enc_id = EncAlgoId
        self._mac_id = IntegrityAlgoId
        self._cipher: AnoAESCipher | None = make_cipher(EncAlgoId, SharedSecret)
        self._mac: AnoMac | AnoLegacyMac | None = make_mac(
            IntegrityAlgoId, SharedSecret, ServerIv, ClientSide=ClientSide
        )

    @property
    def active(self) -> bool:
        return self._cipher is not None

    def rederive(self) -> None:
        """Re-derive the data-integrity keystreams after a break/reset (#1345).

        The cipher needs nothing; only the MAC's keystreams are re-keyed.
        """
        if self._mac is not None:
            self._mac.rederive()

    def wrap(self, Data: bytes) -> bytes:
        if self._cipher is None:
            return Data
        if self._mac is not None:
            Data = self._mac.sign(Data)  # append MAC before encrypting
        return self._cipher.encrypt(Data) + b'\x00'  # trailing key-fold flag

    def unwrap(self, Data: bytes) -> bytes:
        if self._cipher is None:
            return Data
        Plain = self._cipher.decrypt(Data[:-1])  # drop the key-fold flag byte
        if self._mac is not None:
            Plain = self._mac.validate(Plain)
        return Plain
