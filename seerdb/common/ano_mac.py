# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Oracle native data integrity — the AES-keystream MAC (#437, phase 4).

When the ANO negotiation selects a SHA-2 data-integrity algorithm, each TTC data
packet carries a MAC computed by this construction. It is *not* a standard HMAC: a keyed AES-CBC
"keystream" produces one hash-sized block per packet, and the packet MAC is
``SHA(payload || keystream_block)``. The keystream is stateful — it advances one
block per packet — so identical payloads get different MACs.

Keying (from the DH shared secret + the server-supplied DH IV):

  * ``aes_key = secret[:5] || 0xFF`` (zero-filled to 16 bytes) drives an AES-CBC
    pass over a 32-byte zero buffer; the result seeds a base key (first 16 bytes)
    and base IV (next 16),
  * the per-direction keystream key is that base key with byte **5** set to
    **90** for the sender and **180** for the receiver — swapped between client
    and server, so each side's *send* keystream equals the peer's *receive*
    keystream.

The 5-byte key prefix and the byte-5 tag position match go-ora's
``OracleNetworkHash2`` exactly (both the legacy RC4 hash and this SHA-2 hash use
a 5-byte prefix; an earlier 15-byte guess here was wrong).

The legacy MD5 and SHA1 checksums (#2865) are the same construction over an RC4
keystream, :class:`AnoLegacyMac`. The keystream generator is RC4 keyed with five
bytes of the secret, ``0xFF`` and the server's DH IV. Each re-derivation draws
five bytes from it, and the per-direction keystreams are RC4 keyed with those
five bytes and the tag 90 or 180, as above. Each packet's MAC is
``hash(payload || the next hash-sized run of the keystream)``.
"""

import hashlib

from Crypto.Cipher import AES, ARC4

_HASHES = {
    'SHA256': hashlib.sha256,
    'SHA384': hashlib.sha384,
    'SHA512': hashlib.sha512,
}
_LEGACY_HASHES = {
    'MD5': hashlib.md5,
    'SHA1': hashlib.sha1,
}
LEGACY_ALGORITHMS = frozenset(_LEGACY_HASHES)

_SEND_TAG = 90
_RECV_TAG = 180


class AnoMacError(Exception):
    """A data-integrity check failed, or the MAC was misconfigured."""


class AnoMac:
    """Oracle native data-integrity MAC (AES-keystream, SHA-2)."""

    def __init__(
        self,
        Key: bytes,
        Iv: bytes,
        Algorithm: str,
        ClientSide: bool = True,
    ):
        if Algorithm not in _HASHES:
            raise AnoMacError(
                f'unsupported integrity algorithm {Algorithm!r} '
                f'(supported: {", ".join(sorted(_HASHES))})'
            )
        self._hash = _HASHES[Algorithm]
        self._size = self._hash().digest_size  # 32 / 48 / 64 — block-aligned
        self._key_size = 5  # go-ora's OracleNetworkHash2 keys off the first 5 bytes
        (self._send_tag, self._recv_tag) = (
            (_SEND_TAG, _RECV_TAG) if ClientSide else (_RECV_TAG, _SEND_TAG)
        )

        # aes_key = key[:keysize] | 0xFF, zero-filled to 16 bytes, over the
        # server's DH IV: the seed generator, which re-derivation re-keys.
        AesKey = bytearray(16)
        AesKey[: self._key_size] = Key[: self._key_size]
        AesKey[self._key_size] = 0xFF
        self._seed_gen = AES.new(bytes(AesKey), AES.MODE_CBC, Iv[:16])
        self._seed = bytes(32)
        # The evolving keystream buffers (one hash-sized block). A re-derivation
        # re-keys the ciphers that advance them but leaves them as they are.
        self._send_buf = bytes(self._size)
        self._recv_buf = bytes(self._size)
        self.rederive()

    def rederive(self) -> None:
        """Derive the keystream ciphers afresh (#1345).

        One AES-CBC pass of the seed generator over the 32-byte seed gives the
        next seed; its first 16 bytes key and its last 16 bytes seed both the
        next seed generator and the two per-direction keystream ciphers. At
        channel creation the seed is 32 zero bytes, so the first call is the
        original derivation. The server runs it again after every break/reset
        exchange -- an in-band error report -- so a client that did not
        failed the MAC of the error that followed, and lost the session.
        """
        self._seed = self._seed_gen.encrypt(self._seed)
        BaseKey = bytearray(self._seed[:16])
        BaseIv = self._seed[16:32]
        self._seed_gen = AES.new(bytes(BaseKey), AES.MODE_CBC, BaseIv)
        self._send_cipher = self._keystream_cipher(
            BaseKey, self._key_size, self._send_tag, BaseIv
        )
        self._recv_cipher = self._keystream_cipher(
            BaseKey, self._key_size, self._recv_tag, BaseIv
        )

    @staticmethod
    def _keystream_cipher(BaseKey: bytearray, KeySize: int, Tag: int, Iv: bytes):
        Key = bytearray(BaseKey)
        Key[KeySize] = Tag
        return AES.new(bytes(Key), AES.MODE_CBC, Iv)

    def compute(self, Payload: bytes) -> bytes:
        # Advance the send keystream one block, then MAC (payload || block).
        self._send_buf = self._send_cipher.encrypt(self._send_buf)
        return self._hash(Payload + self._send_buf).digest()

    def sign(self, Payload: bytes) -> bytes:
        """Return ``Payload`` with its MAC appended."""
        return Payload + self.compute(Payload)

    def validate(self, Data: bytes) -> bytes:
        """Verify a ``payload || mac`` buffer; return the payload or raise."""
        if len(Data) <= self._size:
            raise AnoMacError('data shorter than its MAC')
        Payload = Data[: -self._size]
        Received = Data[-self._size :]
        self._recv_buf = self._recv_cipher.encrypt(self._recv_buf)
        Expected = self._hash(Payload + self._recv_buf).digest()
        if Received != Expected:
            raise AnoMacError('data integrity check failed')
        return Payload


class AnoLegacyMac:
    """Oracle native data-integrity MAC for MD5 and SHA1 (RC4 keystream, #2865).

    Same interface as :class:`AnoMac`. ``Key`` is the DH shared secret and ``Iv``
    the server's DH IV; the keystream generator is keyed with the secret's last
    five bytes, ``0xFF`` and the IV.
    """

    _KEY_SIZE = 5

    def __init__(
        self,
        Key: bytes,
        Iv: bytes,
        Algorithm: str,
        ClientSide: bool = True,
    ):
        if Algorithm not in _LEGACY_HASHES:
            raise AnoMacError(
                f'unsupported legacy integrity algorithm {Algorithm!r} '
                f'(supported: {", ".join(sorted(_LEGACY_HASHES))})'
            )
        self._hash = _LEGACY_HASHES[Algorithm]
        self._size = self._hash().digest_size  # 16 / 20
        (self._send_tag, self._recv_tag) = (
            (_SEND_TAG, _RECV_TAG) if ClientSide else (_RECV_TAG, _SEND_TAG)
        )
        Seed = Key[-self._KEY_SIZE :] + b'\xff' + bytes(Iv)
        self._seed_gen = ARC4.new(Seed)
        self.rederive()

    def rederive(self) -> None:
        """Draw the next five bytes from the generator and key both
        per-direction keystreams from them (#1345)."""
        Base = self._seed_gen.encrypt(bytes(self._KEY_SIZE))
        self._send_stream = ARC4.new(Base + bytes([self._send_tag]))
        self._recv_stream = ARC4.new(Base + bytes([self._recv_tag]))

    def compute(self, Payload: bytes) -> bytes:
        Block = self._send_stream.encrypt(bytes(self._size))
        return self._hash(Payload + Block).digest()

    def sign(self, Payload: bytes) -> bytes:
        """Return ``Payload`` with its MAC appended."""
        return Payload + self.compute(Payload)

    def validate(self, Data: bytes) -> bytes:
        """Verify a ``payload || mac`` buffer; return the payload or raise."""
        if len(Data) <= self._size:
            raise AnoMacError('data shorter than its MAC')
        Payload = Data[: -self._size]
        Received = Data[-self._size :]
        Block = self._recv_stream.encrypt(bytes(self._size))
        if self._hash(Payload + Block).digest() != Received:
            raise AnoMacError('data integrity check failed')
        return Payload
