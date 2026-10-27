"""Cipher implementations for AES, DES and RC4, with encrypt-then-MAC.

* ``AES`` / ``DES`` are block ciphers and support the non-ECB modes of
  operation CBC, CFB, OFB and CTR. Stored data uses CTR for both
  (:data:`~core.crypto.constants.MODE_FOR`); the other modes exist for the
  mode comparison in the benchmark.
* ``RC4`` is a stream cipher, so a mode of operation does not apply.

Only CBC requires PKCS#7 padding; CFB, OFB and CTR turn the block cipher into
a stream cipher and operate on the plaintext length directly. CFB is run with
full-block segments (CFB-128 for AES, CFB-64 for DES) instead of
PyCryptodome's 8-bit default, which was measured to be ~10x slower.

None of the three ciphers detects modification of the ciphertext, and in
CTR/OFB/CFB/RC4 a wrong key just yields garbage. Every ciphertext therefore
carries an HMAC-SHA256 tag over its parameters and bytes (encrypt-then-MAC),
and :func:`decrypt` verifies the tag *before* decrypting. That is what lets the
application guarantee the data comes back intact.

Adapted from https://github.com/ukassu/lab-session-information-security
(``crypto_tool.py``); the key sizes and the CBC / PKCS#7 paths follow that
reference, while CFB, OFB, CTR and the MAC are added here.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Final

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util import Counter

from .constants import MODE_FOR, SUPPORTED_ALGORITHMS, SUPPORTED_MODES
from .keys import SALT_SIZE, derive_keys, new_salt

#: Key length in bytes per algorithm (AES-256 / DES-64 / RC4-256).
_KEY_SIZE: Final = {"AES": 32, "DES": 8, "RC4": 32}

_BLOCK_SIZE: Final = {"AES": AES.block_size, "DES": DES.block_size}
_IV_SIZE: Final = {"AES": AES.block_size, "DES": DES.block_size}

#: Length of the HMAC-SHA256 tag stored with every ciphertext.
TAG_SIZE: Final = 32

#: Format version bound into the MAC, so a future format cannot be confused
#: with this one.
_MAC_VERSION: Final = b"cipher-safe/v1"


class IntegrityError(ValueError):
    """The ciphertext, its parameters or the password do not match the tag."""


@dataclass(frozen=True)
class EncryptionResult:
    """The output of a single encryption operation."""

    algorithm: str
    mode: str
    salt: bytes
    iv: bytes | None
    ciphertext: bytes
    tag: bytes
    plaintext_size: int
    key_derivation_ms: float
    cipher_ms: float
    mac_ms: float

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms + self.mac_ms


@dataclass(frozen=True)
class DecryptionResult:
    """The output of a single decryption operation."""

    plaintext: bytes
    key_derivation_ms: float
    cipher_ms: float
    mac_ms: float

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms + self.mac_ms


def _normalise(algorithm: str, mode: str | None) -> tuple[str, str]:
    algorithm = algorithm.upper()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if algorithm == "RC4":
        # A stream cipher has no block mode of operation.
        return algorithm, ""
    mode = (mode or MODE_FOR[algorithm]).upper()
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode of operation: {mode}")
    return algorithm, mode


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid padding.")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding.")
    return data[:-padding]


def _block_cipher(algorithm: str, key: bytes, mode: str, iv: bytes):
    module = AES if algorithm == "AES" else DES
    bits = _BLOCK_SIZE[algorithm] * 8
    if mode == "CBC":
        return module.new(key, module.MODE_CBC, iv=iv)
    if mode == "CFB":
        return module.new(key, module.MODE_CFB, iv=iv, segment_size=bits)
    if mode == "OFB":
        return module.new(key, module.MODE_OFB, iv=iv)
    if mode == "CTR":
        counter = Counter.new(bits, initial_value=int.from_bytes(iv, "big"))
        return module.new(key, module.MODE_CTR, counter=counter)
    raise ValueError(f"Unsupported mode of operation: {mode}")


def _mac(mac_key: bytes, algorithm: str, mode: str, salt: bytes, iv: bytes | None, ciphertext: bytes) -> bytes:
    """HMAC-SHA256 over every value the decryption depends on.

    Algorithm and mode are bound in so a ciphertext cannot be relabelled; the
    salt and IV have lengths fixed by the algorithm, so the concatenation is
    unambiguous.
    """

    header = b"|".join([_MAC_VERSION, algorithm.encode(), (mode or "-").encode()])
    return hmac.new(mac_key, header + b"|" + salt + (iv or b"") + ciphertext, hashlib.sha256).digest()


def encrypt(
    data: bytes,
    password: str,
    algorithm: str = "AES",
    mode: str | None = None,
) -> EncryptionResult:
    """Encrypt ``data`` and return the ciphertext, its MAC tag and the
    parameters needed to decrypt it (salt, IV), together with timings.

    ``mode`` defaults to the application's chosen mode for ``algorithm``.
    """

    algorithm, mode = _normalise(algorithm, mode)
    salt = new_salt()

    start = time.perf_counter()
    key, mac_key = derive_keys(password, salt, _KEY_SIZE[algorithm])
    key_derivation_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    iv: bytes | None = None
    if algorithm == "RC4":
        ciphertext = ARC4.new(key).encrypt(data)
    else:
        iv = secrets.token_bytes(_IV_SIZE[algorithm])
        cipher = _block_cipher(algorithm, key, mode, iv)
        payload = _pkcs7_pad(data, _BLOCK_SIZE[algorithm]) if mode == "CBC" else data
        ciphertext = cipher.encrypt(payload)
    cipher_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    tag = _mac(mac_key, algorithm, mode, salt, iv, ciphertext)
    mac_ms = (time.perf_counter() - start) * 1000

    return EncryptionResult(
        algorithm=algorithm,
        mode=mode,
        salt=salt,
        iv=iv,
        ciphertext=ciphertext,
        tag=tag,
        plaintext_size=len(data),
        key_derivation_ms=key_derivation_ms,
        cipher_ms=cipher_ms,
        mac_ms=mac_ms,
    )


def decrypt(
    ciphertext: bytes,
    password: str,
    algorithm: str,
    salt: bytes,
    iv: bytes | None,
    mode: str | None,
    tag: bytes,
) -> DecryptionResult:
    """Verify the tag, then reverse :func:`encrypt`.

    Raises :class:`IntegrityError` if the tag does not match, which covers a
    wrong password as well as any modified byte of ciphertext, salt, IV,
    algorithm or mode.
    """

    algorithm, mode = _normalise(algorithm, mode)
    if len(salt) != SALT_SIZE:
        raise IntegrityError("Invalid salt size.")
    if algorithm != "RC4" and (not iv or len(iv) != _IV_SIZE[algorithm]):
        raise IntegrityError("Missing or invalid IV for block cipher.")
    if not tag or len(tag) != TAG_SIZE:
        raise IntegrityError("Missing or invalid integrity tag.")

    start = time.perf_counter()
    key, mac_key = derive_keys(password, salt, _KEY_SIZE[algorithm])
    key_derivation_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    expected = _mac(mac_key, algorithm, mode, salt, iv, ciphertext)
    if not hmac.compare_digest(expected, tag):
        raise IntegrityError("Wrong password or tampered ciphertext.")
    mac_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    try:
        if algorithm == "RC4":
            plaintext = ARC4.new(key).decrypt(ciphertext)
        else:
            cipher = _block_cipher(algorithm, key, mode, iv)
            plaintext = cipher.decrypt(ciphertext)
            if mode == "CBC":
                plaintext = _pkcs7_unpad(plaintext, _BLOCK_SIZE[algorithm])
    except ValueError as exc:  # pragma: no cover - unreachable once the tag verifies
        raise IntegrityError("Corrupted ciphertext.") from exc
    cipher_ms = (time.perf_counter() - start) * 1000

    return DecryptionResult(
        plaintext=plaintext,
        key_derivation_ms=key_derivation_ms,
        cipher_ms=cipher_ms,
        mac_ms=mac_ms,
    )
