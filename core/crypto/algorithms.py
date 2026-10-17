"""Cipher implementations for AES, DES and RC4.

* ``AES`` / ``DES`` are block ciphers and support the non-ECB modes of
  operation CBC, CFB, OFB and CTR.
* ``RC4`` is a stream cipher, so a mode of operation does not apply.

Only CBC requires PKCS#7 padding; CFB, OFB and CTR turn the block cipher into
a stream cipher and operate on the plaintext length directly.

Adapted from https://github.com/ukassu/lab-session-information-security
(``crypto_tool.py``); the key sizes and the CBC / PKCS#7 paths follow that
reference, while CFB, OFB and CTR are added here.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Final

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util import Counter

from .constants import DEFAULT_MODE, SUPPORTED_ALGORITHMS, SUPPORTED_MODES
from .keys import derive_key, new_salt

#: Key length in bytes per algorithm (AES-256 / DES-64 / RC4-256).
_KEY_SIZE: Final = {"AES": 32, "DES": 8, "RC4": 32}

_BLOCK_SIZE: Final = {"AES": AES.block_size, "DES": DES.block_size}
_IV_SIZE: Final = {"AES": AES.block_size, "DES": DES.block_size}


@dataclass(frozen=True)
class EncryptionResult:
    """The output of a single encryption operation."""

    algorithm: str
    mode: str
    salt: bytes
    iv: bytes | None
    ciphertext: bytes
    plaintext_size: int
    key_derivation_ms: float
    cipher_ms: float

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms


@dataclass(frozen=True)
class DecryptionResult:
    """The output of a single decryption operation."""

    plaintext: bytes
    key_derivation_ms: float
    cipher_ms: float

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms


def _normalise(algorithm: str, mode: str) -> tuple[str, str]:
    algorithm = algorithm.upper()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if algorithm == "RC4":
        # A stream cipher has no block mode of operation.
        return algorithm, ""
    mode = mode.upper()
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
    if mode == "CBC":
        return module.new(key, module.MODE_CBC, iv=iv)
    if mode == "CFB":
        return module.new(key, module.MODE_CFB, iv=iv)
    if mode == "OFB":
        return module.new(key, module.MODE_OFB, iv=iv)
    if mode == "CTR":
        bits = _BLOCK_SIZE[algorithm] * 8
        counter = Counter.new(bits, initial_value=int.from_bytes(iv, "big"))
        return module.new(key, module.MODE_CTR, counter=counter)
    raise ValueError(f"Unsupported mode of operation: {mode}")


def encrypt(
    data: bytes,
    password: str,
    algorithm: str = "AES",
    mode: str = DEFAULT_MODE,
) -> EncryptionResult:
    """Encrypt ``data`` and return the ciphertext plus the parameters needed
    to decrypt it (salt, IV) together with timing measurements."""

    algorithm, mode = _normalise(algorithm, mode)
    salt = new_salt()

    start = time.perf_counter()
    key = derive_key(password, salt, _KEY_SIZE[algorithm])
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

    return EncryptionResult(
        algorithm=algorithm,
        mode=mode,
        salt=salt,
        iv=iv,
        ciphertext=ciphertext,
        plaintext_size=len(data),
        key_derivation_ms=key_derivation_ms,
        cipher_ms=cipher_ms,
    )


def decrypt(
    ciphertext: bytes,
    password: str,
    algorithm: str,
    salt: bytes,
    iv: bytes | None = None,
    mode: str = DEFAULT_MODE,
) -> DecryptionResult:
    """Reverse :func:`encrypt`."""

    algorithm, mode = _normalise(algorithm, mode)
    if algorithm != "RC4" and not iv:
        raise ValueError("Missing IV for block cipher.")
    if iv is not None and algorithm != "RC4" and len(iv) != _IV_SIZE[algorithm]:
        raise ValueError("Invalid IV size.")

    start = time.perf_counter()
    key = derive_key(password, salt, _KEY_SIZE[algorithm])
    key_derivation_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    try:
        if algorithm == "RC4":
            plaintext = ARC4.new(key).decrypt(ciphertext)
        else:
            cipher = _block_cipher(algorithm, key, mode, iv)
            plaintext = cipher.decrypt(ciphertext)
            if mode == "CBC":
                plaintext = _pkcs7_unpad(plaintext, _BLOCK_SIZE[algorithm])
    except ValueError as exc:
        raise ValueError("Wrong password or corrupted ciphertext.") from exc
    cipher_ms = (time.perf_counter() - start) * 1000

    return DecryptionResult(
        plaintext=plaintext,
        key_derivation_ms=key_derivation_ms,
        cipher_ms=cipher_ms,
    )
