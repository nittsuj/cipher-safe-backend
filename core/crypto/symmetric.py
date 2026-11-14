"""AES-256-GCM with raw random keys, for records shared with another user.

The rest of :mod:`core.crypto` derives every key from a password. A shared
item instead gets its own **random** 32-byte key, so the key can be handed to
the requester (encrypted with their RSA public key) without revealing anyone's
password, and a leaked key exposes only that one item.

Associated data binds a ciphertext to its context (request, item, kind), so a
copy can't be swapped for another one encrypted under the same key.

Uses AES-GCM from the ``cryptography`` package. No Django imports.
"""

from __future__ import annotations

import secrets
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .algorithms import IntegrityError

#: AES-256 key length.
SYMMETRIC_KEY_SIZE = 32

#: AES-GCM nonce length.
SYMMETRIC_NONCE_SIZE = 12


class SealedData(NamedTuple):
    """AES-GCM output: the nonce and the ciphertext with its 16-byte tag appended."""

    nonce: bytes
    ciphertext: bytes


def new_symmetric_key() -> bytes:
    """Return a fresh random AES-256 key."""

    return secrets.token_bytes(SYMMETRIC_KEY_SIZE)


def _check_key(key: bytes) -> None:
    if len(key) != SYMMETRIC_KEY_SIZE:
        raise ValueError("Key must be 32 bytes (AES-256).")


def encrypt_with_key(data: bytes, key: bytes, aad: bytes) -> SealedData:
    """Encrypt ``data`` under ``key`` with a fresh random nonce."""

    _check_key(key)
    nonce = secrets.token_bytes(SYMMETRIC_NONCE_SIZE)
    return SealedData(nonce, AESGCM(key).encrypt(nonce, data, aad))


def decrypt_with_key(sealed: SealedData, key: bytes, aad: bytes) -> bytes:
    """Decrypt and verify. Raises :class:`IntegrityError` for a wrong key, a
    modified ciphertext or associated data that does not match."""

    _check_key(key)
    if len(sealed.nonce) != SYMMETRIC_NONCE_SIZE:
        raise IntegrityError("Invalid nonce size.")
    try:
        return AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityError("The data could not be decrypted with this key.") from exc
