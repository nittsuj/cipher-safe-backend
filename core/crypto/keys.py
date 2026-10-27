"""Password-based key derivation.

Keys are always derived from the user's password with PBKDF2-HMAC-SHA256.
Each encryption uses a fresh random salt, so the same password never produces
the same key twice.

One PBKDF2 call yields both the cipher key and a separate 32-byte HMAC key
(``derive_keys``), so adding the integrity check costs no extra derivation.
Adapted from https://github.com/ukassu/lab-session-information-security
(``crypto_tool.py``).
"""

from __future__ import annotations

import secrets

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

#: Length of the random per-operation salt.
SALT_SIZE = 16

#: PBKDF2 iteration count (same value as the upstream reference tool).
PBKDF2_ROUNDS = 600_000

#: Length of the HMAC-SHA256 key derived alongside every cipher key.
MAC_KEY_SIZE = 32


def new_salt() -> bytes:
    """Return a fresh cryptographically random salt."""

    return secrets.token_bytes(SALT_SIZE)


def derive_key(password: str, salt: bytes, length: int) -> bytes:
    """Derive ``length`` bytes of key material from ``password`` and ``salt``."""

    if not password:
        raise ValueError("Password must not be empty.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt size.")
    return PBKDF2(
        password,
        salt,
        dkLen=length,
        count=PBKDF2_ROUNDS,
        hmac_hash_module=SHA256,
    )


def derive_keys(password: str, salt: bytes, cipher_key_size: int) -> tuple[bytes, bytes]:
    """Return ``(cipher_key, mac_key)`` from a single PBKDF2 derivation.

    The two keys are disjoint slices of one output, so they are independent
    and the cipher key is never reused as the MAC key.
    """

    material = derive_key(password, salt, cipher_key_size + MAC_KEY_SIZE)
    return material[:cipher_key_size], material[cipher_key_size:]
