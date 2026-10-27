"""Encryption primitives for Cipher Safe (AES, DES and RC4).

Adapted from https://github.com/ukassu/lab-session-information-security
(``crypto_tool.py``). The package re-exports the public API so that callers do
not depend on the module layout; the implementations live in
:mod:`core.crypto.algorithms` and :mod:`core.crypto.keys`, with the supported
algorithm and mode sets in :mod:`core.crypto.constants`.
"""

from .algorithms import TAG_SIZE, DecryptionResult, EncryptionResult, IntegrityError, decrypt, encrypt
from .constants import DEFAULT_MODE, MODE_FOR, SUPPORTED_ALGORITHMS, SUPPORTED_MODES
from .keys import PBKDF2_ROUNDS, SALT_SIZE, derive_key, derive_keys, new_salt

__all__ = [
    "DEFAULT_MODE",
    "MODE_FOR",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
    "TAG_SIZE",
    "DecryptionResult",
    "EncryptionResult",
    "IntegrityError",
    "PBKDF2_ROUNDS",
    "SALT_SIZE",
    "decrypt",
    "derive_key",
    "derive_keys",
    "encrypt",
    "new_salt",
]
