"""Encryption primitives for Cipher Safe (AES, DES and RC4).

Adapted from https://github.com/ukassu/lab-session-information-security
(``crypto_tool.py``). The package re-exports the public API so that callers do
not depend on the module layout; the implementations live in
:mod:`core.crypto.algorithms` and :mod:`core.crypto.keys`, with the supported
algorithm and mode sets in :mod:`core.crypto.constants`, and RSA key pairs
with password-wrapped private keys in :mod:`core.crypto.asymmetric`, and
AES-GCM with raw random keys in :mod:`core.crypto.symmetric`.
"""

from .algorithms import GCM_TAG_SIZE, TAG_SIZE, DecryptionResult, EncryptionResult, IntegrityError, decrypt, encrypt
from .asymmetric import (
    RSA_ALGORITHM,
    WrappedKey,
    fingerprint,
    generate_rsa_key_pair,
    key_pair_aad,
    load_public_key,
    public_key_pem,
    unwrap_private_key,
    wrap_private_key,
)
from .constants import AEAD_MODES, DEFAULT_MODE, MODE_FOR, SUPPORTED_ALGORITHMS, SUPPORTED_MODES
from .symmetric import (
    SYMMETRIC_KEY_SIZE,
    SealedData,
    decrypt_with_key,
    encrypt_with_key,
    new_symmetric_key,
)
from .keys import PBKDF2_ROUNDS, SALT_SIZE, derive_key, derive_keys, new_salt

__all__ = [
    "AEAD_MODES",
    "GCM_TAG_SIZE",
    "DEFAULT_MODE",
    "MODE_FOR",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
    "SYMMETRIC_KEY_SIZE",
    "SealedData",
    "TAG_SIZE",
    "DecryptionResult",
    "EncryptionResult",
    "IntegrityError",
    "PBKDF2_ROUNDS",
    "RSA_ALGORITHM",
    "SALT_SIZE",
    "WrappedKey",
    "decrypt",
    "decrypt_with_key",
    "derive_key",
    "derive_keys",
    "encrypt",
    "encrypt_with_key",
    "fingerprint",
    "generate_rsa_key_pair",
    "key_pair_aad",
    "load_public_key",
    "new_salt",
    "new_symmetric_key",
    "public_key_pem",
    "unwrap_private_key",
    "wrap_private_key",
]
