"""RSA key pairs whose private keys are stored only in encrypted form.

Every user gets RSA key pairs: the public key encrypts the keys of records
shared with them, and the private key signs their PDFs. The private key is
never stored in the clear. It is wrapped
like the user's data: a key-encryption key (KEK) is derived from the user's
password with PBKDF2 (:func:`core.crypto.keys.derive_key`), and the PKCS#8
private key is encrypted with AES-256-GCM under that KEK.

Associated data binds a wrapped key to its owner and purpose, so a blob copied
to another user or purpose fails the GCM check instead of decrypting.

Uses the ``cryptography`` package for RSA and AES-GCM. Like the rest of
:mod:`core.crypto`, this module has no Django imports.
"""

from __future__ import annotations

import secrets
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .algorithms import IntegrityError
from .keys import SALT_SIZE, derive_key, new_salt

#: Name stored with every key pair.
RSA_ALGORITHM = "RSA-3072"

#: RSA modulus size in bits (NIST: 128-bit security level).
RSA_KEY_SIZE = 3072

#: Standard RSA public exponent.
RSA_PUBLIC_EXPONENT = 65537

#: AES-256 key-encryption key derived from the password.
KEK_SIZE = 32

#: AES-GCM nonce length (the size GCM is designed for).
NONCE_SIZE = 12


class WrappedKey(NamedTuple):
    """An encrypted private key plus what is needed to decrypt it."""

    ciphertext: bytes  # PKCS#8 DER encrypted with AES-256-GCM, tag appended
    salt: bytes  # PBKDF2 salt for the KEK
    nonce: bytes  # AES-GCM nonce


def generate_rsa_key_pair() -> rsa.RSAPrivateKey:
    """Return a new RSA-3072 private key (the public key is derived from it)."""

    return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)


def public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    """Return the public key as a PEM SubjectPublicKeyInfo string."""

    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def load_public_key(pem: str) -> rsa.RSAPublicKey:
    """Parse a PEM public key, rejecting anything that is not RSA."""

    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Not an RSA public key.")
    return key


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 of the DER public key as ``AB:CD:...``, for people to compare."""

    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return ":".join(f"{byte:02X}" for byte in digest.finalize())


def key_pair_aad(user_id: int, purpose: str) -> bytes:
    """Associated data that ties a wrapped private key to one user and purpose."""

    return f"cipher-safe/keypair:{user_id}:{purpose}".encode("ascii")


def wrap_private_key(private_key: rsa.RSAPrivateKey, password: str, aad: bytes) -> WrappedKey:
    """Encrypt ``private_key`` with a KEK derived from ``password``."""

    der = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    salt = new_salt()
    nonce = secrets.token_bytes(NONCE_SIZE)
    kek = derive_key(password, salt, KEK_SIZE)
    return WrappedKey(AESGCM(kek).encrypt(nonce, der, aad), salt, nonce)


def unwrap_private_key(wrapped: WrappedKey, password: str, aad: bytes) -> rsa.RSAPrivateKey:
    """Decrypt a wrapped private key.

    Raises :class:`IntegrityError` for a wrong password, a modified blob or
    associated data that does not match (another user or purpose).
    """

    if len(wrapped.salt) != SALT_SIZE:
        raise IntegrityError("Invalid salt size.")
    if len(wrapped.nonce) != NONCE_SIZE:
        raise IntegrityError("Invalid nonce size.")
    kek = derive_key(password, wrapped.salt, KEK_SIZE)
    try:
        der = AESGCM(kek).decrypt(wrapped.nonce, wrapped.ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityError("The private key could not be decrypted.") from exc
    key = serialization.load_der_private_key(der, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise IntegrityError("Stored key is not an RSA private key.")
    return key
