from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from django.test import SimpleTestCase

from ..crypto import (
    RSA_ALGORITHM,
    IntegrityError,
    WrappedKey,
    fingerprint,
    generate_rsa_key_pair,
    key_pair_aad,
    load_public_key,
    public_key_pem,
    unwrap_private_key,
    wrap_private_key,
)

from .base import PASSWORD

AAD = key_pair_aad(1, "ENCRYPTION")


def _pkcs8(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


class RsaKeyPairTests(SimpleTestCase):
    """RSA key pairs, and private keys wrapped with a password-derived key."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # RSA-3072 generation takes a moment; one key serves every test.
        cls.private_key = generate_rsa_key_pair()
        cls.wrapped = wrap_private_key(cls.private_key, PASSWORD, AAD)

    def test_key_is_rsa_3072(self):
        self.assertEqual(RSA_ALGORITHM, "RSA-3072")
        self.assertEqual(self.private_key.key_size, 3072)
        self.assertEqual(self.private_key.public_key().public_numbers().e, 65537)

    def test_public_key_pem_round_trip(self):
        pem = public_key_pem(self.private_key.public_key())
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertNotIn("PRIVATE", pem)
        self.assertEqual(fingerprint(load_public_key(pem)), fingerprint(self.private_key.public_key()))

    def test_fingerprint_format(self):
        value = fingerprint(self.private_key.public_key())
        self.assertRegex(value, r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_fingerprint_differs_per_key(self):
        other = generate_rsa_key_pair()
        self.assertNotEqual(fingerprint(other.public_key()), fingerprint(self.private_key.public_key()))

    def test_wrap_unwrap_round_trip(self):
        restored = unwrap_private_key(self.wrapped, PASSWORD, AAD)
        self.assertEqual(_pkcs8(restored), _pkcs8(self.private_key))

    def test_wrapped_key_is_not_plaintext(self):
        self.assertNotIn(_pkcs8(self.private_key), self.wrapped.ciphertext)
        self.assertEqual(len(self.wrapped.salt), 16)
        self.assertEqual(len(self.wrapped.nonce), 12)

    def test_wrapping_twice_uses_fresh_salt_and_nonce(self):
        again = wrap_private_key(self.private_key, PASSWORD, AAD)
        self.assertNotEqual(again.salt, self.wrapped.salt)
        self.assertNotEqual(again.nonce, self.wrapped.nonce)
        self.assertNotEqual(again.ciphertext, self.wrapped.ciphertext)

    def test_wrong_password_raises_integrity_error(self):
        with self.assertRaises(IntegrityError):
            unwrap_private_key(self.wrapped, "not-the-password", AAD)

    def test_aad_binds_user_and_purpose(self):
        for aad in (key_pair_aad(2, "ENCRYPTION"), key_pair_aad(1, "SIGNING")):
            with self.subTest(aad=aad), self.assertRaises(IntegrityError):
                unwrap_private_key(self.wrapped, PASSWORD, aad)

    def test_modified_ciphertext_raises_integrity_error(self):
        data = bytearray(self.wrapped.ciphertext)
        data[10] ^= 0x01
        with self.assertRaises(IntegrityError):
            unwrap_private_key(self.wrapped._replace(ciphertext=bytes(data)), PASSWORD, AAD)

    def test_bad_salt_or_nonce_size_raises_integrity_error(self):
        for broken in (self.wrapped._replace(salt=b"short"), self.wrapped._replace(nonce=b"short")):
            with self.subTest(broken=broken[1:]), self.assertRaises(IntegrityError):
                unwrap_private_key(WrappedKey(*broken), PASSWORD, AAD)

    def test_load_public_key_rejects_non_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )
        with self.assertRaises(ValueError):
            load_public_key(pem)
