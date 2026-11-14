from __future__ import annotations

from django.test import SimpleTestCase

from ..crypto import IntegrityError, decrypt_with_key, encrypt_with_key, new_symmetric_key

AAD = b"cipher-safe/grant:1:2:FILE"


class RawKeyAesGcmTests(SimpleTestCase):
    """AES-256-GCM with a random key: per-item keys for shared records."""

    def test_new_key_is_32_random_bytes(self):
        keys = {new_symmetric_key() for _ in range(20)}
        self.assertEqual(len(keys), 20)
        self.assertTrue(all(len(key) == 32 for key in keys))

    def test_round_trip(self):
        key = new_symmetric_key()
        for data in (b"", b"short", bytes(range(256)) * 64):
            with self.subTest(size=len(data)):
                self.assertEqual(decrypt_with_key(encrypt_with_key(data, key, AAD), key, AAD), data)

    def test_ciphertext_hides_plaintext_and_uses_fresh_nonce(self):
        key = new_symmetric_key()
        data = b"HbA1c 7.1 %" * 10
        first, second = encrypt_with_key(data, key, AAD), encrypt_with_key(data, key, AAD)
        self.assertNotIn(b"HbA1c", first.ciphertext)
        self.assertEqual(len(first.nonce), 12)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertEqual(len(first.ciphertext), len(data) + 16)  # GCM tag appended

    def test_wrong_key_raises_integrity_error(self):
        sealed = encrypt_with_key(b"data", new_symmetric_key(), AAD)
        with self.assertRaises(IntegrityError):
            decrypt_with_key(sealed, new_symmetric_key(), AAD)

    def test_aad_mismatch_raises_integrity_error(self):
        key = new_symmetric_key()
        sealed = encrypt_with_key(b"data", key, AAD)
        with self.assertRaises(IntegrityError):
            decrypt_with_key(sealed, key, b"cipher-safe/grant:1:3:FILE")

    def test_modified_ciphertext_raises_integrity_error(self):
        key = new_symmetric_key()
        sealed = encrypt_with_key(b"some data", key, AAD)
        broken = bytearray(sealed.ciphertext)
        broken[0] ^= 0x01
        with self.assertRaises(IntegrityError):
            decrypt_with_key(sealed._replace(ciphertext=bytes(broken)), key, AAD)

    def test_bad_nonce_raises_integrity_error(self):
        key = new_symmetric_key()
        sealed = encrypt_with_key(b"data", key, AAD)
        with self.assertRaises(IntegrityError):
            decrypt_with_key(sealed._replace(nonce=b"short"), key, AAD)

    def test_key_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            encrypt_with_key(b"data", b"too short", AAD)
