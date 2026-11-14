from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from django.db import IntegrityError as DatabaseIntegrityError
from django.db import connection
from django.test import TestCase

from ..constants import KEY_PURPOSE_ENCRYPTION, KEY_PURPOSE_SIGNING
from ..crypto import (
    IntegrityError,
    certificate_fingerprint,
    fingerprint,
    generate_rsa_key_pair,
    key_pair_aad,
    load_certificate,
    load_public_key,
    public_key_pem,
    unwrap_private_key,
    wrap_private_key,
)
from ..models import User, UserKeyPair
from ..services import ensure_key_pair, load_private_key, rotate_key_pair

from .base import PASSWORD


class UserKeyPairModelTests(TestCase):
    """Storage of key pairs: one active pair per purpose, private key encrypted."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", password=PASSWORD)
        cls.private_key = generate_rsa_key_pair()

    def _store(self, purpose=KEY_PURPOSE_ENCRYPTION, active=True) -> UserKeyPair:
        wrapped = wrap_private_key(self.private_key, PASSWORD, key_pair_aad(self.user.pk, purpose))
        return UserKeyPair.objects.create(
            user=self.user,
            purpose=purpose,
            public_key_pem=public_key_pem(self.private_key.public_key()),
            encrypted_private_key=wrapped.ciphertext,
            kek_salt=wrapped.salt,
            nonce=wrapped.nonce,
            fingerprint=fingerprint(self.private_key.public_key()),
            active=active,
        )

    def test_stored_private_key_unwraps_after_reload(self):
        pair = UserKeyPair.objects.get(pk=self._store().pk)
        restored = unwrap_private_key(pair.wrapped, PASSWORD, key_pair_aad(self.user.pk, pair.purpose))
        self.assertEqual(restored.private_numbers(), self.private_key.private_numbers())
        self.assertEqual(pair.algorithm, "RSA-3072")

    def test_one_active_pair_per_purpose(self):
        self._store()
        with self.assertRaises(DatabaseIntegrityError):
            self._store()

    def test_inactive_pairs_and_other_purposes_are_allowed(self):
        self._store(active=False)
        self._store(active=False)
        self._store()
        self._store(purpose=KEY_PURPOSE_SIGNING)
        self.assertEqual(self.user.key_pairs.filter(active=True).count(), 2)


class KeyPairServiceTests(TestCase):
    """ensure / load / rotate: generate on first use, unlock only with the password."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", password=PASSWORD)

    def test_ensure_creates_once_then_reuses(self):
        first, created = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        second, created_again = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(UserKeyPair.objects.filter(user=self.user).count(), 1)
        self.assertGreater(first.generation_ms, 0)

    def test_purposes_get_separate_pairs(self):
        encryption, _ = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        signing, _ = ensure_key_pair(self.user, KEY_PURPOSE_SIGNING, PASSWORD)
        self.assertNotEqual(encryption.fingerprint, signing.fingerprint)

    def test_load_private_key_matches_public_key(self):
        pair, _ = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        private_key = load_private_key(pair, PASSWORD)
        self.assertEqual(fingerprint(private_key.public_key()), pair.fingerprint)

    def test_load_private_key_with_wrong_password_fails(self):
        pair, _ = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        with self.assertRaises(IntegrityError):
            load_private_key(pair, "not-the-password")

    def test_rotate_deactivates_old_and_changes_fingerprint(self):
        old, _ = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        new = rotate_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        old.refresh_from_db()
        self.assertFalse(old.active)
        self.assertTrue(new.active)
        self.assertNotEqual(old.fingerprint, new.fingerprint)
        # The old private key can still be opened for data encrypted to it.
        self.assertEqual(fingerprint(load_private_key(old, PASSWORD).public_key()), old.fingerprint)

    def test_no_plaintext_private_key_in_database(self):
        pair, _ = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        private_key = load_private_key(pair, PASSWORD)
        pkcs8 = private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        # Read the raw row, so no model code can hide anything.
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {UserKeyPair._meta.db_table} WHERE id = %s", [pair.pk])
            row = cursor.fetchone()
        for value in row:
            raw = bytes(value) if isinstance(value, (bytes, memoryview)) else str(value).encode()
            self.assertNotIn(pkcs8, raw)
            self.assertNotIn(b"PRIVATE KEY", raw)


class SigningKeyPairTests(TestCase):
    """A signing pair comes with a self-signed certificate."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", password=PASSWORD)

    def test_signing_pair_gets_a_certificate_for_its_key(self):
        pair, _ = ensure_key_pair(self.user, KEY_PURPOSE_SIGNING, PASSWORD)
        certificate = load_certificate(pair.certificate_pem)
        self.assertEqual(certificate.subject.rfc4514_string(), "O=Cipher Safe,CN=alice")
        self.assertEqual(fingerprint(certificate.public_key()), fingerprint(load_public_key(pair.public_key_pem)))
        # The certificate belongs to the stored private key.
        private_key = load_private_key(pair, PASSWORD)
        self.assertEqual(fingerprint(private_key.public_key()), fingerprint(certificate.public_key()))

    def test_signing_fingerprint_is_certificate_sha256(self):
        pair, _ = ensure_key_pair(self.user, KEY_PURPOSE_SIGNING, PASSWORD)
        self.assertEqual(pair.fingerprint, certificate_fingerprint(load_certificate(pair.certificate_pem)))

    def test_encryption_pair_has_no_certificate(self):
        pair, _ = ensure_key_pair(self.user, KEY_PURPOSE_ENCRYPTION, PASSWORD)
        self.assertEqual(pair.certificate_pem, "")
        self.assertEqual(pair.fingerprint, fingerprint(load_public_key(pair.public_key_pem)))

    def test_rotation_issues_new_certificate_and_keeps_old(self):
        old, _ = ensure_key_pair(self.user, KEY_PURPOSE_SIGNING, PASSWORD)
        new = rotate_key_pair(self.user, KEY_PURPOSE_SIGNING, PASSWORD)
        old.refresh_from_db()
        self.assertFalse(old.active)
        self.assertTrue(old.certificate_pem)  # old signatures can still be traced to it
        self.assertNotEqual(load_certificate(old.certificate_pem), load_certificate(new.certificate_pem))
        self.assertNotEqual(old.fingerprint, new.fingerprint)
