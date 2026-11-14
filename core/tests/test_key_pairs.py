from __future__ import annotations

from django.db import IntegrityError as DatabaseIntegrityError
from django.test import TestCase

from ..constants import KEY_PURPOSE_ENCRYPTION, KEY_PURPOSE_SIGNING
from ..crypto import fingerprint, generate_rsa_key_pair, key_pair_aad, public_key_pem, unwrap_private_key, wrap_private_key
from ..models import User, UserKeyPair

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
