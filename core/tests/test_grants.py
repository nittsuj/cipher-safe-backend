from __future__ import annotations

import os

from django.core.files.base import ContentFile
from django.db import IntegrityError as DatabaseIntegrityError
from django.test import TestCase, override_settings

from ..constants import GRANT_KIND_FILE, GRANT_KIND_PROFILE, KEY_PURPOSE_ENCRYPTION, REQUEST_APPROVED
from ..crypto import decrypt_with_key, encrypt_with_key, new_symmetric_key
from ..models import AccessRequest, GrantedItem, SharedKey, StoredFile, User
from ..services import ensure_key_pair

from .base import PASSWORD, PASSWORD_HASHERS, TEST_MEDIA_ROOT


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, PASSWORD_HASHERS=PASSWORD_HASHERS)
class GrantedItemModelTests(TestCase):
    """Storage of granted copies and their keys."""

    @classmethod
    def setUpTestData(cls):
        cls.alice = User.objects.create_user("alice", password=PASSWORD)
        cls.budi = User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")
        cls.record = StoredFile.objects.create(owner=cls.alice, category="DOCUMENT", plaintext_size=4)
        cls.request = AccessRequest.objects.create(requester=cls.budi, owner=cls.alice, status=REQUEST_APPROVED)
        cls.budi_key, _ = ensure_key_pair(cls.budi, KEY_PURPOSE_ENCRYPTION, PASSWORD)

    def _item(self, kind=GRANT_KIND_FILE, file="default", data=b"data", key=None):
        item = GrantedItem.objects.create(
            request=self.request,
            kind=kind,
            file=self.record if file == "default" else file,
            nonce=b"",
        )
        sealed = encrypt_with_key(data, key or new_symmetric_key(), item.aad)
        item.nonce = sealed.nonce
        item.plaintext_size = len(data)
        item.blob.save(f"{item.pk}.bin", ContentFile(sealed.ciphertext))
        return item

    def test_sealed_copy_decrypts_with_its_key_after_reload(self):
        key = new_symmetric_key()
        item = GrantedItem.objects.get(pk=self._item(data=b"HbA1c 7.1 %", key=key).pk)
        self.assertEqual(decrypt_with_key(item.sealed(), key, item.aad), b"HbA1c 7.1 %")

    def test_aad_names_request_item_and_kind(self):
        item = self._item()
        self.assertEqual(item.aad, f"cipher-safe/grant:{self.request.pk}:{item.pk}:FILE".encode())

    def test_file_item_needs_a_file_and_profile_item_must_not_have_one(self):
        with self.assertRaises(DatabaseIntegrityError):
            GrantedItem.objects.create(request=self.request, kind=GRANT_KIND_FILE, file=None, nonce=b"")

    def test_profile_item_must_not_point_at_a_file(self):
        with self.assertRaises(DatabaseIntegrityError):
            GrantedItem.objects.create(request=self.request, kind=GRANT_KIND_PROFILE, file=self.record, nonce=b"")

    def test_one_grant_per_file_and_one_profile_per_request(self):
        self._item()
        self._item(kind=GRANT_KIND_PROFILE, file=None)
        with self.assertRaises(DatabaseIntegrityError):
            self._item()

    def test_second_profile_grant_is_rejected(self):
        self._item(kind=GRANT_KIND_PROFILE, file=None)
        with self.assertRaises(DatabaseIntegrityError):
            self._item(kind=GRANT_KIND_PROFILE, file=None)

    def test_deleting_an_item_removes_its_blob_and_key(self):
        item = self._item()
        SharedKey.objects.create(
            item=item,
            key_for_owner=b"x",
            owner_salt=b"s",
            owner_nonce=b"n",
            envelope_sha256="0" * 64,
            requester_key=self.budi_key,
        )
        path = item.blob.path
        self.assertTrue(os.path.exists(path))
        with self.captureOnCommitCallbacks(execute=True):
            self.request.delete()
        self.assertFalse(os.path.exists(path))
        self.assertFalse(SharedKey.objects.exists())

    def test_requester_key_is_protected_while_a_key_uses_it(self):
        item = self._item()
        SharedKey.objects.create(
            item=item,
            key_for_owner=b"x",
            owner_salt=b"s",
            owner_nonce=b"n",
            envelope_sha256="0" * 64,
            requester_key=self.budi_key,
        )
        from django.db.models import ProtectedError

        with self.assertRaises(ProtectedError):
            self.budi_key.delete()
