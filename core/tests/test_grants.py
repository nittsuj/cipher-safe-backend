from __future__ import annotations

import json
import os

from django.core.files.base import ContentFile
from django.db import IntegrityError as DatabaseIntegrityError
from django.test import TestCase, override_settings

from ..constants import (
    GRANT_KIND_FILE,
    GRANT_KIND_PROFILE,
    KEY_PURPOSE_ENCRYPTION,
    REQUEST_APPROVED,
    REQUEST_PENDING,
)
from ..crypto import (
    IntegrityError,
    SealedData,
    decrypt_with_key,
    encrypt_with_key,
    envelope_digest,
    new_symmetric_key,
    parse_envelope,
    unwrap_key,
)
from ..exceptions import InvalidTransition, RequesterHasNoKey
from ..models import AccessRequest, GrantedItem, PersonalData, SharedKey, StoredFile, User
from ..services import (
    approve_request,
    ensure_key_pair,
    envelope_for_owner,
    load_private_key,
    open_key_for_user,
    store_personal_data,
    store_record,
    unpack_share_payload,
)

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


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, PASSWORD_HASHERS=PASSWORD_HASHERS)
class ApproveRequestTests(TestCase):
    """approve_request: one random key per item, wrapped for the requester."""

    LAB = b"HbA1c 7.1 %, fasting glucose 132 mg/dL"
    PROFILE = {"full_name": "Siti Rahmawati", "blood_type": "O+"}

    @classmethod
    def setUpTestData(cls):
        cls.alice = User.objects.create_user("alice", password=PASSWORD)
        cls.budi = User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")
        cls.lab = store_record(cls.alice, "DOCUMENT", "lab.txt", "text/plain", cls.LAB, PASSWORD)
        cls.scan = store_record(cls.alice, "ID_CARD", "ktp.png", "image/png", b"\x89PNG fake", PASSWORD)
        store_personal_data(PersonalData.objects.create(owner=cls.alice), PASSWORD, cls.PROFILE)
        cls.budi_pair, _ = ensure_key_pair(cls.budi, KEY_PURPOSE_ENCRYPTION, PASSWORD)

    def setUp(self):
        self.request = AccessRequest.objects.create(requester=self.budi, owner=self.alice)

    def _approve(self, files=None, include_profile=False, hours=24):
        files = [self.lab] if files is None else files
        return approve_request(self.request, PASSWORD, files, include_profile, hours)

    def _open_as_requester(self, item, envelope_text):
        """What the requester does: unwrap K with their private key, decrypt the copy."""

        envelope = parse_envelope(envelope_text)
        key = unwrap_key(load_private_key(self.budi_pair, PASSWORD), envelope.wrapped_key)
        return key, decrypt_with_key(item.sealed(), key, item.aad)

    def test_approve_sets_status_and_expiry(self):
        request, pair, grants = self._approve(hours=24)
        self.assertEqual(request.status, REQUEST_APPROVED)
        self.assertIsNotNone(request.decided_at)
        self.assertAlmostEqual((request.expires_at - request.decided_at).total_seconds(), 24 * 3600, delta=1)
        self.assertEqual(pair.pk, self.budi_pair.pk)
        self.assertEqual(len(grants), 1)

    def test_requester_opens_a_record_with_the_envelope(self):
        _, _, [(item, envelope)] = self._approve()
        parsed = parse_envelope(envelope)
        self.assertEqual((parsed.request_id, parsed.item_id), (self.request.pk, item.pk))
        _, payload = self._open_as_requester(item, envelope)
        label, data = unpack_share_payload(payload)
        self.assertEqual(label, {"name": "lab.txt", "content_type": "text/plain"})
        self.assertEqual(data, self.LAB)

    def test_profile_is_granted_as_a_snapshot(self):
        _, _, grants = self._approve(files=[], include_profile=True)
        [(item, envelope)] = grants
        self.assertEqual(item.kind, GRANT_KIND_PROFILE)
        _, payload = self._open_as_requester(item, envelope)
        self.assertEqual(json.loads(payload), self.PROFILE)

    def test_each_item_gets_its_own_key(self):
        _, _, grants = self._approve(files=[self.lab, self.scan], include_profile=True)
        keys = {self._open_as_requester(item, envelope)[0] for item, envelope in grants}
        self.assertEqual(len(keys), 3)
        self.assertTrue(all(len(key) == 32 for key in keys))

    def test_owner_copy_of_the_key_opens_with_owner_password(self):
        _, _, [(item, envelope)] = self._approve()
        key, _ = self._open_as_requester(item, envelope)
        shared = item.shared_key
        sealed = SealedData(bytes(shared.owner_nonce), bytes(shared.key_for_owner))
        self.assertEqual(open_key_for_user(sealed, bytes(shared.owner_salt), PASSWORD, shared.aad("owner")), key)
        with self.assertRaises(IntegrityError):
            open_key_for_user(sealed, bytes(shared.owner_salt), "not-the-password", shared.aad("owner"))

    def test_owner_gets_the_same_envelope_again(self):
        _, _, [(item, envelope)] = self._approve()
        item = GrantedItem.objects.get(pk=item.pk)
        self.assertEqual(envelope_for_owner(item, PASSWORD), envelope)
        with self.assertRaises(IntegrityError):
            envelope_for_owner(item, "not-the-password")

    def test_envelope_hash_and_requester_key_are_stored(self):
        _, _, [(item, envelope)] = self._approve()
        self.assertEqual(item.shared_key.envelope_sha256, envelope_digest(parse_envelope(envelope).wrapped_key))
        self.assertIsNone(item.shared_key.key_for_requester)
        self.assertEqual(item.shared_key.requester_key_id, self.budi_pair.pk)

    def test_no_plaintext_key_or_envelope_in_the_database(self):
        from django.db import connection

        _, _, grants = self._approve(files=[self.lab, self.scan])
        secrets_to_find = []
        for item, envelope in grants:
            key, _ = self._open_as_requester(item, envelope)
            secrets_to_find += [key, parse_envelope(envelope).wrapped_key, envelope.encode()]
        with connection.cursor() as cursor:
            for table in (SharedKey._meta.db_table, GrantedItem._meta.db_table, AccessRequest._meta.db_table):
                cursor.execute(f"SELECT * FROM {table}")
                for row in cursor.fetchall():
                    for value in row:
                        raw = bytes(value) if isinstance(value, (bytes, memoryview)) else str(value).encode()
                        for secret in secrets_to_find:
                            self.assertNotIn(secret, raw)

    def test_requester_without_key_gets_an_error_and_nothing_changes(self):
        citra = User.objects.create_user("citra", password=PASSWORD)
        request = AccessRequest.objects.create(requester=citra, owner=self.alice)
        with self.assertRaises(RequesterHasNoKey):
            approve_request(request, PASSWORD, [self.lab], False, 24)
        request.refresh_from_db()
        self.assertEqual(request.status, REQUEST_PENDING)
        self.assertFalse(request.items.exists())

    def test_only_pending_requests_can_be_approved(self):
        self._approve()
        with self.assertRaises(InvalidTransition):
            self._approve()

    def test_wrong_owner_password_creates_nothing(self):
        with self.assertRaises(IntegrityError):
            approve_request(self.request, "not-the-password", [self.lab], False, 24)
        self.request.refresh_from_db()
        self.assertEqual(self.request.status, REQUEST_PENDING)
        self.assertFalse(GrantedItem.objects.exists())

    def test_someone_elses_record_is_refused(self):
        other = store_record(self.budi, "DOCUMENT", "x.txt", "text/plain", b"x", PASSWORD)
        with self.assertRaises(ValueError):
            self._approve(files=[other])

    def test_at_least_one_item(self):
        with self.assertRaises(ValueError):
            self._approve(files=[], include_profile=False)
