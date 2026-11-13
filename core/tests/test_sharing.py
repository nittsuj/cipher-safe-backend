from __future__ import annotations

import os
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from ..models import FileShare

from .base import PASSWORD, AuthenticatedApiTestCase

CONTENT = b"%PDF-1.4 fake lab result " * 50


class SharingTests(AuthenticatedApiTestCase):
    """alice (patient) shares a record with dr_budi (doctor)."""

    def setUp(self):
        super().setUp()
        self.doctor = APIClient()
        self.doctor.post(
            "/api/auth/register/",
            {"username": "dr_budi", "password": PASSWORD, "role": "DOCTOR"},
            format="json",
        )
        tokens = self.doctor.post(
            "/api/auth/login/", {"username": "dr_budi", "password": PASSWORD}, format="json"
        ).json()
        self.assertEqual(tokens["user"]["role"], "DOCTOR")
        self.doctor.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}", HTTP_X_CIPHER_PASSWORD=PASSWORD)
        self.file = self._upload(CONTENT)

    def _share(self, doctor="dr_budi", **extra):
        return self.client.post(
            f"/api/files/{self.file['id']}/shares/", {"doctor": doctor, **extra}, format="json"
        )

    def _open(self, share_id, key, inline=True):
        query = "?inline=1" if inline else ""
        return self.doctor.get(f"/api/shares/received/{share_id}/open/{query}", HTTP_X_SHARE_KEY=key)

    def test_doctor_opens_a_share_with_the_key(self):
        response = self._share()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        key = response.json()["share_key"]
        self.assertRegex(key, r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){4}$")

        listed = self.doctor.get("/api/shares/received/").json()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["patient"], "alice")
        self.assertNotIn("original_name", listed[0])  # name stays encrypted

        opened = self._open(listed[0]["id"], key.lower().replace("-", " "))
        self.assertEqual(opened.status_code, status.HTTP_200_OK)
        self.assertEqual(opened.content, CONTENT)
        self.assertEqual(opened["Content-Type"], "application/pdf")
        self.assertTrue(opened["Content-Disposition"].startswith("inline"))
        self.assertEqual(FileShare.objects.get().access_count, 1)

    def test_key_is_not_stored(self):
        key = self._share().json()["share_key"]
        share = FileShare.objects.get()
        stored = b"".join(bytes(v or b"") for v in (share.salt, share.iv, share.tag)) + share._payload()
        self.assertNotIn(key.encode(), stored)
        self.assertEqual(share.mode, "GCM")

    def test_wrong_key_is_rejected(self):
        self._share()
        share_id = FileShare.objects.get().pk
        self.assertEqual(self._open(share_id, "AAAA-AAAA-AAAA-AAAA-AAAA").status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self._open(share_id, "").status_code, status.HTTP_400_BAD_REQUEST)

    def test_expired_share_is_hidden(self):
        key = self._share().json()["share_key"]
        FileShare.objects.update(expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.doctor.get("/api/shares/received/").json(), [])
        self.assertEqual(self._open(FileShare.objects.get().pk, key).status_code, status.HTTP_404_NOT_FOUND)

    def test_revoked_share_cannot_be_opened(self):
        key = self._share().json()["share_key"]
        share_id = FileShare.objects.get().pk
        self.assertEqual(self.client.delete(f"/api/shares/{share_id}/").status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(self._open(share_id, key).status_code, status.HTTP_404_NOT_FOUND)

    def test_only_doctors_can_receive(self):
        cache.clear()
        self.client.post("/api/auth/register/", {"username": "bob", "password": PASSWORD}, format="json")
        response = self._share(doctor="bob")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_share_needs_the_patient_password(self):
        self._auth(password="wrong-password")
        self.assertEqual(self._share().status_code, status.HTTP_403_FORBIDDEN)

    def test_doctor_has_no_vault_and_patient_no_inbox(self):
        self.assertEqual(self.doctor.get("/api/files/").status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self.client.get("/api/shares/received/").status_code, status.HTTP_403_FORBIDDEN)

    def test_other_doctor_cannot_open(self):
        key = self._share().json()["share_key"]
        cache.clear()
        other = APIClient()
        other.post("/api/auth/register/", {"username": "dr_sari", "password": PASSWORD, "role": "DOCTOR"}, format="json")
        tokens = other.post("/api/auth/login/", {"username": "dr_sari", "password": PASSWORD}, format="json").json()
        other.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = other.get(f"/api/shares/received/{FileShare.objects.get().pk}/open/", HTTP_X_SHARE_KEY=key)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_deleting_the_record_removes_share_blobs(self):
        self._share()
        path = FileShare.objects.get().blob.path
        with self.captureOnCommitCallbacks(execute=True):
            self.client.delete(f"/api/files/{self.file['id']}/")
        self.assertFalse(os.path.exists(path))
