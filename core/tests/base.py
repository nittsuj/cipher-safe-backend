"""Shared fixtures for the API test modules.

Kept out of a ``test_*.py`` file so unittest discovery does not try to collect
it directly; the concrete test cases subclass :class:`AuthenticatedApiTestCase`.
"""

from __future__ import annotations

import tempfile

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

PASSWORD = "SuperSecret123!"
TEST_MEDIA_ROOT = tempfile.mkdtemp(prefix="cipher-safe-tests-")
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, PASSWORD_HASHERS=PASSWORD_HASHERS)
class AuthenticatedApiTestCase(APITestCase):
    """Registers + logs in ``alice`` and provides auth/upload helpers."""

    def setUp(self):
        # Reset throttle counters so tests do not rate-limit each other.
        cache.clear()
        self.client.post(
            "/api/auth/register/",
            {"username": "alice", "password": PASSWORD},
            format="json",
        )
        login = self.client.post(
            "/api/auth/login/",
            {"username": "alice", "password": PASSWORD},
            format="json",
        )
        tokens = login.json()
        self.access = tokens["access"]
        self.refresh = tokens["refresh"]
        self._auth()

    def _auth(self, password: str = PASSWORD, access: str | None = None):
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access or self.access}",
            HTTP_X_CIPHER_PASSWORD=password,
        )

    def _upload(self, content: bytes = b"fake document payload " * 200, mode: str = "CBC"):
        upload = SimpleUploadedFile("report.pdf", content, content_type="application/pdf")
        response = self.client.post(
            "/api/files/", {"file": upload, "category": "DOCUMENT", "mode": mode}, format="multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response.json()
