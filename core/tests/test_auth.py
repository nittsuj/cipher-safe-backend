from __future__ import annotations

from rest_framework import status

from .base import AuthenticatedApiTestCase


class AuthApiTests(AuthenticatedApiTestCase):
    def test_login_rejects_bad_password(self):
        response = self.client.post(
            "/api/auth/login/",
            {"username": "alice", "password": "wrong"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_blacklists_refresh_token(self):
        response = self.client.post(
            "/api/auth/logout/", {"refresh": self.refresh}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # The blacklisted refresh token can no longer be exchanged.
        refreshed = self.client.post(
            "/api/auth/refresh/", {"refresh": self.refresh}, format="json"
        )
        self.assertEqual(refreshed.status_code, status.HTTP_401_UNAUTHORIZED)


class RoleTests(AuthenticatedApiTestCase):
    def test_register_defaults_to_patient(self):
        self.assertEqual(self.client.get("/api/me/").json()["role"], "PATIENT")

    def test_doctor_has_no_records_vault(self):
        self.client.credentials()
        body = self.client.post(
            "/api/auth/register/",
            {"username": "dr-budi", "password": "AnotherSecret123!", "role": "DOCTOR"},
            format="json",
        ).json()
        self.assertEqual(body["user"]["role"], "DOCTOR")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {body['access']}")
        response = self.client.get("/api/files/", HTTP_X_CIPHER_PASSWORD="AnotherSecret123!")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
