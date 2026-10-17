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
