from __future__ import annotations

from rest_framework import status

from ..crypto import SUPPORTED_ALGORITHMS

from .base import AuthenticatedApiTestCase


class PersonalDataApiTests(AuthenticatedApiTestCase):
    def test_round_trip_all_algorithms(self):
        payload = {"full_name": "Alice Liddell", "national_id": "3174xxxx0001", "phone": "+62812"}
        response = self.client.put("/api/me/personal-data/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for algorithm in SUPPORTED_ALGORITHMS:
            response = self.client.get(f"/api/me/personal-data/?algorithm={algorithm}")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json()["fields"]["full_name"], "Alice Liddell")

    def test_requires_correct_password(self):
        self.client.put("/api/me/personal-data/", {"full_name": "Alice"}, format="json")
        self._auth(password="wrong")
        response = self.client.get("/api/me/personal-data/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_missing_password_is_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.get("/api/me/personal-data/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
