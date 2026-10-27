from __future__ import annotations

from rest_framework import status

from ..crypto import SUPPORTED_ALGORITHMS
from ..models import EncryptedValue

from .base import AuthenticatedApiTestCase

PROFILE = {
    "full_name": "Siti Rahayu",
    "national_id": "3578014501900002",
    "bpjs_number": "0001234567890",
    "date_of_birth": "1990-01-05",
    "blood_type": "O+",
    "allergies": "Penicillin",
}


class PersonalDataApiTests(AuthenticatedApiTestCase):
    def test_round_trip_all_algorithms(self):
        response = self.client.put("/api/me/personal-data/", PROFILE, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for algorithm in SUPPORTED_ALGORITHMS:
            response = self.client.get(f"/api/me/personal-data/?algorithm={algorithm}")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json()["fields"], PROFILE)

    def test_profile_is_one_record_per_algorithm(self):
        self.client.put("/api/me/personal-data/", PROFILE, format="json")
        self.assertEqual(EncryptedValue.objects.count(), len(SUPPORTED_ALGORITHMS))

    def test_put_replaces_the_profile(self):
        self.client.put("/api/me/personal-data/", PROFILE, format="json")
        self.client.put("/api/me/personal-data/", {"full_name": "Siti R."}, format="json")
        fields = self.client.get("/api/me/personal-data/").json()["fields"]
        self.assertEqual(fields, {"full_name": "Siti R."})

    def test_invalid_nik_is_rejected(self):
        response = self.client.put("/api/me/personal-data/", {"national_id": "12345"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_tampered_profile_is_refused(self):
        self.client.put("/api/me/personal-data/", PROFILE, format="json")
        row = EncryptedValue.objects.get(algorithm="RC4")
        ciphertext = bytearray(bytes(row.ciphertext))
        ciphertext[0] ^= 0x01
        row.ciphertext = bytes(ciphertext)
        row.save()
        response = self.client.get("/api/me/personal-data/?algorithm=RC4")
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_requires_correct_password(self):
        self.client.put("/api/me/personal-data/", {"full_name": "Siti"}, format="json")
        self._auth(password="wrong")
        response = self.client.get("/api/me/personal-data/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_missing_password_is_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.get("/api/me/personal-data/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
