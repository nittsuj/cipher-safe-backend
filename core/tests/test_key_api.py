from __future__ import annotations

from rest_framework import status

from ..models import User, UserKeyPair

from .base import PASSWORD, AuthenticatedApiTestCase

KEYS_URL = "/api/me/keys/"
PUBLIC_FIELDS = {"purpose", "algorithm", "fingerprint", "public_key_pem", "has_certificate", "created_at"}


class KeyPairApiTests(AuthenticatedApiTestCase):
    """/api/me/keys/ and /api/users/{username}/public-key/."""

    def _create(self, purpose="ENCRYPTION", rotate=False):
        return self.client.post(KEYS_URL, {"purpose": purpose, "rotate": rotate}, format="json")

    def test_list_is_empty_before_any_key(self):
        response = self.client.get(KEYS_URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), [])

    def test_post_generates_then_returns_existing(self):
        first = self._create()
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        second = self._create()
        self.assertEqual(second.status_code, status.HTTP_200_OK)
        self.assertEqual(first.json()["fingerprint"], second.json()["fingerprint"])
        self.assertEqual(first.json()["algorithm"], "RSA-3072")

    def test_rotate_returns_a_new_key(self):
        old = self._create().json()
        new = self._create(rotate=True)
        self.assertEqual(new.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(new.json()["fingerprint"], old["fingerprint"])
        listed = self.client.get(KEYS_URL).json()
        self.assertEqual([pair["fingerprint"] for pair in listed], [new.json()["fingerprint"]])

    def test_unknown_purpose_is_rejected(self):
        self.assertEqual(self._create(purpose="BOGUS").status_code, status.HTTP_400_BAD_REQUEST)

    def test_wrong_password_is_rejected_without_generating(self):
        self._auth(password="not-the-password")
        self.assertEqual(self._create().status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(UserKeyPair.objects.exists())

    def test_requires_authentication(self):
        self.client.credentials()
        self.assertEqual(self.client.get(KEYS_URL).status_code, status.HTTP_401_UNAUTHORIZED)

    def test_api_never_returns_private_material(self):
        created = self._create().json()
        listed = self.client.get(KEYS_URL).json()
        for body in [created, *listed]:
            self.assertEqual(set(body), PUBLIC_FIELDS)
            self.assertNotIn("PRIVATE", body["public_key_pem"])

    def test_doctor_accounts_have_keys_too(self):
        User.objects.create_user("drbob", password=PASSWORD, role="DOCTOR")
        login = self.client.post("/api/auth/login/", {"username": "drbob", "password": PASSWORD}, format="json")
        self._auth(access=login.json()["access"])
        self.assertEqual(self._create().status_code, status.HTTP_201_CREATED)

    def test_public_key_lookup(self):
        mine = self._create().json()
        response = self.client.get("/api/users/alice/public-key/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {
                "username": "alice",
                "purpose": "ENCRYPTION",
                "algorithm": "RSA-3072",
                "fingerprint": mine["fingerprint"],
                "public_key_pem": mine["public_key_pem"],
            },
        )

    def test_public_key_lookup_404_for_unknown_user(self):
        self.assertEqual(self.client.get("/api/users/nobody/public-key/").status_code, status.HTTP_404_NOT_FOUND)

    def test_public_key_lookup_404_without_key_and_does_not_generate(self):
        User.objects.create_user("carol", password=PASSWORD)
        response = self.client.get("/api/users/carol/public-key/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(UserKeyPair.objects.filter(user__username="carol").exists())

    def test_public_key_lookup_rejects_unknown_purpose(self):
        response = self.client.get("/api/users/alice/public-key/?purpose=BOGUS")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
