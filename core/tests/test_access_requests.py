from __future__ import annotations

from datetime import timedelta

from django.db import IntegrityError as DatabaseIntegrityError
from django.test import TestCase
from rest_framework import status
from django.utils import timezone

from ..constants import REQUEST_APPROVED, REQUEST_CANCELLED, REQUEST_DENIED, REQUEST_PENDING
from ..models import AccessRequest, User

from .base import PASSWORD, AuthenticatedApiTestCase


class AccessRequestModelTests(TestCase):
    """Storage rules: not to yourself, one pending request per pair."""

    @classmethod
    def setUpTestData(cls):
        cls.alice = User.objects.create_user("alice", password=PASSWORD)
        cls.budi = User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")

    def test_new_request_is_pending(self):
        request = AccessRequest.objects.create(requester=self.budi, owner=self.alice, message="Check-up")
        self.assertEqual(request.status, REQUEST_PENDING)
        self.assertIsNone(request.decided_at)
        self.assertFalse(request.expired)

    def test_cannot_request_self(self):
        with self.assertRaises(DatabaseIntegrityError):
            AccessRequest.objects.create(requester=self.alice, owner=self.alice)

    def test_one_pending_per_pair(self):
        AccessRequest.objects.create(requester=self.budi, owner=self.alice)
        with self.assertRaises(DatabaseIntegrityError):
            AccessRequest.objects.create(requester=self.budi, owner=self.alice)

    def test_decided_requests_do_not_block_a_new_one(self):
        AccessRequest.objects.create(requester=self.budi, owner=self.alice, status=REQUEST_DENIED)
        AccessRequest.objects.create(requester=self.budi, owner=self.alice)
        # The other direction is a different pair.
        AccessRequest.objects.create(requester=self.alice, owner=self.budi)
        self.assertEqual(AccessRequest.objects.count(), 3)

    def test_expired_is_computed(self):
        request = AccessRequest(
            requester=self.budi,
            owner=self.alice,
            status=REQUEST_APPROVED,
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        self.assertTrue(request.expired)
        request.expires_at = timezone.now() + timedelta(hours=1)
        self.assertFalse(request.expired)


class AccessRequestCreateListApiTests(AuthenticatedApiTestCase):
    """POST and GET /api/access-requests/. ``alice`` (patient) is signed in."""

    URL = "/api/access-requests/"

    def setUp(self):
        super().setUp()
        self.budi = User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")

    def _as(self, username):
        login = self.client.post("/api/auth/login/", {"username": username, "password": PASSWORD}, format="json")
        self._auth(access=login.json()["access"])

    def _ask(self, owner="alice", **extra):
        return self.client.post(self.URL, {"owner": owner, **extra}, format="json")

    def test_request_creates_pending(self):
        self._as("budi")
        response = self._ask(message="For my check-up on Monday", category="DOCUMENT")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()
        self.assertEqual(
            {k: body[k] for k in ("requester", "owner", "message", "category", "status", "expired")},
            {
                "requester": "budi",
                "owner": "alice",
                "message": "For my check-up on Monday",
                "category": "DOCUMENT",
                "status": "PENDING",
                "expired": False,
            },
        )

    def test_profile_can_be_requested(self):
        self._as("budi")
        self.assertEqual(self._ask(category="PROFILE").json()["category"], "PROFILE")

    def test_unknown_owner_400(self):
        response = self._ask(owner="nobody")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("owner", response.json())

    def test_cannot_request_self(self):
        self.assertEqual(self._ask(owner="alice").status_code, status.HTTP_400_BAD_REQUEST)

    def test_one_pending_per_pair(self):
        self._as("budi")
        self.assertEqual(self._ask().status_code, status.HTTP_201_CREATED)
        response = self._ask()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pending", response.json()["owner"][0])

    def test_unknown_category_400(self):
        self.assertEqual(self._ask(owner="budi", category="XRAY").status_code, status.HTTP_400_BAD_REQUEST)

    def test_any_role_can_request_any_role(self):
        User.objects.create_user("citra", password=PASSWORD)
        # patient -> doctor, patient -> patient, doctor -> patient
        self.assertEqual(self._ask(owner="budi").status_code, status.HTTP_201_CREATED)
        self.assertEqual(self._ask(owner="citra").status_code, status.HTTP_201_CREATED)
        self._as("budi")
        self.assertEqual(self._ask(owner="alice").status_code, status.HTTP_201_CREATED)

    def test_incoming_and_outgoing_boxes_are_separate(self):
        self._ask(owner="budi")  # alice -> budi
        self._as("budi")
        self._ask(owner="alice")  # budi -> alice
        incoming = self.client.get(self.URL, {"box": "incoming"}).json()
        outgoing = self.client.get(self.URL, {"box": "outgoing"}).json()
        self.assertEqual([(r["requester"], r["owner"]) for r in incoming], [("alice", "budi")])
        self.assertEqual([(r["requester"], r["owner"]) for r in outgoing], [("budi", "alice")])

    def test_box_defaults_to_incoming_and_rejects_unknown(self):
        self._ask(owner="budi")
        self._as("budi")
        self.assertEqual(len(self.client.get(self.URL).json()), 1)
        self.assertEqual(self.client.get(self.URL, {"box": "all"}).status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_only_shows_my_requests(self):
        User.objects.create_user("citra", password=PASSWORD)
        self._as("budi")
        self._ask(owner="citra")  # between budi and citra, not alice
        self._as("alice")
        self.assertEqual(self.client.get(self.URL, {"box": "incoming"}).json(), [])
        self.assertEqual(self.client.get(self.URL, {"box": "outgoing"}).json(), [])

    def test_request_reveals_nothing_about_records(self):
        self._upload()
        self._as("budi")
        created = self._ask().json()
        self._as("alice")
        listed = self.client.get(self.URL).json()
        expected = {
            "id", "requester", "owner", "message", "category", "status",
            "created_at", "decided_at", "expires_at", "expired", "items",
        }
        for body in [created, *listed]:
            self.assertEqual(body["items"], [])
            self.assertEqual(set(body), expected)
            self.assertNotIn("lab-result", str(body))

    def test_requires_authentication(self):
        self.client.credentials()
        self.assertEqual(self.client.get(self.URL).status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_is_throttled(self):
        for name in [f"user{i}" for i in range(11)]:
            User.objects.create_user(name, password=PASSWORD)
        codes = [self._ask(owner=f"user{i}").status_code for i in range(11)]
        self.assertEqual(codes[:10], [status.HTTP_201_CREATED] * 10)
        self.assertEqual(codes[10], status.HTTP_429_TOO_MANY_REQUESTS)


class AccessRequestDenyCancelApiTests(AuthenticatedApiTestCase):
    """Deny (owner) and cancel (requester). ``budi`` asks ``alice``."""

    def setUp(self):
        super().setUp()
        User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")
        User.objects.create_user("citra", password=PASSWORD)
        self._as("budi")
        self.request_id = self.client.post(
            "/api/access-requests/", {"owner": "alice"}, format="json"
        ).json()["id"]

    def _as(self, username):
        login = self.client.post("/api/auth/login/", {"username": username, "password": PASSWORD}, format="json")
        self._auth(access=login.json()["access"])

    def _deny(self):
        return self.client.post(f"/api/access-requests/{self.request_id}/deny/")

    def _cancel(self):
        return self.client.delete(f"/api/access-requests/{self.request_id}/")

    def _status(self):
        return AccessRequest.objects.get(pk=self.request_id).status

    def test_owner_denies(self):
        self._as("alice")
        response = self._deny()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["status"], "DENIED")
        self.assertIsNotNone(response.json()["decided_at"])

    def test_only_owner_can_deny(self):
        response = self._deny()  # budi, the requester
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self._status(), REQUEST_PENDING)

    def test_requester_cancels(self):
        self.assertEqual(self._cancel().status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(self._status(), REQUEST_CANCELLED)

    def test_only_requester_can_cancel(self):
        self._as("alice")
        self.assertEqual(self._cancel().status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self._status(), REQUEST_PENDING)

    def test_outsider_gets_404(self):
        self._as("citra")
        self.assertEqual(self._deny().status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(self._cancel().status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(self._status(), REQUEST_PENDING)

    def test_unknown_id_gets_404(self):
        self.request_id = 999999
        self.assertEqual(self._cancel().status_code, status.HTTP_404_NOT_FOUND)

    def test_denied_request_cannot_be_cancelled(self):
        self._as("alice")
        self._deny()
        self._as("budi")
        response = self._cancel()
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()["detail"], "This request is already denied.")

    def test_cancelled_request_cannot_be_denied(self):
        self._cancel()
        self._as("alice")
        self.assertEqual(self._deny().status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(self._status(), REQUEST_CANCELLED)

    def test_cancelled_request_allows_a_new_one(self):
        self._cancel()
        response = self.client.post("/api/access-requests/", {"owner": "alice"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
