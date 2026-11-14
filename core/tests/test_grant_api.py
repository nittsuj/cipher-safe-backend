from __future__ import annotations

from datetime import timedelta

from django.utils import timezone
from rest_framework import status

from ..crypto import parse_envelope
from ..models import AccessRequest, GrantedItem, PersonalData, User
from ..services import ensure_key_pair, store_personal_data

from .base import PASSWORD, AuthenticatedApiTestCase


class ApproveApiTests(AuthenticatedApiTestCase):
    """POST /approve/ and GET /items/{id}/envelope/. ``alice`` owns, ``budi`` asks."""

    def setUp(self):
        super().setUp()
        self.budi = User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")
        User.objects.create_user("citra", password=PASSWORD)
        self.budi_pair, _ = ensure_key_pair(self.budi, "ENCRYPTION", PASSWORD)
        self.file_id = self._upload()["id"]
        store_personal_data(PersonalData.objects.create(owner=self.alice), PASSWORD, {"full_name": "Alice"})
        self.request_id = AccessRequest.objects.create(requester=self.budi, owner=self.alice).pk

    @property
    def alice(self):
        return User.objects.get(username="alice")

    def _as(self, username, password=PASSWORD):
        login = self.client.post("/api/auth/login/", {"username": username, "password": PASSWORD}, format="json")
        self._auth(password=password, access=login.json()["access"])

    def _approve(self, request_id=None, **body):
        body.setdefault("file_ids", [self.file_id])
        url = f"/api/access-requests/{request_id or self.request_id}/approve/"
        return self.client.post(url, body, format="json")

    def _envelope(self, item_id, request_id=None):
        return self.client.get(f"/api/access-requests/{request_id or self.request_id}/items/{item_id}/envelope/")

    def test_approve_returns_one_envelope_per_item(self):
        response = self._approve(include_profile=True, expires_hours=48)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        body = response.json()
        self.assertEqual(body["request"]["status"], "APPROVED")
        self.assertIsNotNone(body["request"]["expires_at"])
        self.assertEqual(body["recipient_fingerprint"], self.budi_pair.fingerprint)
        kinds = [(i["kind"], i["category"]) for i in body["items"]]
        self.assertEqual(kinds, [("FILE", "DOCUMENT"), ("PROFILE", None)])
        for item in body["items"]:
            envelope = parse_envelope(item["envelope"])
            self.assertEqual((envelope.request_id, envelope.item_id), (self.request_id, item["item_id"]))

    def test_envelope_can_be_shown_again_unchanged(self):
        item = self._approve().json()["items"][0]
        response = self._envelope(item["item_id"])
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["envelope"], item["envelope"])
        self.assertEqual(response.json()["recipient_fingerprint"], self.budi_pair.fingerprint)

    def test_approve_needs_the_password(self):
        self._auth(password="not-the-password")
        self.assertEqual(self._approve().status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(GrantedItem.objects.exists())

    def test_only_owner_can_approve(self):
        self._as("budi")
        self.assertEqual(self._approve().status_code, status.HTTP_403_FORBIDDEN)

    def test_outsider_gets_404(self):
        item = self._approve().json()["items"][0]
        self._as("citra")
        self.assertEqual(self._approve().status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(self._envelope(item["item_id"]).status_code, status.HTTP_404_NOT_FOUND)

    def test_requester_cannot_see_the_owner_envelope_view(self):
        item = self._approve().json()["items"][0]
        self._as("budi")
        self.assertEqual(self._envelope(item["item_id"]).status_code, status.HTTP_403_FORBIDDEN)

    def test_body_is_validated(self):
        cases = [
            {"file_ids": []},  # nothing granted
            {"file_ids": [999999]},  # not a record
            {"file_ids": [self.file_id, self.file_id]},  # listed twice
            {"expires_hours": 0},
            {"expires_hours": 169},
        ]
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(self._approve(**body).status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(GrantedItem.objects.exists())

    def test_someone_elses_record_is_refused(self):
        self._as("citra")
        citra_file = self._upload()["id"]
        self._as("alice")
        self.assertEqual(self._approve(file_ids=[citra_file]).status_code, status.HTTP_400_BAD_REQUEST)

    def test_requester_without_key_gets_409(self):
        citra = User.objects.get(username="citra")
        request_id = AccessRequest.objects.create(requester=citra, owner=self.alice).pk
        response = self._approve(request_id=request_id)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertIn("citra has no encryption key", response.json()["detail"])

    def test_approving_twice_gets_409(self):
        self._approve()
        self.assertEqual(self._approve().status_code, status.HTTP_409_CONFLICT)

    def test_envelope_is_gone_after_expiry(self):
        item = self._approve().json()["items"][0]
        AccessRequest.objects.filter(pk=self.request_id).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self._envelope(item["item_id"]).status_code, status.HTTP_404_NOT_FOUND)

    def test_envelope_of_unknown_item_is_404(self):
        self._approve()
        self.assertEqual(self._envelope(999999).status_code, status.HTTP_404_NOT_FOUND)


class RedeemAndOpenApiTests(AuthenticatedApiTestCase):
    """The requester (``budi``) redeems envelopes and opens what ``alice`` granted."""

    CONTENT = b"fake lab result payload " * 200  # what AuthenticatedApiTestCase._upload sends

    def setUp(self):
        super().setUp()
        budi = User.objects.create_user("budi", password=PASSWORD, role="DOCTOR")
        User.objects.create_user("citra", password=PASSWORD)
        ensure_key_pair(budi, "ENCRYPTION", PASSWORD)
        file_id = self._upload()["id"]
        alice = User.objects.get(username="alice")
        store_personal_data(PersonalData.objects.create(owner=alice), PASSWORD, {"full_name": "Alice"})
        self.request_id = AccessRequest.objects.create(requester=budi, owner=alice).pk
        body = self.client.post(
            f"/api/access-requests/{self.request_id}/approve/",
            {"file_ids": [file_id], "include_profile": True},
            format="json",
        ).json()
        self.file_item, self.profile_item = body["items"]
        self._as("budi")

    def _as(self, username, password=PASSWORD):
        login = self.client.post("/api/auth/login/", {"username": username, "password": PASSWORD}, format="json")
        self._auth(password=password, access=login.json()["access"])

    def _url(self, item, suffix=""):
        return f"/api/access-requests/{self.request_id}/items/{item['item_id']}/{suffix}"

    def _redeem(self, item, envelope=None):
        return self.client.post(
            self._url(item, "redeem/"), {"envelope": envelope or item["envelope"]}, format="json"
        )

    def test_redeem_then_open_the_record(self):
        response = self._redeem(self.file_item)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), {"item_id": self.file_item["item_id"], "kind": "FILE", "redeemed": True})
        opened = self.client.get(self._url(self.file_item))
        self.assertEqual(opened.status_code, status.HTTP_200_OK)
        self.assertEqual(opened.content, self.CONTENT)
        self.assertIn("lab-result.pdf", opened["Content-Disposition"])
        self.assertEqual(GrantedItem.objects.get(pk=self.file_item["item_id"]).access_count, 1)

    def test_redeem_then_open_the_profile(self):
        self._redeem(self.profile_item)
        self.assertEqual(self.client.get(self._url(self.profile_item)).json(), {"full_name": "Alice"})

    def test_open_before_redeem_is_refused(self):
        response = self.client.get(self._url(self.file_item))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_envelope_with_chat_line_breaks_still_works(self):
        text = self.file_item["envelope"]
        broken_up = text[:200] + "\n" + text[200:] + "\n"
        self.assertEqual(self._redeem(self.file_item, broken_up).status_code, status.HTTP_200_OK)

    def test_envelope_of_another_item_is_rejected(self):
        response = self._redeem(self.file_item, self.profile_item["envelope"])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_malformed_envelope_is_400(self):
        self.assertEqual(self._redeem(self.file_item, "hello").status_code, status.HTTP_400_BAD_REQUEST)

    def test_different_envelope_for_this_item_is_403(self):
        prefix = f"CSK1.{self.request_id}.{self.file_item['item_id']}."
        response = self._redeem(self.file_item, prefix + "A" * 512)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()["detail"], "This key is not for this item.")

    def test_wrong_password_is_refused(self):
        self._as("budi", password="not-the-password")
        self.assertEqual(self._redeem(self.file_item).status_code, status.HTTP_403_FORBIDDEN)

    def test_owner_and_outsiders_cannot_redeem(self):
        self._as("alice")
        self.assertEqual(self._redeem(self.file_item).status_code, status.HTTP_403_FORBIDDEN)
        self._as("citra")
        self.assertEqual(self._redeem(self.file_item).status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(self.client.get(self._url(self.file_item)).status_code, status.HTTP_404_NOT_FOUND)

    def test_redeem_stores_key_for_requester_only_encrypted(self):
        self._redeem(self.file_item)
        shared = GrantedItem.objects.get(pk=self.file_item["item_id"]).shared_key
        self.assertIsNotNone(shared.redeemed_at)
        self.assertEqual(len(bytes(shared.key_for_requester)), 32 + 16)  # K + GCM tag, never plain
        self.assertNotIn(parse_envelope(self.file_item["envelope"]).wrapped_key, bytes(shared.key_for_requester))

    def test_nothing_after_expiry(self):
        self._redeem(self.file_item)
        AccessRequest.objects.filter(pk=self.request_id).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.get(self._url(self.file_item)).status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(self._redeem(self.profile_item).status_code, status.HTTP_404_NOT_FOUND)

    def test_redeem_is_throttled(self):
        codes = [self._redeem(self.file_item, "hello").status_code for _ in range(11)]
        self.assertEqual(codes[-1], status.HTTP_429_TOO_MANY_REQUESTS)
