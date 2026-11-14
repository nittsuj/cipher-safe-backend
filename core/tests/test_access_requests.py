from __future__ import annotations

from datetime import timedelta

from django.db import IntegrityError as DatabaseIntegrityError
from django.test import TestCase
from django.utils import timezone

from ..constants import REQUEST_APPROVED, REQUEST_DENIED, REQUEST_PENDING
from ..models import AccessRequest, User

from .base import PASSWORD


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
