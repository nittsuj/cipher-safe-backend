from __future__ import annotations

import os
from datetime import timedelta

from django.core.files.base import ContentFile
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from .base import PASSWORD_HASHERS, TEST_MEDIA_ROOT

BEFORE = [("core", "0012_envelope_for_owner")]
AFTER = [("core", "0013_drop_fileshare")]


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, PASSWORD_HASHERS=PASSWORD_HASHERS)
class DropFileShareMigrationTests(TransactionTestCase):
    """A database with old shares migrates cleanly, and their files are deleted."""

    def setUp(self):
        executor = MigrationExecutor(connection)
        executor.migrate(BEFORE)
        apps = executor.loader.project_state(BEFORE).apps
        User = apps.get_model("core", "User")
        StoredFile = apps.get_model("core", "StoredFile")
        self.FileShare = apps.get_model("core", "FileShare")

        patient = User.objects.create(username="alice", role="PATIENT")
        doctor = User.objects.create(username="budi", role="DOCTOR")
        record = StoredFile.objects.create(owner=patient, category="DOCUMENT", plaintext_size=4)
        self.paths = []
        for _ in range(2):
            share = self.FileShare(
                file=record,
                doctor=doctor,
                expires_at=timezone.now() + timedelta(hours=1),
                algorithm="AES",
                mode="GCM",
                salt=b"s" * 16,
                tag=b"t" * 16,
            )
            share.blob.save("old-share.bin", ContentFile(b"ciphertext"), save=False)
            share.save()
            self.paths.append(share.blob.path)

    def tearDown(self):
        # Leave the database at the latest migration for the other tests.
        MigrationExecutor(connection).migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())

    def test_migration_deletes_shares_and_their_files(self):
        self.assertTrue(all(os.path.exists(path) for path in self.paths))
        executor = MigrationExecutor(connection)
        executor.loader.build_graph()
        executor.migrate(AFTER)
        self.assertFalse(any(os.path.exists(path) for path in self.paths))
        self.assertNotIn("core_fileshare", connection.introspection.table_names())
