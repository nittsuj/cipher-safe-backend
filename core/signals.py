"""Remove ciphertext files from disk when their database row is deleted.

Django never deletes a ``FileField``'s file when the row goes away, so without
this a deleted record, share or user account would leave its encrypted blobs
in ``MEDIA_ROOT``. Connecting to ``post_delete`` covers every way a row can be
deleted: the API, the admin, and cascades (e.g. deleting a user deletes their
records and shares).

The file is removed only after the transaction commits, so a rolled-back
delete never leaves a row pointing at a missing file.
"""

from __future__ import annotations

from django.db import transaction
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import FileCiphertext, FileShare


@receiver(post_delete, sender=FileCiphertext, dispatch_uid="core.delete_ciphertext_blob")
@receiver(post_delete, sender=FileShare, dispatch_uid="core.delete_share_blob")
def delete_blob(sender, instance, **kwargs) -> None:
    if not instance.blob:
        return
    storage, name = instance.blob.storage, instance.blob.name
    transaction.on_commit(lambda: storage.delete(name))
