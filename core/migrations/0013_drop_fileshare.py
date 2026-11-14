"""Drop the old doctor shares (``FileShare``) and their files on disk.

Sharing now goes through access requests. The historical model used here
doesn't trigger the app's ``post_delete`` handler, so each share's encrypted
file is deleted explicitly before the rows and the table go.
"""

from django.db import migrations


def delete_share_blobs(apps, schema_editor):
    FileShare = apps.get_model("core", "FileShare")
    for share in FileShare.objects.all().iterator():
        if share.blob:
            share.blob.storage.delete(share.blob.name)
        share.delete()


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0012_envelope_for_owner'),
    ]

    operations = [
        # Going back only recreates the empty table; the old shares are gone.
        migrations.RunPython(delete_share_blobs, migrations.RunPython.noop),
        migrations.DeleteModel(
            name='FileShare',
        ),
    ]
