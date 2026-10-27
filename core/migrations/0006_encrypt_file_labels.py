# Moves the file name and content type out of StoredFile into an encrypted
# FileLabel (one row per algorithm). Existing names cannot be encrypted without
# the owner's password, so they are dropped; re-upload any existing records.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_integrity_tag_and_medical_categories'),
    ]

    operations = [
        migrations.CreateModel(
            name='FileLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('algorithm', models.CharField(choices=[('AES', 'AES'), ('DES', 'DES'), ('RC4', 'RC4')], max_length=3)),
                ('mode', models.CharField(blank=True, max_length=8)),
                ('salt', models.BinaryField()),
                ('iv', models.BinaryField(blank=True, null=True)),
                ('tag', models.BinaryField(default=b'')),
                ('ciphertext_size', models.BigIntegerField(default=0)),
                ('key_derivation_ms', models.FloatField(default=0.0)),
                ('cipher_ms', models.FloatField(default=0.0)),
                ('mac_ms', models.FloatField(default=0.0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ciphertext', models.BinaryField()),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='labels', to='core.storedfile')),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('file', 'algorithm'), name='uniq_file_label_algorithm')],
            },
        ),
        migrations.RemoveField(
            model_name='storedfile',
            name='original_name',
        ),
        migrations.RemoveField(
            model_name='storedfile',
            name='content_type',
        ),
    ]
