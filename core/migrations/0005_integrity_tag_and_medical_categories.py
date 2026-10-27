# Adds the encrypt-then-MAC tag and MAC timing, and relabels the file
# categories for the patient-held medical records scenario.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_rename_kind_storedfile_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='encryptedvalue',
            name='tag',
            field=models.BinaryField(default=b''),
        ),
        migrations.AddField(
            model_name='encryptedvalue',
            name='mac_ms',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='fileciphertext',
            name='tag',
            field=models.BinaryField(default=b''),
        ),
        migrations.AddField(
            model_name='fileciphertext',
            name='mac_ms',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='downloadevent',
            name='mac_ms',
            field=models.FloatField(default=0.0),
        ),
        migrations.AlterField(
            model_name='storedfile',
            name='category',
            field=models.CharField(
                choices=[
                    ('ID_CARD', 'Identity / insurance card scan (KTP, BPJS card)'),
                    ('DOCUMENT', 'Medical document (lab result, referral letter, medication log)'),
                    ('VIDEO', 'Medical video (ultrasound, echocardiogram, endoscopy)'),
                ],
                max_length=12,
            ),
        ),
    ]
