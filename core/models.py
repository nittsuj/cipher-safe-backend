from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models

from .constants import ALGORITHM_CHOICES, FILE_CATEGORY_CHOICES
from .crypto import decrypt as decrypt_payload


class User(AbstractUser):
    """Custom user model (one per patient) holding **credentials only**.

    All GDPR / UU PDP personal data, including the health data that both laws
    treat as a special/specific category, is stored encrypted in
    :class:`PersonalData` and :class:`StoredFile`, never as a plain column here.
    """

    def __str__(self) -> str:
        return self.username


class PersonalData(models.Model):
    """Container for the patient's profile: identity and medical attributes.

    The values are never stored in the clear. The whole profile is serialised
    to one JSON record and kept as one :class:`EncryptedValue` row per
    algorithm (AES / DES / RC4), so saving the profile costs three key
    derivations instead of three per field.
    """

    owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="personal_data")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"PersonalData({self.owner.username})"


class EncryptionEnvelope(models.Model):
    """Shared shape of one encrypted copy of something, per algorithm.

    Abstract: it carries the fields every ciphertext needs (algorithm, mode,
    salt, IV, timings) plus the logic to be populated from a crypto result and
    to be decrypted again. Subclasses decide *where* the ciphertext bytes live.
    """

    algorithm = models.CharField(max_length=3, choices=ALGORITHM_CHOICES)
    mode = models.CharField(max_length=8, blank=True)
    salt = models.BinaryField()
    iv = models.BinaryField(null=True, blank=True)
    #: HMAC-SHA256 over algorithm, mode, salt, IV and ciphertext
    #: (encrypt-then-MAC); verified before every decryption.
    tag = models.BinaryField(default=b"")
    ciphertext_size = models.BigIntegerField(default=0)
    key_derivation_ms = models.FloatField(default=0.0)
    cipher_ms = models.FloatField(default=0.0)
    mac_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms + self.mac_ms

    def apply_result(self, result) -> None:
        """Populate the shared fields from a ``crypto.EncryptionResult``."""

        self.algorithm = result.algorithm
        self.mode = result.mode
        self.salt = result.salt
        self.iv = result.iv
        self.tag = result.tag
        self.ciphertext_size = len(result.ciphertext)
        self.key_derivation_ms = result.key_derivation_ms
        self.cipher_ms = result.cipher_ms
        self.mac_ms = result.mac_ms

    def _payload(self) -> bytes:
        raise NotImplementedError

    def decrypt(self, password: str):
        """Decrypt this envelope with the user's password."""

        return decrypt_payload(
            self._payload(),
            password,
            algorithm=self.algorithm,
            salt=bytes(self.salt),
            iv=bytes(self.iv) if self.iv is not None else None,
            mode=self.mode,
            tag=bytes(self.tag),
        )


class InlineCiphertext(EncryptionEnvelope):
    """An envelope whose ciphertext is stored inline in the database."""

    ciphertext = models.BinaryField()

    class Meta:
        abstract = True

    def apply_result(self, result) -> None:
        super().apply_result(result)
        self.ciphertext = result.ciphertext

    def _payload(self) -> bytes:
        return bytes(self.ciphertext)


class EncryptedValue(InlineCiphertext):
    """The encrypted patient-profile record, under one algorithm.

    ``field_name`` names the record (currently always ``"profile"``); it is
    kept so the schema can hold more than one record per patient later.
    """

    personal_data = models.ForeignKey(PersonalData, on_delete=models.CASCADE, related_name="values")
    field_name = models.CharField(max_length=64)
    plaintext_size = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["personal_data", "field_name", "algorithm"],
                name="uniq_personal_field_algorithm",
            )
        ]

    def __str__(self) -> str:
        return f"{self.field_name} [{self.algorithm}]"


class StoredFile(models.Model):
    """A patient file: identity/insurance card scan, medical document or
    medical video.

    Only the category, size and upload date are stored in the clear, so the
    vault can list and filter records. The file name and type can reveal
    health information on their own (``HIV-test.pdf``), so they are encrypted
    in :class:`FileLabel`.
    """

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="files")
    category = models.CharField(max_length=12, choices=FILE_CATEGORY_CHOICES)
    plaintext_size = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Record {self.pk} ({self.get_category_display()})"


class FileCiphertext(EncryptionEnvelope):
    """One encrypted copy of a :class:`StoredFile`, per algorithm.

    Ciphertext blobs live on disk under ``MEDIA_ROOT`` so large video files do
    not bloat the database.
    """

    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, related_name="ciphertexts")
    blob = models.FileField(upload_to="ciphertexts/%Y/%m/")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["file", "algorithm"], name="uniq_file_algorithm")
        ]

    def _payload(self) -> bytes:
        self.blob.seek(0)
        return bytes(self.blob.read())

    def __str__(self) -> str:
        return f"Record {self.file_id} [{self.algorithm}]"


class FileLabel(InlineCiphertext):
    """The encrypted name and content type of a :class:`StoredFile`, per
    algorithm, stored as one small JSON record."""

    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, related_name="labels")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["file", "algorithm"], name="uniq_file_label_algorithm")
        ]

    def __str__(self) -> str:
        return f"Record {self.file_id} label [{self.algorithm}]"


class DownloadEvent(models.Model):
    """One row per retrieval of a record.

    Tells the patient when each record was opened, and supplies the per-cipher
    running times for the analysis.
    """

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="downloads")
    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, related_name="downloads")
    algorithm = models.CharField(max_length=3, choices=ALGORITHM_CHOICES)
    success = models.BooleanField(default=True)
    bytes_out = models.BigIntegerField(default=0)
    key_derivation_ms = models.FloatField(default=0.0)
    cipher_ms = models.FloatField(default=0.0)
    mac_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms + self.mac_ms

    def __str__(self) -> str:
        return f"Record {self.file_id} [{self.algorithm}] {self.total_ms:.1f} ms"
