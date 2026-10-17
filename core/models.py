from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models

from .constants import ALGORITHM_CHOICES, FILE_CATEGORY_CHOICES
from .crypto import decrypt as decrypt_payload


class User(AbstractUser):
    """Custom user model holding **authentication credentials only**.

    The assignment requires a username + password pair to access data. All
    GDPR / UU PDP personal data is stored encrypted in :class:`PersonalData`,
    never as a plain column here.
    """

    def __str__(self) -> str:
        return self.username


class PersonalData(models.Model):
    """Container for the user's private attributes.

    The actual values are never stored in the clear; each field is kept as one
    :class:`EncryptedValue` row per algorithm (AES / DES / RC4).
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
    ciphertext_size = models.BigIntegerField(default=0)
    key_derivation_ms = models.FloatField(default=0.0)
    cipher_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms

    def apply_result(self, result) -> None:
        """Populate the shared fields from a ``crypto.EncryptionResult``."""

        self.algorithm = result.algorithm
        self.mode = result.mode
        self.salt = result.salt
        self.iv = result.iv
        self.ciphertext_size = len(result.ciphertext)
        self.key_derivation_ms = result.key_derivation_ms
        self.cipher_ms = result.cipher_ms

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
    """A single personal-data field, encrypted with one algorithm."""

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
    """A user file: ID card image, document or video."""

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="files")
    category = models.CharField(max_length=12, choices=FILE_CATEGORY_CHOICES)
    original_name = models.CharField(max_length=255)
    content_type = models.CharField(max_length=128, blank=True)
    plaintext_size = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.original_name} ({self.get_category_display()})"


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
        return f"{self.file.original_name} [{self.algorithm}]"


class DownloadEvent(models.Model):
    """Audit row for every decryption/download, used for the timing analysis.

    The assignment asks to download data multiple times and measure running
    time, so each retrieval is recorded here.
    """

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="downloads")
    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, related_name="downloads")
    algorithm = models.CharField(max_length=3, choices=ALGORITHM_CHOICES)
    success = models.BooleanField(default=True)
    bytes_out = models.BigIntegerField(default=0)
    key_derivation_ms = models.FloatField(default=0.0)
    cipher_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def total_ms(self) -> float:
        return self.key_derivation_ms + self.cipher_ms

    def __str__(self) -> str:
        return f"{self.file.original_name} [{self.algorithm}] {self.total_ms:.1f} ms"
