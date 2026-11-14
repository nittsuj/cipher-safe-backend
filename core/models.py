from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from .constants import (
    ALGORITHM_CHOICES,
    FILE_CATEGORY_CHOICES,
    GRANT_KIND_CHOICES,
    GRANT_KIND_FILE,
    GRANT_KIND_PROFILE,
    KEY_PURPOSE_CHOICES,
    REQUEST_CATEGORY_CHOICES,
    REQUEST_PENDING,
    REQUEST_STATUS_CHOICES,
    ROLE_CHOICES,
    ROLE_PATIENT,
)
from .crypto import RSA_ALGORITHM, SealedData, WrappedKey
from .crypto import decrypt as decrypt_payload


class User(AbstractUser):
    """Custom user model (one per patient) holding **credentials only**.

    All GDPR / UU PDP personal data, including the health data that both laws
    treat as a special/specific category, is stored encrypted in
    :class:`PersonalData` and :class:`StoredFile`, never as a plain column here.

    ``role`` separates patients (who own a vault) from doctors (who can only
    open records a patient has shared with them, using the share key).
    """

    role = models.CharField(max_length=8, choices=ROLE_CHOICES, default=ROLE_PATIENT)

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


class UserKeyPair(models.Model):
    """An RSA key pair belonging to one user, for one purpose.

    The public key is public. The private key is stored only encrypted
    (AES-256-GCM under a key derived from the user's password, see
    :mod:`core.crypto.asymmetric`), and is decrypted in memory for one request
    at a time. Rotating a key keeps the old pair as inactive, so data already
    encrypted for it can still be opened.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="key_pairs")
    purpose = models.CharField(max_length=10, choices=KEY_PURPOSE_CHOICES)
    algorithm = models.CharField(max_length=16, default=RSA_ALGORITHM)
    public_key_pem = models.TextField()
    #: Self-signed X.509 certificate, only for signing keys.
    certificate_pem = models.TextField(blank=True)
    #: PKCS#8 private key encrypted with AES-256-GCM, tag appended.
    encrypted_private_key = models.BinaryField()
    kek_salt = models.BinaryField()
    nonce = models.BinaryField()
    fingerprint = models.CharField(max_length=95, db_index=True)
    active = models.BooleanField(default=True)
    generation_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "purpose"],
                condition=models.Q(active=True),
                name="uniq_active_key_pair",
            )
        ]

    @property
    def wrapped(self) -> WrappedKey:
        """The encrypted private key in the form :func:`unwrap_private_key` takes."""

        return WrappedKey(bytes(self.encrypted_private_key), bytes(self.kek_salt), bytes(self.nonce))

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return f"{self.user} {self.purpose} {self.algorithm} ({state})"


class AccessRequest(models.Model):
    """One user asking to see another user's private data.

    The requester can't name a file (file names are encrypted), so they send a
    message and an optional category hint; the owner decides what, if
    anything, to grant. Nothing here is secret, so no password is needed to
    create, list, deny or cancel a request.
    """

    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name="outgoing_requests")
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="incoming_requests")
    message = models.CharField(max_length=500, blank=True)
    category = models.CharField(max_length=12, choices=REQUEST_CATEGORY_CHOICES, blank=True)
    status = models.CharField(max_length=9, choices=REQUEST_STATUS_CHOICES, default=REQUEST_PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    #: When the owner approved, denied or revoked it (or the requester cancelled).
    decided_at = models.DateTimeField(null=True, blank=True)
    #: End of granted access; set on approval.
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.CheckConstraint(condition=~models.Q(requester=models.F("owner")), name="request_not_to_self"),
            models.UniqueConstraint(
                fields=["requester", "owner"],
                condition=models.Q(status=REQUEST_PENDING),
                name="uniq_pending_request",
            ),
        ]

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= timezone.now()

    def __str__(self) -> str:
        return f"{self.requester} -> {self.owner} ({self.status})"


class GrantedItem(models.Model):
    """One thing an owner granted on an approved request: a record or a
    snapshot of their profile.

    ``blob`` is a separate copy of the item, encrypted with AES-256-GCM under
    a fresh random key that belongs to this item only (see :class:`SharedKey`).
    For a record the payload also holds its name and type, so they stay
    encrypted too.
    """

    request = models.ForeignKey(AccessRequest, on_delete=models.CASCADE, related_name="items")
    kind = models.CharField(max_length=7, choices=GRANT_KIND_CHOICES)
    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, null=True, blank=True, related_name="grants")
    blob = models.FileField(upload_to="grants/%Y/%m/")
    nonce = models.BinaryField()
    plaintext_size = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    access_count = models.PositiveIntegerField(default=0)
    last_accessed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["id"]
        constraints = [
            # A record item points at its record; a profile snapshot doesn't.
            models.CheckConstraint(
                condition=(
                    models.Q(kind=GRANT_KIND_FILE, file__isnull=False)
                    | models.Q(kind=GRANT_KIND_PROFILE, file__isnull=True)
                ),
                name="grant_kind_matches_file",
            ),
            models.UniqueConstraint(fields=["request", "file"], name="uniq_grant_per_file"),
            models.UniqueConstraint(
                fields=["request"], condition=models.Q(kind=GRANT_KIND_PROFILE), name="uniq_profile_grant"
            ),
        ]

    @property
    def aad(self) -> bytes:
        """Associated data for the item copy: binds it to its request, item and kind."""

        return f"cipher-safe/grant:{self.request_id}:{self.pk}:{self.kind}".encode("ascii")

    def sealed(self) -> SealedData:
        self.blob.seek(0)
        return SealedData(bytes(self.nonce), bytes(self.blob.read()))

    def __str__(self) -> str:
        return f"Grant {self.pk} ({self.kind}) on request {self.request_id}"


class SharedKey(models.Model):
    """The random AES key of one granted item, stored only in wrapped form.

    * ``key_for_owner``: the key encrypted with the **owner's** password-derived
      key, so the owner can show the envelope again without a new key.
    * ``key_for_requester``: the same key under the **requester's**
      password-derived key, written when they redeem the envelope.
    * ``envelope_for_owner``: the RSA-wrapped key (the envelope) encrypted
      under the same owner key, so the owner can show the **same** envelope
      again. OAEP is randomised, so rebuilding it would give a different one.
    * ``envelope_sha256``: hash of the RSA-wrapped key, to check a pasted
      envelope before any RSA work.

    The plain key is never stored.
    """

    item = models.OneToOneField(GrantedItem, on_delete=models.CASCADE, related_name="shared_key")
    key_for_owner = models.BinaryField()
    owner_salt = models.BinaryField()
    owner_nonce = models.BinaryField()
    envelope_for_owner = models.BinaryField(default=b"")
    envelope_nonce = models.BinaryField(default=b"")
    key_for_requester = models.BinaryField(null=True, blank=True)
    requester_salt = models.BinaryField(null=True, blank=True)
    requester_nonce = models.BinaryField(null=True, blank=True)
    envelope_sha256 = models.CharField(max_length=64)
    #: The public key the envelope was made for; kept even after rotation.
    requester_key = models.ForeignKey(UserKeyPair, on_delete=models.PROTECT, related_name="shared_keys")
    redeemed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def aad(self, side: str) -> bytes:
        """Associated data for one stored copy of the key (``owner`` or ``requester``)."""

        return f"cipher-safe/sharedkey:{self.item_id}:{side}".encode("ascii")

    @property
    def redeemed(self) -> bool:
        return self.redeemed_at is not None

    def __str__(self) -> str:
        return f"Key for grant {self.item_id}"
