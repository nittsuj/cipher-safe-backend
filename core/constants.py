"""Shared constants for the core app.

This is the single source of truth for the ``choices`` pairs used by models and
serializers. The algorithm and mode sets come from :mod:`core.crypto` (which
stays framework free); the file-category choices are defined here.
"""

from __future__ import annotations

from .crypto import DEFAULT_MODE, MODE_FOR, SUPPORTED_ALGORITHMS, SUPPORTED_MODES

ALGORITHM_CHOICES = [(value, value) for value in SUPPORTED_ALGORITHMS]
MODE_CHOICES = [(value, value) for value in SUPPORTED_MODES]

#: What a patient keeps in the vault. The keys are stable identifiers; the
#: labels describe the medical-records scenario.
FILE_CATEGORY_CHOICES = [
    ("ID_CARD", "Identity / insurance card scan (KTP, BPJS card)"),
    ("DOCUMENT", "Medical document (lab result, referral letter, medication log)"),
    ("VIDEO", "Medical video (ultrasound, echocardiogram, endoscopy)"),
]

#: Account roles. Patients own a vault; doctors only receive shared records.
ROLE_PATIENT = "PATIENT"
ROLE_DOCTOR = "DOCTOR"
ROLE_CHOICES = [(ROLE_PATIENT, "Patient"), (ROLE_DOCTOR, "Doctor")]

#: What a user key pair is for. Separate pairs keep the key that decrypts
#: shared-record keys apart from the key that signs PDFs.
KEY_PURPOSE_ENCRYPTION = "ENCRYPTION"
KEY_PURPOSE_SIGNING = "SIGNING"
KEY_PURPOSE_CHOICES = [(KEY_PURPOSE_ENCRYPTION, "Encryption"), (KEY_PURPOSE_SIGNING, "Signing")]

#: Lifecycle of an access request (one user asking for another user's data).
#: Expiry is computed from ``expires_at``, not stored as a status.
REQUEST_PENDING = "PENDING"
REQUEST_APPROVED = "APPROVED"
REQUEST_DENIED = "DENIED"
REQUEST_CANCELLED = "CANCELLED"
REQUEST_REVOKED = "REVOKED"
REQUEST_STATUS_CHOICES = [
    (REQUEST_PENDING, "Pending"),
    (REQUEST_APPROVED, "Approved"),
    (REQUEST_DENIED, "Denied"),
    (REQUEST_CANCELLED, "Cancelled"),
    (REQUEST_REVOKED, "Revoked"),
]

#: What a requester may hint at: a record category, or the profile.
REQUEST_CATEGORY_PROFILE = "PROFILE"
REQUEST_CATEGORY_CHOICES = FILE_CATEGORY_CHOICES + [(REQUEST_CATEGORY_PROFILE, "Patient profile")]

#: Content types the browser may render inline in a preview. Anything else
#: (HTML, SVG, ...) could run script, so it is only offered as a download.
PREVIEWABLE_TYPES = (
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "video/mp4",
    "video/webm",
    "video/ogg",
    "text/plain",
)

__all__ = [
    "REQUEST_APPROVED",
    "REQUEST_CANCELLED",
    "REQUEST_CATEGORY_CHOICES",
    "REQUEST_CATEGORY_PROFILE",
    "REQUEST_DENIED",
    "REQUEST_PENDING",
    "REQUEST_REVOKED",
    "REQUEST_STATUS_CHOICES",
    "KEY_PURPOSE_CHOICES",
    "KEY_PURPOSE_ENCRYPTION",
    "KEY_PURPOSE_SIGNING",
    "PREVIEWABLE_TYPES",
    "ROLE_CHOICES",
    "ROLE_DOCTOR",
    "ROLE_PATIENT",
    "ALGORITHM_CHOICES",
    "MODE_CHOICES",
    "FILE_CATEGORY_CHOICES",
    "DEFAULT_MODE",
    "MODE_FOR",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
]
