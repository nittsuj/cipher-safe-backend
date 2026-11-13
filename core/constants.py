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
