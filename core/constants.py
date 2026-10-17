"""Shared constants for the core app.

This is the single source of truth for the ``choices`` pairs used by models and
serializers. The algorithm and mode sets come from :mod:`core.crypto` (which
stays framework free); the file-category choices are defined here.
"""

from __future__ import annotations

from .crypto import DEFAULT_MODE, SUPPORTED_ALGORITHMS, SUPPORTED_MODES

ALGORITHM_CHOICES = [(value, value) for value in SUPPORTED_ALGORITHMS]
MODE_CHOICES = [(value, value) for value in SUPPORTED_MODES]

FILE_CATEGORY_CHOICES = [
    ("ID_CARD", "ID card image"),
    ("DOCUMENT", "PDF / DOC / XLS document"),
    ("VIDEO", "Video"),
    ("OTHER", "Other"),
]

__all__ = [
    "ALGORITHM_CHOICES",
    "MODE_CHOICES",
    "FILE_CATEGORY_CHOICES",
    "DEFAULT_MODE",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
]
