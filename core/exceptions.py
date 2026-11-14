"""API error mapping.

The crypto layer raises :class:`core.crypto.IntegrityError` when a tag does
not verify. The views verify the password against the user's hash before any
crypto work, so by the time a tag fails the stored data itself was modified.
:func:`exception_handler` turns that into one consistent HTTP 409 response,
so views do not need to catch it.
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler as drf_exception_handler

from .crypto import IntegrityError


class IntegrityCheckFailed(APIException):
    """The stored ciphertext failed its integrity check.

    The password has already been verified against the user's hash by the
    time this can happen, so a failed tag means the stored data (ciphertext,
    salt, IV or parameters) was modified. Nothing is returned rather than
    corrupted plaintext.
    """

    status_code = status.HTTP_409_CONFLICT
    default_detail = "Integrity check failed: the stored data has been modified."
    default_code = "integrity_check_failed"


class InvalidTransition(APIException):
    """An access request can't move from its current status (e.g. denying a
    request that was already cancelled)."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "This request can't be changed any more."
    default_code = "invalid_transition"


class RequesterHasNoKey(APIException):
    """The requester has no encryption key pair yet, so nothing can be
    encrypted for them. The server can't make one without their password."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The requester has no encryption key yet. Ask them to open Cipher Safe once."
    default_code = "requester_has_no_key"


class EnvelopeMismatch(APIException):
    """A pasted envelope is well formed but isn't the one made for this item."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "This key is not for this item."
    default_code = "envelope_mismatch"


class NotRedeemed(APIException):
    """The requester hasn't entered the key for this item yet."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Enter the key the owner sent you first."
    default_code = "not_redeemed"


class Conflict(APIException):
    """The request can't be done in the current state (e.g. already signed)."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "This can't be done in the current state."
    default_code = "conflict"


def exception_handler(exc, context):
    """DRF's handler, plus :class:`IntegrityError` -> HTTP 409."""

    if isinstance(exc, IntegrityError):
        exc = IntegrityCheckFailed()
    return drf_exception_handler(exc, context)
