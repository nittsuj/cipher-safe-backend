"""Orchestration layer that ties the cipher primitives to the models.

The views stay thin and the encryption workflow can be tested directly. The
per-model knowledge lives on
:class:`~core.models.EncryptionEnvelope` (``apply_result`` / ``decrypt``), so
this module only sequences the use cases.

Every item is encrypted with all three algorithms, each in the mode chosen for
it in :data:`core.crypto.MODE_FOR`.
"""

from __future__ import annotations

import json

from django.core.files.base import ContentFile

from .constants import SUPPORTED_ALGORITHMS
from .crypto import encrypt
from .models import DownloadEvent, EncryptedValue, FileCiphertext, FileLabel, PersonalData, StoredFile

#: ``EncryptedValue.field_name`` of the single encrypted patient-profile record.
PROFILE_RECORD = "profile"


def encrypt_with_all_algorithms(data: bytes, password: str):
    """Encrypt ``data`` with every algorithm the assignment requires.

    Returns a mapping ``{algorithm: EncryptionResult}``.
    """

    return {algorithm: encrypt(data, password, algorithm=algorithm) for algorithm in SUPPORTED_ALGORITHMS}


def store_personal_data(personal_data: PersonalData, password: str, fields: dict[str, str]) -> None:
    """Encrypt and persist the patient profile with all three algorithms.

    The profile is serialised to one JSON document and encrypted as a single
    record, so a save costs three PBKDF2 derivations (one per algorithm)
    instead of three per field. It also hides which fields are filled in and
    how long each one is.
    """

    plaintext = json.dumps(fields, ensure_ascii=False, sort_keys=True).encode("utf-8")
    personal_data.values.filter(field_name=PROFILE_RECORD).delete()
    for result in encrypt_with_all_algorithms(plaintext, password).values():
        row = EncryptedValue(
            personal_data=personal_data,
            field_name=PROFILE_RECORD,
            plaintext_size=result.plaintext_size,
        )
        row.apply_result(result)
        row.save()
    personal_data.save(update_fields=["updated_at"])


def decrypt_personal_data(personal_data: PersonalData, password: str, algorithm: str) -> dict[str, str]:
    """Return the decrypted patient profile using the chosen algorithm."""

    row = personal_data.values.filter(field_name=PROFILE_RECORD, algorithm=algorithm).first()
    if row is None:
        return {}
    return json.loads(row.decrypt(password).plaintext.decode("utf-8"))


def store_file_ciphertexts(stored_file: StoredFile, data: bytes, password: str) -> list[FileCiphertext]:
    """Encrypt a file with all three algorithms and persist each ciphertext."""

    rows: list[FileCiphertext] = []
    for algorithm, result in encrypt_with_all_algorithms(data, password).items():
        row = FileCiphertext(file=stored_file)
        row.apply_result(result)
        row.blob.save(
            f"{stored_file.pk}-{algorithm}.bin",
            ContentFile(result.ciphertext),
            save=False,
        )
        row.save()
        rows.append(row)
    return rows


def store_file_label(stored_file: StoredFile, name: str, content_type: str, password: str) -> None:
    """Encrypt the file name and content type with all three algorithms."""

    plaintext = json.dumps({"name": name, "content_type": content_type}, ensure_ascii=False).encode("utf-8")
    for result in encrypt_with_all_algorithms(plaintext, password).values():
        row = FileLabel(file=stored_file)
        row.apply_result(result)
        row.save()


def decrypt_file_label(stored_file: StoredFile, password: str, algorithm: str = "AES") -> dict[str, str]:
    """Return ``{"name", "content_type"}`` for one file, decrypted with ``algorithm``."""

    row = next((label for label in stored_file.labels.all() if label.algorithm == algorithm), None)
    if row is None:
        return {"name": "", "content_type": ""}
    return json.loads(row.decrypt(password).plaintext.decode("utf-8"))


def decrypt_file_labels(files, password: str) -> dict[int, dict[str, str]]:
    """Decrypt the labels of several files (AES copy), keyed by file id.

    Each label has its own salt, so this costs one PBKDF2 derivation per file.
    """

    return {stored_file.pk: decrypt_file_label(stored_file, password) for stored_file in files}


def decrypt_file(ciphertext: FileCiphertext, password: str):
    """Verify and decrypt one stored ciphertext; returns the ``DecryptionResult``."""

    return ciphertext.decrypt(password)


def log_download(
    stored_file: StoredFile,
    algorithm: str,
    key_derivation_ms: float,
    cipher_ms: float,
    mac_ms: float,
    bytes_out: int,
    success: bool = True,
) -> DownloadEvent:
    """Record a retrieval for the running-time analysis."""

    return DownloadEvent.objects.create(
        owner=stored_file.owner,
        file=stored_file,
        algorithm=algorithm,
        success=success,
        bytes_out=bytes_out,
        key_derivation_ms=key_derivation_ms,
        cipher_ms=cipher_ms,
        mac_ms=mac_ms,
    )
