"""Orchestration layer that ties the cipher primitives to the models.

Keeping this separate from the views makes the encryption workflow easy to
reason about, test and justify in the report. The per-model knowledge lives on
:class:`~core.models.EncryptionEnvelope` (``apply_result`` / ``decrypt``), so
this module only sequences the use cases.
"""

from __future__ import annotations

from django.core.files.base import ContentFile

from .constants import DEFAULT_MODE, SUPPORTED_ALGORITHMS
from .crypto import encrypt
from .models import DownloadEvent, EncryptedValue, FileCiphertext, PersonalData, StoredFile


def encrypt_with_all_algorithms(data: bytes, password: str, mode: str = DEFAULT_MODE):
    """Encrypt ``data`` with every algorithm the assignment requires.

    Returns a mapping ``{algorithm: EncryptionResult}``.
    """

    return {
        algorithm: encrypt(data, password, algorithm=algorithm, mode=mode)
        for algorithm in SUPPORTED_ALGORITHMS
    }


def store_personal_data(
    personal_data: PersonalData,
    password: str,
    fields: dict[str, str],
    mode: str = DEFAULT_MODE,
) -> None:
    """Encrypt and persist the supplied PII fields with all three algorithms."""

    for field_name, value in fields.items():
        plaintext = str(value).encode("utf-8")
        personal_data.values.filter(field_name=field_name).delete()
        for result in encrypt_with_all_algorithms(plaintext, password, mode).values():
            row = EncryptedValue(
                personal_data=personal_data,
                field_name=field_name,
                plaintext_size=result.plaintext_size,
            )
            row.apply_result(result)
            row.save()


def decrypt_personal_data(
    personal_data: PersonalData,
    password: str,
    algorithm: str,
) -> dict[str, str]:
    """Return ``{field_name: plaintext}`` using the chosen algorithm."""

    return {
        value.field_name: value.decrypt(password).plaintext.decode("utf-8")
        for value in personal_data.values.filter(algorithm=algorithm)
    }


def store_file_ciphertexts(
    stored_file: StoredFile,
    data: bytes,
    password: str,
    mode: str = DEFAULT_MODE,
) -> list[FileCiphertext]:
    """Encrypt a file with all three algorithms and persist each ciphertext."""

    rows: list[FileCiphertext] = []
    for algorithm, result in encrypt_with_all_algorithms(data, password, mode).items():
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


def decrypt_file(ciphertext: FileCiphertext, password: str) -> tuple[bytes, float, float]:
    """Decrypt one stored ciphertext; returns ``(plaintext, kdf_ms, cipher_ms)``."""

    result = ciphertext.decrypt(password)
    return result.plaintext, result.key_derivation_ms, result.cipher_ms


def log_download(
    stored_file: StoredFile,
    algorithm: str,
    key_derivation_ms: float,
    cipher_ms: float,
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
    )
