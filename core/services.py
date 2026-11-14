"""Orchestration layer that ties the cipher primitives to the models.

The views stay thin and the encryption workflow can be tested directly. The
per-model knowledge lives on
:class:`~core.models.EncryptionEnvelope` (``apply_result`` / ``decrypt``), so
this module only sequences the use cases.

Every item is encrypted with all three algorithms, each in the mode chosen for
it in :data:`core.crypto.MODE_FOR`.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import timedelta

from django.core.files.base import ContentFile
from django.db import IntegrityError as DatabaseIntegrityError
from django.db import transaction
from django.db.models import Avg, Count, F, Max, Min
from django.utils import timezone

from .constants import (
    GRANT_KIND_FILE,
    GRANT_KIND_PROFILE,
    KEY_PURPOSE_ENCRYPTION,
    KEY_PURPOSE_SIGNING,
    MODE_FOR,
    REQUEST_APPROVED,
    REQUEST_CANCELLED,
    REQUEST_DENIED,
    REQUEST_PENDING,
    REQUEST_REVOKED,
    SUPPORTED_ALGORITHMS,
)
from .signing import NotAPdf, is_pdf, sign_pdf
from .exceptions import EnvelopeMismatch, InvalidTransition, NotRedeemed, RequesterHasNoKey
from .crypto import (
    SYMMETRIC_KEY_SIZE,
    SealedData,
    build_signing_certificate,
    certificate_fingerprint,
    certificate_pem,
    decrypt_with_key,
    derive_key,
    encrypt,
    encrypt_with_key,
    envelope_digest,
    format_envelope,
    load_certificate,
    load_public_key,
    new_salt,
    new_symmetric_key,
    parse_envelope,
    unwrap_key,
    wrap_key,
    fingerprint,
    generate_rsa_key_pair,
    key_pair_aad,
    public_key_pem,
    unwrap_private_key,
    wrap_private_key,
)
from .models import (
    AccessRequest,
    DownloadEvent,
    EncryptedValue,
    FileCiphertext,
    FileLabel,
    GrantedItem,
    PdfSignature,
    PersonalData,
    SharedKey,
    StoredFile,
    UserKeyPair,
)

#: ``EncryptedValue.field_name`` of the single encrypted patient-profile record.
PROFILE_RECORD = "profile"

#: Timings of key generation, wrapping and unwrapping go here (for the report).
key_log = logging.getLogger("core.keys")


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


def store_record(
    owner,
    category: str,
    name: str,
    content_type: str,
    data: bytes,
    password: str,
    signature: SignedPdf | None = None,
) -> StoredFile:
    """Create a record: its row, encrypted label and three encrypted copies.

    With ``signature`` the data is the already **signed** PDF, so what gets
    encrypted is the signed file, and the signature is recorded alongside.
    Runs in one transaction, so a failure leaves no half-stored record in the
    database.
    """

    with transaction.atomic():
        stored_file = StoredFile.objects.create(owner=owner, category=category, plaintext_size=len(data))
        store_file_label(stored_file, name, content_type, password)
        store_file_ciphertexts(stored_file, data, password)
        if signature is not None:
            PdfSignature.objects.create(
                file=stored_file,
                key_pair=signature.key_pair,
                signer_fingerprint=signature.key_pair.fingerprint,
                sign_ms=signature.sign_ms,
            )
    return stored_file


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


def benchmark_decryption(ciphertext: FileCiphertext, password: str, runs: int) -> dict:
    """Decrypt ``ciphertext`` ``runs`` times and summarise the timings.

    ``samples_ms`` is the full decrypt (key setup + cipher + integrity check).
    ``cipher_samples_ms`` leaves out key setup: PBKDF2 costs the same for every
    algorithm and would hide the difference between them.
    """

    samples: list[float] = []
    cipher_samples: list[float] = []
    for _ in range(runs):
        result = ciphertext.decrypt(password)
        samples.append(result.total_ms)
        cipher_samples.append(result.cipher_ms + result.mac_ms)
    return {
        "samples_ms": samples,
        "min_ms": min(samples),
        "max_ms": max(samples),
        "mean_ms": sum(samples) / len(samples),
        "cipher_samples_ms": cipher_samples,
        "cipher_mean_ms": sum(cipher_samples) / len(cipher_samples),
    }


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


# --- Payload packing (record name, type and bytes in one ciphertext) ----------


def pack_share_payload(label: dict[str, str], data: bytes) -> bytes:
    """``len(label) || label JSON || file bytes``: one ciphertext holds both."""

    header = json.dumps(label, ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(header)) + header + data


def unpack_share_payload(payload: bytes) -> tuple[dict[str, str], bytes]:
    (size,) = struct.unpack(">I", payload[:4])
    return json.loads(payload[4 : 4 + size].decode("utf-8")), payload[4 + size :]


def timing_summary(owner) -> dict:
    """Running times per algorithm for one patient (Analysis page).

    ``downloads`` aggregates successful decryptions; ``encryptions`` aggregates
    the stored copies (one per record and algorithm).
    """

    total = F("key_derivation_ms") + F("cipher_ms") + F("mac_ms")
    downloads = (
        DownloadEvent.objects.filter(owner=owner, success=True)
        .annotate(total_ms=total)
        .values("algorithm")
        .annotate(
            runs=Count("id"),
            min_ms=Min("total_ms"),
            max_ms=Max("total_ms"),
            mean_ms=Avg("total_ms"),
        )
        .order_by("algorithm")
    )
    encryptions = (
        FileCiphertext.objects.filter(file__owner=owner)
        .annotate(total_ms=total)
        .values("algorithm")
        .annotate(
            files=Count("id"),
            min_ms=Min("total_ms"),
            max_ms=Max("total_ms"),
            mean_ms=Avg("total_ms"),
            mean_ciphertext_size=Avg("ciphertext_size"),
        )
        .order_by("algorithm")
    )
    return {
        "supported_algorithms": list(SUPPORTED_ALGORITHMS),
        "modes": MODE_FOR,
        "downloads": list(downloads),
        "encryptions": list(encryptions),
    }


# ---------------------------------------------------------------- key pairs


def active_key_pair(user, purpose: str) -> UserKeyPair | None:
    """The user's active key pair for ``purpose``, or ``None``."""

    return UserKeyPair.objects.filter(user=user, purpose=purpose, active=True).first()


def _create_key_pair(user, purpose: str, password: str) -> UserKeyPair:
    """Generate a pair and store it with the private key wrapped by ``password``.

    A signing pair also gets a self-signed X.509 certificate (PDF signatures
    carry it), and its fingerprint is the certificate's, the value PDF readers
    show. The private key exists unencrypted only inside this call.
    """

    started = time.perf_counter()
    private_key = generate_rsa_key_pair()
    generation_ms = (time.perf_counter() - started) * 1000
    public_key = private_key.public_key()
    wrapped = wrap_private_key(private_key, password, key_pair_aad(user.pk, purpose))
    certificate_text, shown_fingerprint = "", fingerprint(public_key)
    if purpose == KEY_PURPOSE_SIGNING:
        certificate = build_signing_certificate(private_key, user.username)
        certificate_text, shown_fingerprint = certificate_pem(certificate), certificate_fingerprint(certificate)
    return UserKeyPair.objects.create(
        user=user,
        purpose=purpose,
        public_key_pem=public_key_pem(public_key),
        certificate_pem=certificate_text,
        encrypted_private_key=wrapped.ciphertext,
        kek_salt=wrapped.salt,
        nonce=wrapped.nonce,
        fingerprint=shown_fingerprint,
        generation_ms=round(generation_ms, 3),
    )


def ensure_key_pair(user, purpose: str, password: str) -> tuple[UserKeyPair, bool]:
    """Return the user's active pair for ``purpose``, generating one if needed.

    Returns ``(pair, created)``. Two requests racing to create the first pair
    hit the one-active-pair constraint; the loser returns the winner's pair.
    """

    existing = active_key_pair(user, purpose)
    if existing is not None:
        return existing, False
    try:
        with transaction.atomic():
            return _create_key_pair(user, purpose, password), True
    except DatabaseIntegrityError:
        return UserKeyPair.objects.get(user=user, purpose=purpose, active=True), False


def rotate_key_pair(user, purpose: str, password: str) -> UserKeyPair:
    """Replace the active pair with a new one; the old pair stays, inactive.

    Data already encrypted for the old public key can still be opened with the
    old private key, so old pairs are never deleted here.
    """

    with transaction.atomic():
        UserKeyPair.objects.select_for_update().filter(user=user, purpose=purpose, active=True).update(active=False)
        return _create_key_pair(user, purpose, password)


def load_private_key(pair: UserKeyPair, password: str):
    """Decrypt a pair's private key in memory, for use within one request.

    Raises :class:`core.crypto.IntegrityError` for a wrong password or a
    modified key (HTTP 409 through the exception handler).
    """

    return unwrap_private_key(pair.wrapped, password, key_pair_aad(pair.user_id, pair.purpose))


# ---------------------------------------------------------- access requests


def _decide(access_request: AccessRequest, allowed_from: str, new_status: str) -> AccessRequest:
    """Move a request to ``new_status`` if it is still in ``allowed_from``.

    The row is locked, so a deny and a cancel arriving together can't both win.
    """

    with transaction.atomic():
        locked = AccessRequest.objects.select_for_update().get(pk=access_request.pk)
        if locked.status != allowed_from:
            raise InvalidTransition(f"This request is already {locked.status.lower()}.")
        locked.status = new_status
        locked.decided_at = timezone.now()
        locked.save(update_fields=["status", "decided_at"])
    return locked


def deny_request(access_request: AccessRequest) -> AccessRequest:
    """Owner refuses a pending request."""

    return _decide(access_request, REQUEST_PENDING, REQUEST_DENIED)


def cancel_request(access_request: AccessRequest) -> AccessRequest:
    """Requester withdraws a pending request."""

    return _decide(access_request, REQUEST_PENDING, REQUEST_CANCELLED)



# ------------------------------------------------- approving with item keys


def user_kek(password: str, salt: bytes) -> bytes:
    """Key-encryption key for one user's stored copies of item keys: PBKDF2 of
    their password, the same protection as their own data."""

    return derive_key(password, salt, SYMMETRIC_KEY_SIZE)


def seal_key_for_user(key: bytes, password: str, aad: bytes) -> tuple[SealedData, bytes]:
    """Encrypt an item key with a key derived from a user's password.

    Returns ``(sealed, salt)``: PBKDF2 with a fresh salt, then AES-256-GCM.
    """

    salt = new_salt()
    return encrypt_with_key(key, user_kek(password, salt), aad), salt


def open_key_for_user(sealed: SealedData, salt: bytes, password: str, aad: bytes) -> bytes:
    """Reverse of :func:`seal_key_for_user`; ``IntegrityError`` on a wrong password."""

    return decrypt_with_key(sealed, derive_key(password, salt, SYMMETRIC_KEY_SIZE), aad)


def _item_payload(owner, password: str, stored_file: StoredFile | None) -> bytes:
    """Decrypt what is being granted: a record (name, type and bytes together)
    or a snapshot of the profile as JSON."""

    if stored_file is None:
        personal_data = PersonalData.objects.filter(owner=owner).first()
        fields = decrypt_personal_data(personal_data, password, "AES") if personal_data else {}
        return json.dumps(fields, ensure_ascii=False).encode("utf-8")
    label = decrypt_file_label(stored_file, password)
    data = decrypt_file(stored_file.ciphertexts.get(algorithm="AES"), password).plaintext
    return pack_share_payload(label, data)


def _grant_item(access_request, owner_password, stored_file, requester_pair, requester_public_key):
    """Create one granted item: its own random key K, an AES-GCM copy under K,
    K sealed for the owner, and the envelope (K under the requester's RSA key).

    Returns ``(item, envelope_text)``. The envelope is not stored, only its hash.
    """

    payload = _item_payload(access_request.owner, owner_password, stored_file)
    kind = GRANT_KIND_PROFILE if stored_file is None else GRANT_KIND_FILE
    item = GrantedItem.objects.create(
        request=access_request, kind=kind, file=stored_file, nonce=b"", plaintext_size=len(payload)
    )

    key = new_symmetric_key()
    sealed_item = encrypt_with_key(payload, key, item.aad)
    item.nonce = sealed_item.nonce
    item.blob.save(f"{access_request.pk}-{item.pk}-{secrets.token_hex(4)}.bin", ContentFile(sealed_item.ciphertext))

    started = time.perf_counter()
    wrapped = wrap_key(requester_public_key, key)
    wrap_ms = (time.perf_counter() - started) * 1000

    shared_key = SharedKey(item=item, envelope_sha256=envelope_digest(wrapped), requester_key=requester_pair)
    # One PBKDF2 derivation protects both the owner's copy of K and of the
    # envelope; each gets its own nonce and associated data.
    owner_salt = new_salt()
    owner_kek = user_kek(owner_password, owner_salt)
    sealed_key = encrypt_with_key(key, owner_kek, shared_key.aad("owner"))
    sealed_envelope = encrypt_with_key(wrapped, owner_kek, shared_key.aad("envelope"))
    shared_key.owner_salt = owner_salt
    shared_key.key_for_owner, shared_key.owner_nonce = sealed_key.ciphertext, sealed_key.nonce
    shared_key.envelope_for_owner, shared_key.envelope_nonce = sealed_envelope.ciphertext, sealed_envelope.nonce
    shared_key.save()

    key_log.info("wrap item=%s rsa_oaep_ms=%.3f", item.pk, wrap_ms)
    return item, format_envelope(access_request.pk, item.pk, wrapped)


def approve_request(
    access_request: AccessRequest,
    owner_password: str,
    files: list[StoredFile],
    include_profile: bool,
    expires_hours: int,
) -> tuple[AccessRequest, UserKeyPair, list[tuple[GrantedItem, str]]]:
    """Grant a pending request: one granted item, with its own key, per record
    (and optionally the profile).

    Returns the updated request, the requester's key pair (its fingerprint is
    shown to the owner) and ``(item, envelope)`` pairs. The envelopes are what
    the owner sends to the requester out of band; the server keeps them only
    encrypted for the owner, plus their hashes. ``files`` must already be checked to belong to the owner.
    """

    if not files and not include_profile:
        raise ValueError("Grant at least one item.")
    if any(stored_file.owner_id != access_request.owner_id for stored_file in files):
        raise ValueError("Only the owner's own records can be granted.")

    requester_pair = active_key_pair(access_request.requester, KEY_PURPOSE_ENCRYPTION)
    if requester_pair is None:
        raise RequesterHasNoKey(
            f"{access_request.requester.username} has no encryption key yet. Ask them to open Cipher Safe once."
        )
    requester_public_key = load_public_key(requester_pair.public_key_pem)

    with transaction.atomic():
        locked = AccessRequest.objects.select_for_update().get(pk=access_request.pk)
        if locked.status != REQUEST_PENDING:
            raise InvalidTransition(f"This request is already {locked.status.lower()}.")
        targets: list[StoredFile | None] = list(files) + ([None] if include_profile else [])
        grants = [
            _grant_item(locked, owner_password, stored_file, requester_pair, requester_public_key)
            for stored_file in targets
        ]
        now = timezone.now()
        locked.status = REQUEST_APPROVED
        locked.decided_at = now
        locked.expires_at = now + timedelta(hours=expires_hours)
        locked.save(update_fields=["status", "decided_at", "expires_at"])
    return locked, requester_pair, grants


def envelope_for_owner(item: GrantedItem, owner_password: str) -> str:
    """The envelope of an item, exactly as first shown, for the owner to send again.

    Raises ``IntegrityError`` for a wrong password.
    """

    shared_key = item.shared_key
    sealed = SealedData(bytes(shared_key.envelope_nonce), bytes(shared_key.envelope_for_owner))
    owner_kek = user_kek(owner_password, bytes(shared_key.owner_salt))
    wrapped = decrypt_with_key(sealed, owner_kek, shared_key.aad("envelope"))
    return format_envelope(item.request_id, item.pk, wrapped)



# ------------------------------------------------- redeeming and opening


def redeem_item(item: GrantedItem, requester_password: str, envelope_text: str) -> GrantedItem:
    """The requester enters the envelope the owner sent them.

    1. Parse it and check it names this request and item (``ValueError``).
    2. Compare its hash with the stored one, before any RSA work
       (:class:`EnvelopeMismatch`: a different envelope).
    3. Unlock the requester's private key with their password and open the
       envelope (RSA-OAEP), then check the key really opens the item
       (``IntegrityError``: modified envelope or data).
    4. Store the key encrypted for the requester, so they don't need the
       envelope again until access ends.
    """

    envelope = parse_envelope(envelope_text)
    if (envelope.request_id, envelope.item_id) != (item.request_id, item.pk):
        raise ValueError("This key belongs to another item.")
    shared_key = item.shared_key
    if not hmac.compare_digest(envelope_digest(envelope.wrapped_key), shared_key.envelope_sha256):
        raise EnvelopeMismatch()

    private_key = load_private_key(shared_key.requester_key, requester_password)
    started = time.perf_counter()
    key = unwrap_key(private_key, envelope.wrapped_key)
    unwrap_ms = (time.perf_counter() - started) * 1000
    decrypt_with_key(item.sealed(), key, item.aad)  # proves K opens this copy

    sealed, salt = seal_key_for_user(key, requester_password, shared_key.aad("requester"))
    shared_key.key_for_requester, shared_key.requester_nonce = sealed.ciphertext, sealed.nonce
    shared_key.requester_salt = salt
    shared_key.redeemed_at = timezone.now()
    shared_key.save(update_fields=["key_for_requester", "requester_nonce", "requester_salt", "redeemed_at"])
    key_log.info("unwrap item=%s rsa_oaep_ms=%.3f", item.pk, unwrap_ms)
    return item


def open_item(item: GrantedItem, requester_password: str) -> tuple[dict[str, str], bytes]:
    """Decrypt a redeemed item for the requester.

    Returns ``(label, data)``: for a record its name, type and bytes; for a
    profile snapshot ``{"name": "profile.json", "content_type": "application/json"}``
    and the JSON. Counts the access.
    """

    shared_key = item.shared_key
    if shared_key.key_for_requester is None:
        raise NotRedeemed()
    sealed = SealedData(bytes(shared_key.requester_nonce), bytes(shared_key.key_for_requester))
    salt = bytes(shared_key.requester_salt)
    key = open_key_for_user(sealed, salt, requester_password, shared_key.aad("requester"))
    payload = decrypt_with_key(item.sealed(), key, item.aad)
    GrantedItem.objects.filter(pk=item.pk).update(
        access_count=F("access_count") + 1, last_accessed_at=timezone.now()
    )
    if item.kind == GRANT_KIND_PROFILE:
        return {"name": "profile.json", "content_type": "application/json"}, payload
    return unpack_share_payload(payload)



# ------------------------------------------------- ending access


def revoke_request(access_request: AccessRequest) -> AccessRequest:
    """The owner ends an approved request early.

    Deletes every granted copy and its keys (the files on disk go through the
    ``post_delete`` handler), so nothing the requester could open is left.
    """

    with transaction.atomic():
        locked = AccessRequest.objects.select_for_update().get(pk=access_request.pk)
        if locked.status != REQUEST_APPROVED:
            raise InvalidTransition(f"This request is already {locked.status.lower()}.")
        locked.items.all().delete()
        locked.status = REQUEST_REVOKED
        locked.decided_at = timezone.now()
        locked.save(update_fields=["status", "decided_at"])
    return locked


def purge_expired_grants(now=None) -> int:
    """Delete the copies and keys of approved requests whose access has ended.

    Expired items are already refused by every endpoint; this removes the
    data itself. Returns how many items were deleted. Run it regularly
    (``manage.py purge_expired_grants``).
    """

    now = now or timezone.now()
    expired = GrantedItem.objects.filter(request__status=REQUEST_APPROVED, request__expires_at__lte=now)
    count = expired.count()
    with transaction.atomic():
        expired.delete()
    return count



# ------------------------------------------------------------ PDF signing


@dataclass(frozen=True)
class SignedPdf:
    """A PDF signed with a user's signing key, ready to be stored."""

    data: bytes
    key_pair: UserKeyPair
    sign_ms: float


def sign_pdf_for(user, data: bytes, content_type: str, password: str) -> SignedPdf:
    """Sign PDF bytes with the user's signing key, creating it the first time.

    Only PDFs are signed: the content type must say so **and** the bytes must
    start with ``%PDF-``. Raises :class:`core.signing.PdfSigningError`
    (not a PDF, password-protected, already signed).
    """

    if content_type != "application/pdf" or not is_pdf(data):
        raise NotAPdf("Only PDF files can be signed.")
    pair, _ = ensure_key_pair(user, KEY_PURPOSE_SIGNING, password)
    private_key = load_private_key(pair, password)
    signed, sign_ms = sign_pdf(data, private_key, load_certificate(pair.certificate_pem), user.username)
    key_log.info("sign user=%s pdf_bytes=%d sign_ms=%.3f", user.pk, len(data), sign_ms)
    return SignedPdf(signed, pair, sign_ms)
