from __future__ import annotations

import json
import os

from django.contrib.auth import authenticate
from django.db import IntegrityError as DatabaseIntegrityError
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.http import content_disposition_header
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import (
    KEY_PURPOSE_CHOICES,
    KEY_PURPOSE_ENCRYPTION,
    GRANT_KIND_PROFILE,
    PREVIEWABLE_TYPES,
    REQUEST_APPROVED,
    ROLE_DOCTOR,
    ROLE_PATIENT,
    SUPPORTED_ALGORITHMS,
)
from .crypto import IntegrityError
from .models import (
    AccessRequest,
    GrantedItem,
    DownloadEvent,
    FileCiphertext,
    FileShare,
    PersonalData,
    StoredFile,
    User,
    UserKeyPair,
)
from .serializers import (
    ApproveRequestSerializer,
    AccessRequestCreateSerializer,
    AccessRequestSerializer,
    PII_FIELDS,
    DownloadEventSerializer,
    FileShareSerializer,
    ReceivedShareSerializer,
    ShareCreateSerializer,
    FileUploadSerializer,
    KeyPairCreateSerializer,
    KeyPairSerializer,
    LoginSerializer,
    PersonalDataSerializer,
    PublicKeySerializer,
    RedeemSerializer,
    RegisterSerializer,
    StoredFileSerializer,
    UserSerializer,
)
from .services import (
    create_share,
    decrypt_file,
    delete_share,
    ensure_key_pair,
    envelope_for_owner,
    open_share,
    decrypt_file_label,
    decrypt_file_labels,
    decrypt_personal_data,
    log_download,
    open_item,
    redeem_item,
    revoke_request,
    rotate_key_pair,
    approve_request,
    benchmark_decryption,
    cancel_request,
    deny_request,
    store_personal_data,
    store_record,
    timing_summary,
)


class IsPatient(BasePermission):
    """Vault endpoints: only patients own records."""

    message = "Only patient accounts have a records vault."

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == ROLE_PATIENT)


class IsDoctor(BasePermission):
    message = "Only doctor accounts receive shared records."

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == ROLE_DOCTOR)


PATIENT_ONLY = [IsAuthenticated, IsPatient]


def file_response(data: bytes, content_type: str, filename: str, inline: bool) -> HttpResponse:
    """Serve decrypted bytes, inline only for types that cannot run script.

    ``nosniff`` and a sandboxing CSP keep an uploaded HTML/SVG file from
    executing even if it is opened directly.
    """

    content_type = content_type or "application/octet-stream"
    inline = inline and content_type in PREVIEWABLE_TYPES
    response = HttpResponse(data, content_type=content_type if inline else "application/octet-stream")
    response["Content-Disposition"] = content_disposition_header(not inline, filename)
    response["Content-Length"] = str(len(data))
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "sandbox; default-src 'none'"
    response["Cache-Control"] = "no-store"
    return response


def _wants_inline(request) -> bool:
    return request.query_params.get("inline") in ("1", "true")


def password_from_request(request) -> str | None:
    """Read the cipher password from the request.

    Preferred transport is the ``X-Cipher-Password`` header; the request body is
    accepted as a fallback. The query string is deliberately not accepted,
    because URLs end up in access logs, browser history and Referer headers.
    """

    password = request.headers.get("X-Cipher-Password")
    if not password and hasattr(request, "data"):
        try:
            password = request.data.get("password")
        except Exception:  # pragma: no cover - unparsable body
            password = None
    return password


def require_password(request) -> str:
    """Return the verified password or raise a 4xx error.

    The password is checked against the authenticated user's hash, so a wrong
    or missing password is rejected before any crypto work happens.
    """

    password = password_from_request(request)
    if not password:
        raise ValidationError({"password": "This operation requires the password."})
    if not request.user.check_password(password):
        raise PermissionDenied("Incorrect password.")
    return password


def _validate_algorithm(value: str | None) -> str:
    algorithm = (value or "AES").upper()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValidationError({"algorithm": f"Must be one of {', '.join(SUPPORTED_ALGORITHMS)}."})
    return algorithm


def _personal_data_for(user) -> PersonalData:
    personal_data, _ = PersonalData.objects.get_or_create(owner=user)
    return personal_data


def _token_pair(user) -> dict[str, str]:
    """Issue a JWT access/refresh pair for ``user``."""

    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {"user": UserSerializer(user).data, **_token_pair(user)},
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    """Return an auth token; also confirms the username + password pair."""

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            request,
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if user is None:
            return Response(
                {"detail": "Invalid username or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return Response({"user": UserSerializer(user).data, **_token_pair(user)})


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh = request.data.get("refresh")
        if refresh:
            try:
                RefreshToken(refresh).blacklist()
            except TokenError:
                pass
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class PersonalDataView(APIView):
    """Read or replace the patient profile (identity + medical attributes).

    GET decrypts with ``?algorithm=`` (default AES) and requires the password.
    PUT accepts the full plaintext profile and re-encrypts it with AES, DES
    and RC4, replacing the previous profile.
    """

    permission_classes = PATIENT_ONLY

    def get(self, request):
        password = require_password(request)
        algorithm = _validate_algorithm(request.query_params.get("algorithm"))
        personal_data = _personal_data_for(request.user)
        values = decrypt_personal_data(personal_data, password, algorithm)
        return Response(
            {
                "algorithm": algorithm,
                "updated_at": personal_data.updated_at,
                "fields": {name: values.get(name) for name in PII_FIELDS if name in values},
            }
        )

    def put(self, request):
        password = require_password(request)
        serializer = PersonalDataSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        fields = {
            k: (v.isoformat() if hasattr(v, "isoformat") else v)
            for k, v in serializer.validated_data.items()
            if v not in ("", None)
        }
        if not fields:
            raise ValidationError({"detail": "Provide at least one personal-data field."})
        personal_data = _personal_data_for(request.user)
        with transaction.atomic():
            store_personal_data(personal_data, password, fields)
        personal_data.refresh_from_db()
        values = fields
        return Response(
            {
                "updated_at": personal_data.updated_at,
                "fields": {name: values.get(name) for name in PII_FIELDS if name in values},
            }
        )


class FileListCreateView(APIView):
    permission_classes = PATIENT_ONLY

    def get(self, request):
        password = require_password(request)
        files = StoredFile.objects.filter(owner=request.user).prefetch_related("ciphertexts", "labels")
        category = request.query_params.get("category")
        if category:
            files = files.filter(category=category.upper())
        files = list(files)
        labels = decrypt_file_labels(files, password)
        return Response(StoredFileSerializer(files, many=True, context={"labels": labels}).data)

    def post(self, request):
        password = require_password(request)
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        upload = serializer.validated_data["file"]

        data = upload.read()
        if not data:
            raise ValidationError({"file": "The uploaded file is empty."})

        label = {"name": upload.name, "content_type": getattr(upload, "content_type", "") or ""}
        stored_file = store_record(
            request.user,
            serializer.validated_data["category"],
            label["name"],
            label["content_type"],
            data,
            password,
        )
        stored_file.refresh_from_db()
        return Response(
            StoredFileSerializer(stored_file, context={"labels": {stored_file.pk: label}}).data,
            status=status.HTTP_201_CREATED,
        )


class FileDetailView(APIView):
    permission_classes = PATIENT_ONLY

    def _get_file(self, request, pk: int) -> StoredFile:
        return get_object_or_404(StoredFile, pk=pk, owner=request.user)

    def get(self, request, pk: int):
        password = require_password(request)
        stored_file = self._get_file(request, pk)
        labels = {stored_file.pk: decrypt_file_label(stored_file, password)}
        return Response(StoredFileSerializer(stored_file, context={"labels": labels}).data)

    def delete(self, request, pk: int):
        # The ciphertext and share blobs are removed from disk by the
        # post_delete handlers in core.signals.
        self._get_file(request, pk).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class FileDownloadView(APIView):
    """Decrypt and stream a file, recording the running time."""

    permission_classes = PATIENT_ONLY

    def get(self, request, pk: int):
        password = require_password(request)
        algorithm = _validate_algorithm(request.query_params.get("algorithm"))
        stored_file = get_object_or_404(StoredFile, pk=pk, owner=request.user)
        ciphertext = get_object_or_404(
            FileCiphertext, file=stored_file, algorithm=algorithm
        )

        try:
            # Name and type come from the label copy of the same algorithm.
            label = decrypt_file_label(stored_file, password, algorithm)
            result = decrypt_file(ciphertext, password)
        except IntegrityError:
            # Record the failed attempt; the exception handler returns 409.
            log_download(stored_file, algorithm, 0.0, 0.0, 0.0, 0, success=False)
            raise

        plaintext = result.plaintext
        kdf_ms = result.key_derivation_ms
        cipher_ms = result.cipher_ms
        log_download(stored_file, algorithm, kdf_ms, cipher_ms, result.mac_ms, len(plaintext))

        response = file_response(
            plaintext,
            label.get("content_type", ""),
            label.get("name") or f"record-{stored_file.pk}",
            inline=_wants_inline(request),
        )
        response["X-Cipher-Algorithm"] = algorithm
        response["X-Cipher-Decrypt-Ms"] = f"{result.total_ms:.3f}"
        return response


class FileCiphertextView(APIView):
    """Return one stored copy exactly as it is on disk, without decrypting it.

    Lets the owner see that what the server keeps is ciphertext. The file keeps
    its original extension (``lab-result.AES-encrypted.pdf``), so it is plain
    that the same PDF no longer opens. The password is needed to decrypt the
    name for that.
    """

    permission_classes = PATIENT_ONLY

    def get(self, request, pk: int):
        password = require_password(request)
        algorithm = _validate_algorithm(request.query_params.get("algorithm"))
        stored_file = get_object_or_404(StoredFile, pk=pk, owner=request.user)
        ciphertext = get_object_or_404(FileCiphertext, file=stored_file, algorithm=algorithm)
        name = decrypt_file_label(stored_file, password).get("name") or f"record-{stored_file.pk}"
        stem, ext = os.path.splitext(name)
        response = HttpResponse(ciphertext._payload(), content_type="application/octet-stream")
        response["Content-Disposition"] = content_disposition_header(
            True, f"{stem}.{algorithm}-encrypted{ext}"
        )
        response["Cache-Control"] = "no-store"
        return response


class FileBenchmarkView(APIView):
    """Run N server-side decryptions of one file and return timing statistics."""

    permission_classes = PATIENT_ONLY
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "benchmark"
    MAX_RUNS = 50

    def get(self, request, pk: int):
        password = require_password(request)
        algorithm = _validate_algorithm(request.query_params.get("algorithm"))
        try:
            runs = int(request.query_params.get("runs", 5))
        except ValueError:
            raise ValidationError({"runs": "Must be an integer."})
        runs = max(1, min(runs, self.MAX_RUNS))

        stored_file = get_object_or_404(StoredFile, pk=pk, owner=request.user)
        ciphertext = get_object_or_404(
            FileCiphertext, file=stored_file, algorithm=algorithm
        )

        return Response(
            {
                "file": stored_file.id,
                "algorithm": algorithm,
                "mode": ciphertext.mode,
                "runs": runs,
                "ciphertext_size": ciphertext.ciphertext_size,
                **benchmark_decryption(ciphertext, password, runs),
            }
        )


class DownloadHistoryView(APIView):
    permission_classes = PATIENT_ONLY

    def get(self, request):
        password = require_password(request)
        events = list(
            DownloadEvent.objects.filter(owner=request.user)
            .select_related("file")
            .prefetch_related("file__labels")
            .order_by("-created_at")[:100]
        )
        files = {event.file_id: event.file for event in events}
        labels = decrypt_file_labels(files.values(), password)
        return Response(DownloadEventSerializer(events, many=True, context={"labels": labels}).data)


class TimingAnalysisView(APIView):
    """Aggregate running times per algorithm (Analysis page)."""

    permission_classes = PATIENT_ONLY

    def get(self, request):
        return Response(timing_summary(request.user))


class FileShareListCreateView(APIView):
    """List a record's shares, or share it with a doctor.

    POST re-encrypts the record under a fresh share key and returns that key
    **once**; the patient sends it to the doctor themselves.
    """

    permission_classes = PATIENT_ONLY

    def get(self, request, pk: int):
        stored_file = get_object_or_404(StoredFile, pk=pk, owner=request.user)
        shares = stored_file.shares.select_related("doctor")
        return Response(FileShareSerializer(shares, many=True).data)

    def post(self, request, pk: int):
        password = require_password(request)
        stored_file = get_object_or_404(StoredFile, pk=pk, owner=request.user)
        serializer = ShareCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            share, key = create_share(
                stored_file,
                serializer.validated_data["doctor"],
                password,
                serializer.validated_data["expires_hours"],
            )
        return Response(
            {**FileShareSerializer(share).data, "share_key": key},
            status=status.HTTP_201_CREATED,
        )


class FileShareRevokeView(APIView):
    permission_classes = PATIENT_ONLY

    def delete(self, request, pk: int):
        share = get_object_or_404(FileShare, pk=pk, file__owner=request.user)
        delete_share(share)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ReceivedShareListView(APIView):
    """Records shared with the signed-in doctor that have not expired."""

    permission_classes = [IsAuthenticated, IsDoctor]

    def get(self, request):
        shares = FileShare.objects.filter(doctor=request.user, expires_at__gt=timezone.now()).select_related(
            "file", "file__owner"
        )
        return Response(ReceivedShareSerializer(shares, many=True).data)


class ReceivedShareOpenView(APIView):
    """Decrypt a shared record with the share key (``X-Share-Key`` header).

    The key is never stored, so the server cannot open the share without it.
    Throttled because the key is the only secret.
    """

    permission_classes = [IsAuthenticated, IsDoctor]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "share"

    def get(self, request, pk: int):
        key = request.headers.get("X-Share-Key", "")
        if not key:
            raise ValidationError({"share_key": "Enter the share key the patient sent you."})
        share = get_object_or_404(FileShare, pk=pk, doctor=request.user, expires_at__gt=timezone.now())
        try:
            label, data = open_share(share, key)
        except IntegrityError:
            raise PermissionDenied("Wrong share key.")
        response = file_response(
            data,
            label.get("content_type", ""),
            label.get("name") or f"shared-record-{share.pk}",
            inline=_wants_inline(request),
        )
        response["X-Content-Type"] = label.get("content_type", "")
        return response


class MyKeyPairsView(APIView):
    """List the signed-in user's active key pairs, or generate / rotate one.

    Any account (patient or doctor) has key pairs. Generating needs the
    password, because the new private key is encrypted with it. Throttled:
    RSA-3072 generation is expensive.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "keygen"

    def get_throttles(self):
        # Listing is cheap; only generation is rate-limited.
        return super().get_throttles() if self.request.method == "POST" else []

    def get(self, request):
        pairs = UserKeyPair.objects.filter(user=request.user, active=True).order_by("purpose")
        return Response(KeyPairSerializer(pairs, many=True).data)

    def post(self, request):
        password = require_password(request)
        serializer = KeyPairCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        purpose = serializer.validated_data["purpose"]
        if serializer.validated_data["rotate"]:
            pair, created = rotate_key_pair(request.user, purpose, password), True
        else:
            pair, created = ensure_key_pair(request.user, purpose, password)
        return Response(
            KeyPairSerializer(pair).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class UserPublicKeyView(APIView):
    """Another user's active public key and fingerprint (``?purpose=``, default
    ``ENCRYPTION``). Never generates a key for someone else: 404 if they have none."""

    permission_classes = [IsAuthenticated]

    def get(self, request, username: str):
        purpose = (request.query_params.get("purpose") or KEY_PURPOSE_ENCRYPTION).upper()
        if purpose not in dict(KEY_PURPOSE_CHOICES):
            raise ValidationError({"purpose": f"Must be one of {', '.join(dict(KEY_PURPOSE_CHOICES))}."})
        owner = get_object_or_404(User, username=username)
        pair = get_object_or_404(UserKeyPair, user=owner, purpose=purpose, active=True)
        return Response(PublicKeySerializer(pair).data)


class AccessRequestListCreateView(APIView):
    """Ask another user for their data, or list my requests.

    ``?box=incoming`` (default): requests to me. ``?box=outgoing``: requests I
    sent. Any role can ask any other user. No password: nothing is decrypted.
    Creating is throttled so a user can't flood someone's inbox.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "request"

    def get_throttles(self):
        return super().get_throttles() if self.request.method == "POST" else []

    def get(self, request):
        box = (request.query_params.get("box") or "incoming").lower()
        if box == "incoming":
            requests = AccessRequest.objects.filter(owner=request.user)
        elif box == "outgoing":
            requests = AccessRequest.objects.filter(requester=request.user)
        else:
            raise ValidationError({"box": "Must be incoming or outgoing."})
        requests = requests.select_related("requester", "owner")
        return Response(AccessRequestSerializer(requests, many=True).data)

    def post(self, request):
        serializer = AccessRequestCreateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        try:
            with transaction.atomic():
                access_request = serializer.save()
        except DatabaseIntegrityError:
            # Two requests raced past the pending check; the constraint caught it.
            raise ValidationError({"owner": "You already have a pending request to this user."})
        return Response(AccessRequestSerializer(access_request).data, status=status.HTTP_201_CREATED)


def _request_for(user, pk: int) -> AccessRequest:
    """A request the user is part of. Anyone else gets 404, so ids don't leak."""

    return get_object_or_404(
        AccessRequest.objects.select_related("requester", "owner").filter(Q(requester=user) | Q(owner=user)),
        pk=pk,
    )


class AccessRequestDetailView(APIView):
    """``DELETE`` ends a request; the row is kept with its new status.

    * The requester cancels a pending request (``CANCELLED``).
    * The owner revokes an approved one (``REVOKED``): every granted copy and
      its keys are deleted. A pending request is denied instead, not revoked.
    """

    permission_classes = [IsAuthenticated]

    def delete(self, request, pk: int):
        access_request = _request_for(request.user, pk)
        if access_request.requester_id == request.user.pk:
            cancel_request(access_request)
        elif access_request.status == REQUEST_APPROVED:
            revoke_request(access_request)
        else:
            raise PermissionDenied("Only the requester can cancel a request; deny it instead.")
        return Response(status=status.HTTP_204_NO_CONTENT)


class AccessRequestDenyView(APIView):
    """The owner refuses a pending request."""

    permission_classes = [IsAuthenticated]

    def post(self, request, pk: int):
        access_request = _request_for(request.user, pk)
        if access_request.owner_id != request.user.pk:
            raise PermissionDenied("Only the owner can deny a request.")
        return Response(AccessRequestSerializer(deny_request(access_request)).data)


def _owned_request(user, pk: int) -> AccessRequest:
    """A request where ``user`` is the owner. Outsiders get 404, the requester 403."""

    access_request = _request_for(user, pk)
    if access_request.owner_id != user.pk:
        raise PermissionDenied("Only the owner can do this.")
    return access_request


def _live_item(access_request: AccessRequest, item_id: int) -> GrantedItem:
    """An item of an approved, unexpired request; 404 otherwise."""

    if access_request.status != REQUEST_APPROVED or access_request.expired:
        raise NotFound("This access has ended.")
    items = GrantedItem.objects.select_related("shared_key__requester_key")
    return get_object_or_404(items, request=access_request, pk=item_id)


class AccessRequestApproveView(APIView):
    """The owner grants a pending request.

    Each chosen record (and optionally the profile) gets its own random AES-256
    key and encrypted copy; each key is encrypted with the requester's RSA
    public key. The response holds those envelopes for the owner to send out
    of band. Needs the owner's password to decrypt what is granted.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, pk: int):
        password = require_password(request)
        access_request = _owned_request(request.user, pk)
        serializer = ApproveRequestSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        approved, requester_pair, grants = approve_request(
            access_request, password, data["file_ids"], data["include_profile"], data["expires_hours"]
        )
        return Response(
            {
                "request": AccessRequestSerializer(approved).data,
                "recipient_fingerprint": requester_pair.fingerprint,
                "items": [
                    {
                        "item_id": item.pk,
                        "kind": item.kind,
                        "category": item.file.category if item.file else None,
                        "envelope": envelope,
                    }
                    for item, envelope in grants
                ],
            }
        )


class GrantedItemEnvelopeView(APIView):
    """The owner shows an item's envelope again: the same text as at approval,
    so a copy already sent keeps working. Needs the owner's password."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk: int, item_id: int):
        password = require_password(request)
        item = _live_item(_owned_request(request.user, pk), item_id)
        return Response(
            {
                "item_id": item.pk,
                "kind": item.kind,
                "envelope": envelope_for_owner(item, password),
                "recipient_fingerprint": item.shared_key.requester_key.fingerprint,
            }
        )


def _requested_item(user, pk: int, item_id: int) -> GrantedItem:
    """An item of a live request where ``user`` is the requester."""

    access_request = _request_for(user, pk)
    if access_request.requester_id != user.pk:
        raise PermissionDenied("Only the requester can do this.")
    return _live_item(access_request, item_id)


class GrantedItemRedeemView(APIView):
    """The requester enters the envelope the owner sent them.

    The envelope is checked against the stored hash, opened with the
    requester's private key (unlocked with their password), and the item key
    is then kept encrypted for them. Throttled: guessing envelopes is the
    obvious attack.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "redeem"

    def post(self, request, pk: int, item_id: int):
        password = require_password(request)
        item = _requested_item(request.user, pk, item_id)
        serializer = RedeemSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            redeem_item(item, password, serializer.validated_data["envelope"])
        except ValueError as exc:
            if isinstance(exc, IntegrityError):
                raise
            raise ValidationError({"envelope": str(exc)})
        return Response({"item_id": item.pk, "kind": item.kind, "redeemed": True})


class GrantedItemOpenView(APIView):
    """The requester opens a redeemed item: the record (``?inline=1`` for a
    preview) or the profile snapshot as JSON. Needs their password."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk: int, item_id: int):
        password = require_password(request)
        item = _requested_item(request.user, pk, item_id)
        label, data = open_item(item, password)
        if item.kind == GRANT_KIND_PROFILE:
            return Response(json.loads(data))
        content_type = label.get("content_type", "")
        filename = label.get("name") or f"record-{item.pk}"
        response = file_response(data, content_type, filename, inline=_wants_inline(request))
        response["X-Content-Type"] = content_type
        return response
