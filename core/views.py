from __future__ import annotations

import os

from django.contrib.auth import authenticate
from django.db import transaction
from django.db.models import Avg, Count, F, Max, Min
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.http import content_disposition_header
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import MODE_FOR, PREVIEWABLE_TYPES, ROLE_DOCTOR, ROLE_PATIENT, SUPPORTED_ALGORITHMS
from .crypto import IntegrityError
from .exceptions import IntegrityCheckFailed
from .models import DownloadEvent, FileCiphertext, FileShare, PersonalData, StoredFile
from .serializers import (
    PII_FIELDS,
    DownloadEventSerializer,
    FileShareSerializer,
    ReceivedShareSerializer,
    ShareCreateSerializer,
    FileUploadSerializer,
    LoginSerializer,
    PersonalDataSerializer,
    RegisterSerializer,
    StoredFileSerializer,
    UserSerializer,
)
from .services import (
    create_share,
    decrypt_file,
    delete_share,
    open_share,
    decrypt_file_label,
    decrypt_file_labels,
    decrypt_personal_data,
    log_download,
    store_file_ciphertexts,
    store_file_label,
    store_personal_data,
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
        try:
            values = decrypt_personal_data(personal_data, password, algorithm)
        except IntegrityError:
            raise IntegrityCheckFailed()
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
        try:
            labels = decrypt_file_labels(files, password)
        except IntegrityError:
            raise IntegrityCheckFailed()
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
        with transaction.atomic():
            stored_file = StoredFile.objects.create(
                owner=request.user,
                category=serializer.validated_data["category"],
                plaintext_size=len(data),
            )
            store_file_label(stored_file, label["name"], label["content_type"], password)
            store_file_ciphertexts(stored_file, data, password)

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
        try:
            labels = {stored_file.pk: decrypt_file_label(stored_file, password)}
        except IntegrityError:
            raise IntegrityCheckFailed()
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
            log_download(stored_file, algorithm, 0.0, 0.0, 0.0, 0, success=False)
            raise IntegrityCheckFailed()

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
        try:
            name = decrypt_file_label(stored_file, password).get("name") or f"record-{stored_file.pk}"
        except IntegrityError:
            raise IntegrityCheckFailed()
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

        # Decrypt repeatedly to benchmark the full decrypt path.
        samples = []
        # Cipher + integrity check only. Key setup (PBKDF2) costs the same for
        # every algorithm and would hide the difference between them.
        cipher_samples = []
        try:
            for _ in range(runs):
                result = ciphertext.decrypt(password)
                samples.append(result.total_ms)
                cipher_samples.append(result.cipher_ms + result.mac_ms)
        except IntegrityError:
            raise IntegrityCheckFailed()

        return Response(
            {
                "file": stored_file.id,
                "algorithm": algorithm,
                "mode": ciphertext.mode,
                "runs": runs,
                "ciphertext_size": ciphertext.ciphertext_size,
                "samples_ms": samples,
                "min_ms": min(samples),
                "max_ms": max(samples),
                "mean_ms": sum(samples) / len(samples),
                "cipher_samples_ms": cipher_samples,
                "cipher_mean_ms": sum(cipher_samples) / len(cipher_samples),
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
        try:
            labels = decrypt_file_labels(files.values(), password)
        except IntegrityError:
            raise IntegrityCheckFailed()
        return Response(DownloadEventSerializer(events, many=True, context={"labels": labels}).data)


class TimingAnalysisView(APIView):
    """Aggregate running times per algorithm (Analysis page)."""

    permission_classes = PATIENT_ONLY

    def get(self, request):
        total = F("key_derivation_ms") + F("cipher_ms") + F("mac_ms")
        downloads = (
            DownloadEvent.objects.filter(owner=request.user, success=True)
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
            FileCiphertext.objects.filter(file__owner=request.user)
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
        return Response(
            {
                "supported_algorithms": list(SUPPORTED_ALGORITHMS),
                "modes": MODE_FOR,
                "downloads": list(downloads),
                "encryptions": list(encryptions),
            }
        )


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
        try:
            with transaction.atomic():
                share, key = create_share(
                    stored_file,
                    serializer.validated_data["doctor"],
                    password,
                    serializer.validated_data["expires_hours"],
                )
        except IntegrityError:
            raise IntegrityCheckFailed()
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
