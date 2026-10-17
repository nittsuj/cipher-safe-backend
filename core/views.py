from __future__ import annotations

from django.contrib.auth import authenticate
from django.db import transaction
from django.db.models import Avg, Count, F, Max, Min
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.http import content_disposition_header
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import DEFAULT_MODE, SUPPORTED_ALGORITHMS, SUPPORTED_MODES
from .models import DownloadEvent, FileCiphertext, PersonalData, StoredFile
from .serializers import (
    PII_FIELDS,
    DownloadEventSerializer,
    FileUploadSerializer,
    LoginSerializer,
    PersonalDataSerializer,
    RegisterSerializer,
    StoredFileSerializer,
    UserSerializer,
)
from .services import (
    decrypt_file,
    decrypt_personal_data,
    log_download,
    store_file_ciphertexts,
    store_personal_data,
)


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
    """Read or replace the user's private attributes.

    GET decrypts with ``?algorithm=`` (default AES) and requires the password.
    PUT accepts plaintext fields and re-encrypts them with AES, DES and RC4.
    """

    permission_classes = [IsAuthenticated]

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
        fields = {k: v for k, v in serializer.validated_data.items() if v != ""}
        if not fields:
            raise ValidationError({"detail": "Provide at least one personal-data field."})
        personal_data = _personal_data_for(request.user)
        with transaction.atomic():
            store_personal_data(personal_data, password, fields)
        values = decrypt_personal_data(personal_data, password, "AES")
        return Response(
            {
                "updated_at": personal_data.updated_at,
                "fields": {name: values.get(name) for name in PII_FIELDS if name in values},
            }
        )


class FileListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        files = StoredFile.objects.filter(owner=request.user).prefetch_related("ciphertexts")
        category = request.query_params.get("category")
        if category:
            files = files.filter(category=category.upper())
        return Response(StoredFileSerializer(files, many=True).data)

    def post(self, request):
        password = require_password(request)
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        upload = serializer.validated_data["file"]
        mode = serializer.validated_data.get("mode") or DEFAULT_MODE

        data = upload.read()
        if not data:
            raise ValidationError({"file": "The uploaded file is empty."})

        with transaction.atomic():
            stored_file = StoredFile.objects.create(
                owner=request.user,
                category=serializer.validated_data["category"],
                original_name=upload.name,
                content_type=getattr(upload, "content_type", "") or "",
                plaintext_size=len(data),
            )
            store_file_ciphertexts(stored_file, data, password, mode)

        stored_file.refresh_from_db()
        return Response(
            StoredFileSerializer(stored_file).data,
            status=status.HTTP_201_CREATED,
        )


class FileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_file(self, request, pk: int) -> StoredFile:
        return get_object_or_404(StoredFile, pk=pk, owner=request.user)

    def get(self, request, pk: int):
        return Response(StoredFileSerializer(self._get_file(request, pk)).data)

    def delete(self, request, pk: int):
        stored_file = self._get_file(request, pk)
        stored_file.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class FileDownloadView(APIView):
    """Decrypt and stream a file, recording the running time."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk: int):
        password = require_password(request)
        algorithm = _validate_algorithm(request.query_params.get("algorithm"))
        stored_file = get_object_or_404(StoredFile, pk=pk, owner=request.user)
        ciphertext = get_object_or_404(
            FileCiphertext, file=stored_file, algorithm=algorithm
        )

        try:
            plaintext, kdf_ms, cipher_ms = decrypt_file(ciphertext, password)
        except ValueError:
            log_download(stored_file, algorithm, 0.0, 0.0, 0, success=False)
            raise ValidationError({"detail": "Wrong password or corrupted ciphertext."})

        log_download(stored_file, algorithm, kdf_ms, cipher_ms, len(plaintext))

        response = HttpResponse(
            plaintext,
            content_type=stored_file.content_type or "application/octet-stream",
        )
        response["Content-Disposition"] = content_disposition_header(
            True, stored_file.original_name
        )
        response["Content-Length"] = str(len(plaintext))
        response["X-Cipher-Algorithm"] = algorithm
        response["X-Cipher-Decrypt-Ms"] = f"{kdf_ms + cipher_ms:.3f}"
        return response


class FileBenchmarkView(APIView):
    """Run N server-side decryptions of one file and return timing statistics."""

    permission_classes = [IsAuthenticated]
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
        for _ in range(runs):
            samples.append(ciphertext.decrypt(password).total_ms)

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
            }
        )


class DownloadHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        events = (
            DownloadEvent.objects.filter(owner=request.user)
            .select_related("file")
            .order_by("-created_at")[:100]
        )
        return Response(DownloadEventSerializer(events, many=True).data)


class TimingAnalysisView(APIView):
    """Aggregate running times per algorithm for the report."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        total = F("key_derivation_ms") + F("cipher_ms")
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
                "supported_modes": list(SUPPORTED_MODES),
                "downloads": list(downloads),
                "encryptions": list(encryptions),
            }
        )
