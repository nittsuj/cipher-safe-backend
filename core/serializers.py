"""Serializers for the Cipher Safe API.

Ciphertext, salt and IV are never exposed; only metadata leaves the server.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from rest_framework import serializers

from .constants import (
    FILE_CATEGORY_CHOICES,
    KEY_PURPOSE_CHOICES,
    REQUEST_CATEGORY_CHOICES,
    REQUEST_PENDING,
)
from .crypto import certificate_fingerprint, load_certificate
from .models import (
    AccessRequest,
    DownloadEvent,
    FileCiphertext,
    GrantedItem,
    StoredFile,
    UserKeyPair,
)

User = get_user_model()

#: The patient profile. Every field is personal data (GDPR Art. 4(1), UU PDP
#: Art. 1(1)); the classification below decides how sensitive each one is.
#:
#: * Specific / special-category data (UU PDP Art. 4(2)(a) health data,
#:   GDPR Art. 9(1) "data concerning health"): ``blood_type``, ``allergies``,
#:   ``chronic_conditions``, ``current_medications``.
#: * Data UU PDP Art. 4(3) lists as general but that enables identity theft or
#:   links a person to their health record: ``national_id`` (NIK) and
#:   ``bpjs_number`` (national health-insurance number).
#: * General personal data: ``full_name``, ``date_of_birth``, ``address``,
#:   ``phone``, ``emergency_contact``.
#:
#: All of them are encrypted: the general fields are what turns the health
#: fields into data about an identifiable person.
PII_FIELDS = (
    "full_name",
    "national_id",
    "bpjs_number",
    "date_of_birth",
    "address",
    "phone",
    "emergency_contact",
    "blood_type",
    "allergies",
    "chronic_conditions",
    "current_medications",
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "role", "date_joined"]
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ["id", "username", "password", "role"]
        extra_kwargs = {"role": {"required": False}}

    def validate(self, attrs):
        # Run Django's configured password validators (length, common-password,
        # numeric, similarity) before the account is created.
        candidate = User(username=attrs.get("username", ""))
        password_validation.validate_password(attrs["password"], candidate)
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True, style={"input_type": "password"})


class PersonalDataSerializer(serializers.Serializer):
    """Write-only: the plaintext patient profile submitted by the patient.

    The profile is encrypted with AES, DES and RC4 before being persisted, so
    no plaintext personal or health data is ever stored. A PUT replaces the
    whole profile.
    """

    full_name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    national_id = serializers.RegexField(r"^\d{16}$", required=False, allow_blank=True,
                                         error_messages={"invalid": "NIK must be 16 digits."})
    bpjs_number = serializers.RegexField(r"^\d{13}$", required=False, allow_blank=True,
                                         error_messages={"invalid": "BPJS number must be 13 digits."})
    date_of_birth = serializers.DateField(required=False, allow_null=True)
    address = serializers.CharField(required=False, allow_blank=True, max_length=512)
    phone = serializers.CharField(required=False, allow_blank=True, max_length=32)
    emergency_contact = serializers.CharField(required=False, allow_blank=True, max_length=255)
    blood_type = serializers.ChoiceField(
        choices=["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"], required=False
    )
    allergies = serializers.CharField(required=False, allow_blank=True, max_length=1024)
    chronic_conditions = serializers.CharField(required=False, allow_blank=True, max_length=1024)
    current_medications = serializers.CharField(required=False, allow_blank=True, max_length=1024)


class FileCiphertextSerializer(serializers.ModelSerializer):
    total_ms = serializers.FloatField(read_only=True)

    class Meta:
        model = FileCiphertext
        fields = [
            "algorithm",
            "mode",
            "ciphertext_size",
            "key_derivation_ms",
            "cipher_ms",
            "mac_ms",
            "total_ms",
        ]


class StoredFileSerializer(serializers.ModelSerializer):
    """File metadata. ``original_name`` and ``content_type`` are not columns:
    the view decrypts them and passes them in ``context["labels"]``."""

    ciphertexts = FileCiphertextSerializer(many=True, read_only=True)
    original_name = serializers.SerializerMethodField()
    content_type = serializers.SerializerMethodField()

    def _label(self, obj) -> dict:
        return self.context.get("labels", {}).get(obj.pk, {})

    def get_original_name(self, obj) -> str:
        return self._label(obj).get("name", "")

    def get_content_type(self, obj) -> str:
        return self._label(obj).get("content_type", "")

    signed = serializers.SerializerMethodField()
    signed_at = serializers.SerializerMethodField()

    def _signature(self, obj):
        return getattr(obj, "signature", None)

    def get_signed(self, obj) -> bool:
        return self._signature(obj) is not None

    def get_signed_at(self, obj):
        signature = self._signature(obj)
        return serializers.DateTimeField().to_representation(signature.signed_at) if signature else None

    class Meta:
        model = StoredFile
        fields = [
            "id",
            "category",
            "original_name",
            "content_type",
            "plaintext_size",
            "created_at",
            "ciphertexts",
            "signed",
            "signed_at",
        ]
        read_only_fields = fields


class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    category = serializers.ChoiceField(choices=FILE_CATEGORY_CHOICES)
    #: Sign the PDF with the uploader's signing key before it is encrypted.
    sign = serializers.BooleanField(default=False)

    def validate_file(self, value):
        if value.size > settings.MAX_UPLOAD_BYTES:
            limit_mb = settings.MAX_UPLOAD_BYTES // (1024 * 1024)
            raise serializers.ValidationError(f"File exceeds the {limit_mb} MB upload limit.")
        return value


class DownloadEventSerializer(serializers.ModelSerializer):
    total_ms = serializers.FloatField(read_only=True)
    original_name = serializers.SerializerMethodField()

    def get_original_name(self, obj) -> str:
        return self.context.get("labels", {}).get(obj.file_id, {}).get("name", "")

    class Meta:
        model = DownloadEvent
        fields = [
            "id",
            "file",
            "original_name",
            "algorithm",
            "success",
            "bytes_out",
            "key_derivation_ms",
            "cipher_ms",
            "mac_ms",
            "total_ms",
            "created_at",
        ]
        read_only_fields = fields


class KeyPairSerializer(serializers.ModelSerializer):
    """One of the user's own key pairs: public parts only.

    The field list is an allowlist; the encrypted private key, its salt and
    nonce never leave the server.
    """

    has_certificate = serializers.SerializerMethodField()
    certificate = serializers.SerializerMethodField()

    def get_has_certificate(self, obj) -> bool:
        return bool(obj.certificate_pem)

    def get_certificate(self, obj) -> dict | None:
        """Who the certificate names and how long it's valid; ``None`` without one."""

        if not obj.certificate_pem:
            return None
        certificate = load_certificate(obj.certificate_pem)
        return {
            "subject": certificate.subject.rfc4514_string(),
            "not_before": certificate.not_valid_before_utc,
            "not_after": certificate.not_valid_after_utc,
            "fingerprint": certificate_fingerprint(certificate),
        }

    class Meta:
        model = UserKeyPair
        fields = [
            "purpose",
            "algorithm",
            "fingerprint",
            "public_key_pem",
            "has_certificate",
            "certificate",
            "created_at",
        ]
        read_only_fields = fields


class KeyPairCreateSerializer(serializers.Serializer):
    purpose = serializers.ChoiceField(choices=KEY_PURPOSE_CHOICES)
    rotate = serializers.BooleanField(default=False)


class PublicKeySerializer(serializers.ModelSerializer):
    """Another user's active public key, for encrypting data to them."""

    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = UserKeyPair
        fields = ["username", "purpose", "algorithm", "fingerprint", "public_key_pem"]
        read_only_fields = fields


class GrantedItemSummarySerializer(serializers.ModelSerializer):
    """What was granted on an approved request, without names or content."""

    item_id = serializers.IntegerField(source="pk", read_only=True)
    category = serializers.CharField(source="file.category", default=None, read_only=True)
    redeemed = serializers.SerializerMethodField()

    def get_redeemed(self, obj) -> bool:
        shared_key = getattr(obj, "shared_key", None)
        return bool(shared_key and shared_key.redeemed)

    class Meta:
        model = GrantedItem
        fields = ["item_id", "kind", "category", "redeemed", "access_count"]
        read_only_fields = fields


class AccessRequestSerializer(serializers.ModelSerializer):
    """A request as both sides see it. Before approval it says nothing about
    the owner's records; once approved, ``items`` lists what was granted (kind
    and category only), so the requester knows which keys to enter."""

    requester = serializers.CharField(source="requester.username", read_only=True)
    owner = serializers.CharField(source="owner.username", read_only=True)
    expired = serializers.BooleanField(read_only=True)
    items = GrantedItemSummarySerializer(many=True, read_only=True)

    class Meta:
        model = AccessRequest
        fields = [
            "id",
            "requester",
            "owner",
            "message",
            "category",
            "status",
            "created_at",
            "decided_at",
            "expires_at",
            "expired",
            "items",
        ]
        read_only_fields = fields


class AccessRequestCreateSerializer(serializers.Serializer):
    owner = serializers.CharField(help_text="Username of the user whose data you ask for.")
    message = serializers.CharField(max_length=500, required=False, allow_blank=True, default="")
    category = serializers.ChoiceField(
        choices=REQUEST_CATEGORY_CHOICES, required=False, allow_blank=True, default=""
    )

    def validate_owner(self, value):
        owner = User.objects.filter(username=value).first()
        if owner is None:
            raise serializers.ValidationError("No user with that username.")
        if owner == self.context["request"].user:
            raise serializers.ValidationError("You can't request your own data.")
        return owner

    def validate(self, attrs):
        requester = self.context["request"].user
        if AccessRequest.objects.filter(requester=requester, owner=attrs["owner"], status=REQUEST_PENDING).exists():
            raise serializers.ValidationError({"owner": "You already have a pending request to this user."})
        return attrs

    def create(self, validated_data):
        return AccessRequest.objects.create(requester=self.context["request"].user, **validated_data)


class ApproveRequestSerializer(serializers.Serializer):
    """What the owner grants: some of their records and/or a profile snapshot."""

    file_ids = serializers.ListField(child=serializers.IntegerField(min_value=1), required=False, default=list)
    include_profile = serializers.BooleanField(default=False)
    expires_hours = serializers.IntegerField(min_value=1, max_value=168, default=24)

    def validate_file_ids(self, value):
        if len(set(value)) != len(value):
            raise serializers.ValidationError("A record is listed twice.")
        owner = self.context["request"].user
        files = list(StoredFile.objects.filter(owner=owner, pk__in=value))
        if len(files) != len(value):
            raise serializers.ValidationError("Every record must be one of yours.")
        return files

    def validate(self, attrs):
        if not attrs["file_ids"] and not attrs["include_profile"]:
            raise serializers.ValidationError("Choose at least one record or the profile.")
        return attrs


class RedeemSerializer(serializers.Serializer):
    envelope = serializers.CharField(max_length=2000, trim_whitespace=True)


__all__ = [
    "GrantedItemSummarySerializer",
    "RedeemSerializer",
    "ApproveRequestSerializer",
    "AccessRequestCreateSerializer",
    "AccessRequestSerializer",
    "KeyPairCreateSerializer",
    "KeyPairSerializer",
    "PublicKeySerializer",
    "PII_FIELDS",
    "DownloadEventSerializer",
    "FileCiphertextSerializer",
    "FileUploadSerializer",
    "LoginSerializer",
    "PersonalDataSerializer",
    "RegisterSerializer",
    "StoredFileSerializer",
    "UserSerializer",
]
