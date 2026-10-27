"""Serializers for the Cipher Safe API.

Ciphertext, salt and IV are never exposed; only metadata leaves the server.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from rest_framework import serializers

from .constants import FILE_CATEGORY_CHOICES
from .models import DownloadEvent, FileCiphertext, StoredFile

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
        fields = ["id", "username", "date_joined"]
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ["id", "username", "password"]

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
        ]
        read_only_fields = fields


class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    category = serializers.ChoiceField(choices=FILE_CATEGORY_CHOICES)

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


__all__ = [
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
