"""Serializers for the Cipher Safe API.

Ciphertext, salt and IV are never exposed; only metadata leaves the server.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from rest_framework import serializers

from .constants import DEFAULT_MODE, FILE_CATEGORY_CHOICES, MODE_CHOICES
from .models import DownloadEvent, FileCiphertext, StoredFile

User = get_user_model()

#: Fields treated as personal data (GDPR Art. 4 / UU PDP Art. 1).
PII_FIELDS = ("full_name", "national_id", "date_of_birth", "address", "phone", "email")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "date_joined"]
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ["id", "username", "password", "email"]

    def validate(self, attrs):
        # Run Django's configured password validators (length, common-password,
        # numeric, similarity) before the account is created.
        candidate = User(username=attrs.get("username", ""), email=attrs.get("email", ""))
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
    """Write-only: plaintext PII submitted by the user.

    Every supplied field is encrypted with AES, DES and RC4 before being
    persisted, so no plaintext personal data is ever stored.
    """

    full_name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    national_id = serializers.CharField(required=False, allow_blank=True, max_length=64)
    date_of_birth = serializers.CharField(required=False, allow_blank=True, max_length=32)
    address = serializers.CharField(required=False, allow_blank=True, max_length=512)
    phone = serializers.CharField(required=False, allow_blank=True, max_length=32)
    email = serializers.CharField(required=False, allow_blank=True, max_length=254)


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
            "total_ms",
        ]


class StoredFileSerializer(serializers.ModelSerializer):
    ciphertexts = FileCiphertextSerializer(many=True, read_only=True)

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
    mode = serializers.ChoiceField(choices=MODE_CHOICES, default=DEFAULT_MODE, required=False)

    def validate_file(self, value):
        if value.size > settings.MAX_UPLOAD_BYTES:
            limit_mb = settings.MAX_UPLOAD_BYTES // (1024 * 1024)
            raise serializers.ValidationError(f"File exceeds the {limit_mb} MB upload limit.")
        return value


class DownloadEventSerializer(serializers.ModelSerializer):
    total_ms = serializers.FloatField(read_only=True)
    original_name = serializers.CharField(source="file.original_name", read_only=True)

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
