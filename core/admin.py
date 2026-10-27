from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import DownloadEvent, EncryptedValue, FileCiphertext, PersonalData, StoredFile, User


@admin.register(StoredFile)
class StoredFileAdmin(admin.ModelAdmin):
    list_display = ("id", "category", "owner", "plaintext_size", "created_at")
    list_filter = ("category",)
    search_fields = ("owner__username",)


@admin.register(FileCiphertext)
class FileCiphertextAdmin(admin.ModelAdmin):
    list_display = ("id", "file", "algorithm", "mode", "ciphertext_size", "cipher_ms")
    list_filter = ("algorithm", "mode")


@admin.register(EncryptedValue)
class EncryptedValueAdmin(admin.ModelAdmin):
    list_display = ("id", "personal_data", "field_name", "algorithm", "mode", "ciphertext_size")
    list_filter = ("algorithm", "field_name")


@admin.register(DownloadEvent)
class DownloadEventAdmin(admin.ModelAdmin):
    list_display = ("id", "file", "algorithm", "success", "key_derivation_ms", "cipher_ms", "created_at")
    list_filter = ("algorithm", "success")


admin.site.register(PersonalData)
try:
    admin.site.register(User, UserAdmin)
except admin.sites.AlreadyRegistered:  # pragma: no cover - Django may register it
    pass
