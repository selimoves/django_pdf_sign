"""Read-only admin for signing sessions and signature records."""

from __future__ import annotations

from django.contrib import admin
from django.http import HttpRequest

from django_pdf_sign.models import SignatureRecord, SigningSession


class ReadOnlyAdmin(admin.ModelAdmin):
    """Admin that exposes records without allowing changes."""

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: object = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: object = None) -> bool:
        return False


@admin.register(SigningSession)
class SigningSessionAdmin(ReadOnlyAdmin):
    """Read-only view of signing sessions."""

    list_display = (
        "id",
        "status",
        "certificate_common_name",
        "digest_algorithm",
        "created_at",
        "expires_at",
        "completed_at",
    )
    list_filter = ("status", "digest_algorithm", "subfilter")
    search_fields = (
        "certificate_subject",
        "certificate_common_name",
        "certificate_serial",
        "certificate_thumbprint",
    )
    readonly_fields = tuple(field.name for field in SigningSession._meta.fields)


@admin.register(SignatureRecord)
class SignatureRecordAdmin(ReadOnlyAdmin):
    """Read-only view of completed signatures."""

    list_display = (
        "id",
        "certificate_common_name",
        "digest_algorithm",
        "verification_status",
        "signed_at",
    )
    list_filter = ("verification_status", "digest_algorithm", "subfilter")
    search_fields = (
        "certificate_subject",
        "certificate_common_name",
        "certificate_serial",
        "certificate_thumbprint",
    )
    readonly_fields = tuple(field.name for field in SignatureRecord._meta.fields)
