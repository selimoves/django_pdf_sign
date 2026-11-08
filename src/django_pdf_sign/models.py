"""Signing session and signature record models."""

from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from django_pdf_sign.conf import get_setting
from django_pdf_sign.constants import SigningStatus, VerificationStatus


def _upload_to(prefix_setting: str, filename: str) -> str:
    prefix = timezone.now().strftime(get_setting(prefix_setting))
    return f"{prefix}/{filename}"


def prepared_upload_to(instance: SigningSession, filename: str) -> str:
    """Return the storage path for a prepared PDF."""
    return _upload_to("PREPARED_UPLOAD_TO", filename)


def signed_upload_to(instance: SignatureRecord, filename: str) -> str:
    """Return the storage path for a signed PDF."""
    return _upload_to("SIGNED_UPLOAD_TO", filename)


class SigningSession(models.Model):
    """One in-flight client-side signing operation."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    status = models.CharField(
        max_length=16, choices=SigningStatus.choices, default=SigningStatus.PREPARED
    )

    content_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, null=True, blank=True
    )
    object_id = models.CharField(max_length=64, blank=True, default="")
    document = GenericForeignKey("content_type", "object_id")

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="pdf_signing_sessions",
    )

    certificate_der = models.BinaryField()
    certificate_subject = models.CharField(max_length=512)
    certificate_common_name = models.CharField(max_length=256, blank=True, default="")
    certificate_organization = models.CharField(max_length=256, blank=True, default="")
    certificate_serial = models.CharField(max_length=128)
    certificate_thumbprint = models.CharField(max_length=64, db_index=True)
    certificate_not_before = models.DateTimeField()
    certificate_not_after = models.DateTimeField()

    digest_algorithm = models.CharField(max_length=32)
    subfilter = models.CharField(max_length=64)
    field_name = models.CharField(max_length=128)
    page = models.IntegerField()
    box = models.JSONField(null=True, blank=True)
    bytes_reserved = models.PositiveIntegerField()

    prepared_pdf = models.FileField(upload_to=prepared_upload_to, max_length=255)
    reserved_region_start = models.BigIntegerField()
    reserved_region_end = models.BigIntegerField()

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "signing session"
        verbose_name_plural = "signing sessions"

    def __str__(self) -> str:
        return f"{self.pk} ({self.status})"

    @property
    def is_expired(self) -> bool:
        """Whether the session is past its expiry moment."""
        return timezone.now() >= self.expires_at

    def mark_failed(self, message: str) -> None:
        """Mark the session as failed with an explanation."""
        self.status = SigningStatus.FAILED
        self.error = message
        self.save(update_fields=["status", "error"])


class SignatureRecord(models.Model):
    """Immutable audit record of a completed signature."""

    session = models.OneToOneField(
        SigningSession, on_delete=models.PROTECT, related_name="record"
    )

    content_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, null=True, blank=True
    )
    object_id = models.CharField(max_length=64, blank=True, default="")
    document = GenericForeignKey("content_type", "object_id")

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="pdf_signature_records",
    )

    signed_at = models.DateTimeField(auto_now_add=True)
    certificate_der = models.BinaryField()
    certificate_subject = models.CharField(max_length=512)
    certificate_common_name = models.CharField(max_length=256, blank=True, default="")
    certificate_organization = models.CharField(max_length=256, blank=True, default="")
    certificate_serial = models.CharField(max_length=128)
    certificate_thumbprint = models.CharField(max_length=64, db_index=True)

    digest_algorithm = models.CharField(max_length=32)
    subfilter = models.CharField(max_length=64)
    cms_size = models.PositiveIntegerField()
    verification_status = models.CharField(
        max_length=16, choices=VerificationStatus.choices
    )
    verification_details = models.JSONField(default=dict, blank=True)
    signed_pdf = models.FileField(upload_to=signed_upload_to, max_length=255)

    class Meta:
        ordering = ("-signed_at",)
        verbose_name = "signature record"
        verbose_name_plural = "signature records"

    def __str__(self) -> str:
        return f"{self.pk} ({self.verification_status})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ValidationError("SignatureRecord is immutable")
        super().save(*args, **kwargs)
