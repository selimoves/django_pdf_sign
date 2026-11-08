"""Enumerations and protocol constants."""

from __future__ import annotations

from django.db import models

DIGEST_STREEBOG_256 = "streebog256"
DIGEST_STREEBOG_512 = "streebog512"
DIGEST_SHA256 = "sha256"

SUBFILTER_ADOBE_PKCS7 = "/adbe.pkcs7.detached"
SUBFILTER_PADES = "/ETSI.CAdES.detached"

DEFAULT_STAMP_TEXT = (
    "ДОКУМЕНТ ПОДПИСАН\n"
    "ЭЛЕКТРОННОЙ ПОДПИСЬЮ\n"
    "Сертификат: %(serial)s\n"
    "Владелец: %(signer)s\n"
    "Действителен: с %(valid_from)s до %(valid_to)s"
)


class SigningStatus(models.TextChoices):
    """Lifecycle of a signing session."""

    PREPARED = "prepared", "Prepared"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    EXPIRED = "expired", "Expired"


class VerificationStatus(models.TextChoices):
    """Outcome of CMS verification."""

    VALID = "valid", "Valid"
    INVALID = "invalid", "Invalid"
