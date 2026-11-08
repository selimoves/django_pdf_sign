"""Перечисления и константы протокола."""

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
    """Жизненный цикл сессии подписи."""

    PREPARED = "prepared", "Prepared"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    EXPIRED = "expired", "Expired"


class VerificationStatus(models.TextChoices):
    """Итог проверки CMS."""

    VALID = "valid", "Valid"
    INVALID = "invalid", "Invalid"


class ChainStatus(models.TextChoices):
    """Результат проверки цепочки сертификатов."""

    NOT_CHECKED = "not_checked", "Не проверялась"
    VALID = "valid", "Действительна"
    INVALID = "invalid", "Недействительна"


class RevocationStatus(models.TextChoices):
    """Результат проверки отзыва."""

    NOT_CHECKED = "not_checked", "Не проверялся"
    GOOD = "good", "Не отозван"
    REVOKED = "revoked", "Отозван"
    UNKNOWN = "unknown", "Нет данных"


class TimestampStatus(models.TextChoices):
    """Результат проверки метки времени."""

    ABSENT = "absent", "Отсутствует"
    VALID = "valid", "Верна"
    INVALID = "invalid", "Неверна"
