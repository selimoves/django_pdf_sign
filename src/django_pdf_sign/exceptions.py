"""Иерархия исключений django-pdf-sign."""

from __future__ import annotations


class DjangoPdfSignError(Exception):
    """Базовое исключение пакета."""


class CertificateError(DjangoPdfSignError):
    """Сертификат не удалось разобрать или он непригоден."""


class SigningError(DjangoPdfSignError):
    """Документ не удалось подготовить или CMS не удалось встроить."""


class SessionError(DjangoPdfSignError):
    """Сессия отсутствует, истекла, использована или принадлежит другому."""


class VerificationError(DjangoPdfSignError):
    """CMS или подписанный PDF не прошли проверку."""
