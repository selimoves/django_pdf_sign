"""Конфигурация приложения Django."""

from __future__ import annotations

from django.apps import AppConfig


class DjangoPdfSignConfig(AppConfig):
    """Конфигурация приложения django-pdf-sign."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "django_pdf_sign"
    verbose_name = "PDF signatures"
