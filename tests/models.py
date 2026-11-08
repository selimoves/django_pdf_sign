"""Модели, используемые только тестами."""

from __future__ import annotations

from django.db import models


class Document(models.Model):
    """Документ с файлом для тестов подписи."""

    file = models.FileField(upload_to="documents")
    title = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        app_label = "tests"
