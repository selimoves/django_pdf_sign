"""Модель документа примера."""

from django.db import models


class Document(models.Model):
    """Документ, который подписывает пользователь."""

    file = models.FileField(upload_to="documents")
    title = models.CharField(max_length=128, blank=True, default="")
