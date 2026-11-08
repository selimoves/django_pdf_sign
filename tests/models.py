"""Models used only by the test suite."""

from __future__ import annotations

from django.db import models


class Document(models.Model):
    """A document with a file attachment for signing tests."""

    file = models.FileField(upload_to="documents")
    title = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        app_label = "tests"
