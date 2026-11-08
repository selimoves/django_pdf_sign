"""Клиентские электронные подписи PDF-документов в Django."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("django-pdf-sign")
except PackageNotFoundError:  # исходное дерево без установки
    from django_pdf_sign._version import __version__

__all__ = ["__version__"]
