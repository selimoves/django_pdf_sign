"""Access to the ``DJANGO_PDF_SIGN`` settings namespace."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from django_pdf_sign.constants import DEFAULT_STAMP_TEXT

STAMP_DEFAULTS: dict[str, Any] = {
    "TEXT": DEFAULT_STAMP_TEXT,
    "FONT_PATH": None,
    "FONT_SIZE": 7,
    "BORDER_WIDTH": 1,
    "BACKGROUND_PATH": None,
}

DEFAULTS: dict[str, Any] = {
    "SESSION_TTL": 900,
    "BYTES_RESERVED": 16384,
    "MAX_DOCUMENT_BYTES": 25 * 1024 * 1024,
    "DEFAULT_PAGE": -1,
    "DEFAULT_BOX": (60, 60, 300, 140),
    "SUBFILTER": None,
    "STAMP": STAMP_DEFAULTS,
    "PREPARED_UPLOAD_TO": "django_pdf_sign/prepared/%Y/%m/%d",
    "SIGNED_UPLOAD_TO": "django_pdf_sign/signed/%Y/%m/%d",
}


def _user_settings() -> dict[str, Any]:
    value = getattr(settings, "DJANGO_PDF_SIGN", None) or {}
    if not isinstance(value, dict):
        raise ImproperlyConfigured("DJANGO_PDF_SIGN must be a dict")
    return value


def _merge_stamp(user_stamp: Any) -> dict[str, Any]:
    if user_stamp is None:
        return dict(STAMP_DEFAULTS)
    if not isinstance(user_stamp, dict):
        raise ImproperlyConfigured("DJANGO_PDF_SIGN['STAMP'] must be a dict")
    unknown = set(user_stamp) - set(STAMP_DEFAULTS)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ImproperlyConfigured(f"Unknown DJANGO_PDF_SIGN['STAMP'] keys: {names}")
    return {**STAMP_DEFAULTS, **user_stamp}


def _merged() -> dict[str, Any]:
    user = _user_settings()
    unknown = set(user) - set(DEFAULTS)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ImproperlyConfigured(f"Unknown DJANGO_PDF_SIGN keys: {names}")
    merged = {
        **DEFAULTS,
        **{key: value for key, value in user.items() if key != "STAMP"},
    }
    merged["STAMP"] = _merge_stamp(user.get("STAMP"))
    return merged


def get_setting(name: str) -> Any:
    """Return a top-level ``DJANGO_PDF_SIGN`` setting."""
    merged = _merged()
    if name not in merged:
        raise ImproperlyConfigured(f"Unknown DJANGO_PDF_SIGN setting: {name}")
    return merged[name]


def get_stamp_setting(name: str) -> Any:
    """Return a ``DJANGO_PDF_SIGN['STAMP']`` setting."""
    stamp = _merged()["STAMP"]
    if name not in stamp:
        raise ImproperlyConfigured(f"Unknown DJANGO_PDF_SIGN['STAMP'] setting: {name}")
    return stamp[name]
