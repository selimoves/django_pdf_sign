"""Tests for settings access."""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from django_pdf_sign.conf import get_setting, get_stamp_setting


def test_default_session_ttl() -> None:
    assert get_setting("SESSION_TTL") == 900


def test_unknown_setting_raises() -> None:
    with pytest.raises(ImproperlyConfigured):
        get_setting("NOPE")


def test_stamp_text_default_contains_serial() -> None:
    assert "%(serial)s" in get_stamp_setting("TEXT")


@override_settings(DJANGO_PDF_SIGN={"SESSION_TTL": 60, "STAMP": {"FONT_SIZE": 9}})
def test_overrides_merge_with_defaults() -> None:
    assert get_setting("SESSION_TTL") == 60
    assert get_stamp_setting("FONT_SIZE") == 9
    assert get_stamp_setting("BORDER_WIDTH") == 1


@override_settings(DJANGO_PDF_SIGN={"UNKNOWN": 1})
def test_unknown_top_level_key_raises() -> None:
    with pytest.raises(ImproperlyConfigured):
        get_setting("SESSION_TTL")


@override_settings(DJANGO_PDF_SIGN={"STAMP": {"UNKNOWN": 1}})
def test_unknown_stamp_key_raises() -> None:
    with pytest.raises(ImproperlyConfigured):
        get_stamp_setting("FONT_SIZE")
