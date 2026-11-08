"""Tests for stamp rendering."""

from __future__ import annotations

from datetime import UTC, datetime

from django_pdf_sign.pdf.stamp import (
    StampConfig,
    build_stamp_style,
    stamp_text_params,
)
from tests.helpers import make_gost_certificate


def test_params_are_russian_formatted() -> None:
    info, _ = make_gost_certificate(organization="ACME")
    params = stamp_text_params(info, timestamp=datetime(2026, 11, 8, tzinfo=UTC))
    assert params["serial"] == info.serial_number
    assert params["signer"] == "ACME, GOST Test Signer"
    assert params["valid_from"] == "01.01.2024"
    assert params["valid_to"] == "01.01.2034"
    assert params["ts"] == "08.11.2026 00:00:00 UTC"


def test_style_uses_bundled_font() -> None:
    style = build_stamp_style(StampConfig.from_settings())
    assert style.stamp_text
    assert style.text_box_style.font is not None


def test_style_accepts_custom_text() -> None:
    config = StampConfig(
        text="Signed: %(signer)s",
        font_path=None,
        font_size=9,
        border_width=0,
        background_path=None,
    )
    style = build_stamp_style(config)
    assert style.stamp_text == "Signed: %(signer)s"
