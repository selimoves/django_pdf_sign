"""Keep the documentation in sync with the code."""

from __future__ import annotations

from pathlib import Path

from django_pdf_sign.constants import (
    DIGEST_SHA256,
    DIGEST_STREEBOG_256,
    DIGEST_STREEBOG_512,
    SUBFILTER_ADOBE_PKCS7,
    SUBFILTER_PADES,
)

DOCS = Path(__file__).resolve().parent.parent / "docs"


def _read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def test_protocol_documents_subfilters() -> None:
    text = _read("protocol.md")
    assert SUBFILTER_ADOBE_PKCS7 in text
    assert SUBFILTER_PADES in text


def test_protocol_documents_digest_names() -> None:
    text = _read("protocol.md")
    assert DIGEST_STREEBOG_256 in text
    assert DIGEST_STREEBOG_512 in text
    assert DIGEST_SHA256 in text


def test_legal_states_no_private_keys() -> None:
    text = _read("legal.md").lower()
    assert "закрытый ключ" in text
    assert "квалифицированный сертификат" in text


def test_stamp_documents_default_template() -> None:
    text = _read("stamp.md")
    assert "ДОКУМЕНТ ПОДПИСАН" in text
    assert "ЭЛЕКТРОННОЙ ПОДПИСЬЮ" in text


def test_fixtures_documents_cryptopro_source() -> None:
    text = _read("fixtures.md")
    assert "pycades-root.cer" in text
    assert "CryptoPro" in text
