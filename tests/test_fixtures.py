"""Tests against official CryptoPro test fixtures."""

from __future__ import annotations

from pathlib import Path

from django_pdf_sign.crypto.certs import parse_certificate

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "crypto"


def test_parse_cryptopro_root_certificate() -> None:
    info = parse_certificate((FIXTURES / "pycades-root.cer").read_bytes())
    assert info.is_gost is True
    assert info.key_size == 256
    assert info.key_oid == "1.2.643.7.1.1.1.1"
    assert info.curve_oid == "1.2.643.2.2.36.0"
    assert info.signature_oid == "1.2.643.7.1.1.3.2"
    assert info.common_name == "pycades-root"
    assert len(info.public_key) == 64
