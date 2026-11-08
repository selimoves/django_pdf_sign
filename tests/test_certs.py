"""Tests for certificate parsing."""

from __future__ import annotations

import pytest

from django_pdf_sign.crypto.certs import display_name, parse_certificate
from django_pdf_sign.exceptions import CertificateError
from tests.helpers import make_gost_certificate, make_rsa_certificate


def test_parse_rsa_certificate() -> None:
    info, _ = make_rsa_certificate()
    assert info.is_gost is False
    assert info.key_size == 2048
    assert info.common_name == "Test Signer"
    assert len(info.thumbprint_sha256) == 64
    assert info.serial_number.isupper()
    assert info.not_before.tzinfo is not None
    assert info.not_after > info.not_before


def test_parse_gost_certificate() -> None:
    info, _ = make_gost_certificate()
    assert info.is_gost is True
    assert info.key_size == 256
    assert len(info.public_key) == 64
    assert info.curve_oid == "1.2.643.7.1.2.1.1.1"
    assert info.key_oid == "1.2.643.7.1.1.1.1"
    assert info.signature_oid == "1.2.643.7.1.1.3.2"


def test_parse_gost_512_certificate() -> None:
    info, _ = make_gost_certificate(key_size=512)
    assert info.is_gost is True
    assert info.key_size == 512
    assert len(info.public_key) == 128
    assert info.curve_oid == "1.2.643.7.1.2.1.2.1"


def test_display_name_prefers_organization() -> None:
    info, _ = make_rsa_certificate(organization="ACME")
    assert display_name(info) == "ACME, Test Signer"


def test_display_name_without_organization() -> None:
    info, _ = make_rsa_certificate()
    assert display_name(info) == "Test Signer"


def test_garbage_raises() -> None:
    with pytest.raises(CertificateError):
        parse_certificate(b"not a certificate")


def test_parse_certificate_rejects_truncated_der() -> None:
    with pytest.raises(CertificateError):
        parse_certificate(bytes.fromhex("3000"))
