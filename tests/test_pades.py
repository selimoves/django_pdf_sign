"""Tests for RSA and ECDSA PAdES signature verification."""

from __future__ import annotations

import pytest

from django_pdf_sign.crypto.pades import verify_pades
from django_pdf_sign.exceptions import VerificationError
from tests.helpers import make_rsa_certificate, sign_rsa


def test_valid_rsa_signature() -> None:
    info, key = make_rsa_certificate()
    data = b"signed attributes"
    signature = sign_rsa(key, data)
    assert verify_pades(
        certificate_der=info.der,
        signed_attrs_der=data,
        signature=signature,
        digest_algorithm="sha256",
    )


def test_tampered_data_rejected() -> None:
    info, key = make_rsa_certificate()
    signature = sign_rsa(key, b"signed attributes")
    assert not verify_pades(
        certificate_der=info.der,
        signed_attrs_der=b"other",
        signature=signature,
        digest_algorithm="sha256",
    )


def test_unknown_algorithm_raises() -> None:
    info, key = make_rsa_certificate()
    with pytest.raises(VerificationError):
        verify_pades(
            certificate_der=info.der,
            signed_attrs_der=b"data",
            signature=sign_rsa(key, b"data"),
            digest_algorithm="md5",
        )


def test_bad_certificate_raises() -> None:
    with pytest.raises(VerificationError):
        verify_pades(
            certificate_der=b"garbage",
            signed_attrs_der=b"data",
            signature=b"\x00" * 256,
            digest_algorithm="sha256",
        )
