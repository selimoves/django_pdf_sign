"""Tests for the public verification helpers."""

from __future__ import annotations

import pytest
from django.core.files.base import ContentFile

from django_pdf_sign.services import (
    complete_signing,
    prepare_signing,
    verify_cms_over_bytes,
    verify_signed_pdf,
)
from tests.helpers import (
    make_gost_cms,
    make_rsa_certificate,
    make_rsa_cms,
    minimal_pdf,
)
from tests.models import Document


def test_valid_rsa_cms() -> None:
    cms_bytes, info, data = make_rsa_cms()
    result = verify_cms_over_bytes(
        cms=cms_bytes, data=data, expected_certificate_der=info.der
    )
    assert result.valid
    assert result.message_digest_ok
    assert result.signature_ok
    assert result.certificate_matches
    assert result.errors == ()


def test_wrong_certificate_is_flagged() -> None:
    other, _ = make_rsa_certificate(common_name="Other")
    cms_bytes, _, data = make_rsa_cms()
    result = verify_cms_over_bytes(
        cms=cms_bytes, data=data, expected_certificate_der=other.der
    )
    assert not result.valid
    assert not result.certificate_matches
    assert "Certificate does not match" in result.errors


def test_wrong_data_is_flagged() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    result = verify_cms_over_bytes(cms=cms_bytes, data=b"other")
    assert not result.valid
    assert not result.message_digest_ok


def test_gost_cms_verifies() -> None:
    cms_bytes, _, data = make_gost_cms()
    result = verify_cms_over_bytes(cms=cms_bytes, data=data)
    assert result.valid
    assert result.signature_ok


def test_garbage_cms_is_flagged() -> None:
    result = verify_cms_over_bytes(cms=b"garbage", data=b"data")
    assert not result.valid
    assert result.errors


@pytest.mark.django_db
def test_verify_signed_pdf() -> None:
    info, key = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes)

    verification = verify_signed_pdf(result.signed_pdf)
    assert verification.valid
    assert verification.signature_ok


@pytest.mark.django_db
def test_verify_signed_pdf_rejects_tampered_document() -> None:
    info, key = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes)

    tampered = result.signed_pdf.replace(b"Page 1", b"Page X")
    verification = verify_signed_pdf(tampered)
    assert not verification.valid
    assert not verification.message_digest_ok


def test_verify_signed_pdf_rejects_unsigned_document() -> None:
    verification = verify_signed_pdf(minimal_pdf())
    assert not verification.valid
    assert "no signatures" in verification.errors[0]
