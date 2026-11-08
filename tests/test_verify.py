"""Tests for the public verification helpers."""

from __future__ import annotations

import datetime

import pytest
from django.core.files.base import ContentFile

from django_pdf_sign.services import (
    VerificationPolicy,
    complete_signing,
    prepare_signing,
    verify_cms_over_bytes,
    verify_signed_pdf,
)
from tests.helpers import (
    make_gost_certificate,
    make_gost_cms,
    make_rsa_certificate,
    make_rsa_cms,
    minimal_pdf,
)
from tests.models import Document

NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


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
    assert "Сертификат не совпадает с ожидаемым" in result.errors


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


def _gost_chain() -> tuple[bytes, object]:
    ca_info, ca_key = make_gost_certificate(common_name="Test CA", is_ca=True)
    leaf_info, leaf_key = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    cms_bytes, _, data = make_gost_cms(signer=(leaf_info, leaf_key))
    return ca_info.der, (cms_bytes, data)


def test_chain_policy_trusted() -> None:
    ca_der, (cms_bytes, data) = _gost_chain()
    result = verify_cms_over_bytes(
        cms=cms_bytes,
        data=data,
        policy=VerificationPolicy(check_chain=True, trust_roots=(ca_der,), moment=NOW),
    )
    assert result.valid
    assert result.chain_ok is True
    assert result.trusted is True
    assert result.validation_path


def test_chain_policy_untrusted_root() -> None:
    _, (cms_bytes, data) = _gost_chain()
    other_info, _ = make_gost_certificate(common_name="Other CA", is_ca=True)
    result = verify_cms_over_bytes(
        cms=cms_bytes,
        data=data,
        policy=VerificationPolicy(
            check_chain=True, trust_roots=(other_info.der,), moment=NOW
        ),
    )
    assert not result.valid
    assert result.chain_ok is False
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
    assert "нет подписей" in verification.errors[0]


def _sign_pdf(pdf: bytes) -> bytes:
    info, key = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(pdf, name="doc.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    return complete_signing(session_id=prepared.session.pk, cms=cms_bytes).signed_pdf


@pytest.mark.django_db
def test_verify_signed_pdf_by_signature_index() -> None:
    twice_signed = _sign_pdf(_sign_pdf(minimal_pdf()))
    assert not verify_signed_pdf(twice_signed).valid
    assert verify_signed_pdf(twice_signed, signature_index=1).valid
    invalid = verify_signed_pdf(twice_signed, signature_index=5)
    assert not invalid.valid
    assert "индекс" in invalid.errors[0].lower()
