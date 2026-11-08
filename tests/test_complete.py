"""Tests for the complete_signing service."""

from __future__ import annotations

import datetime
import io
from datetime import timedelta

import pytest
from asn1crypto import cms, x509
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.utils import timezone
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from django_pdf_sign.constants import SigningStatus, VerificationStatus
from django_pdf_sign.exceptions import SessionError, VerificationError
from django_pdf_sign.models import SignatureRecord
from django_pdf_sign.services import (
    VerificationPolicy,
    complete_signing,
    prepare_signing,
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


def _document() -> Document:
    return Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))


@pytest.mark.django_db
def test_complete_pades_end_to_end() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    result.session.refresh_from_db()

    assert result.session.status == SigningStatus.COMPLETED
    assert result.session.completed_at is not None
    assert result.record.verification_status == VerificationStatus.VALID
    assert result.record.cms_size == len(cms_bytes)
    assert result.record.chain_status == "not_checked"
    assert result.record.revocation_status == "not_checked"
    assert result.record.timestamp_status == "absent"
    assert result.signed_pdf
    assert result.record.signed_pdf.read()

    reader = PdfFileReader(io.BytesIO(result.signed_pdf))
    status = validate_pdf_signature(
        reader.embedded_signatures[0],
        ValidationContext(
            trust_roots=[x509.Certificate.load(info.der)], allow_fetching=False
        ),
    )
    assert status.intact
    assert status.valid
    assert status.trusted


@pytest.mark.django_db
def test_complete_gost_end_to_end() -> None:
    info, private_key = make_gost_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(info, private_key)
    )

    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    assert result.record.verification_status == VerificationStatus.VALID
    assert result.record.digest_algorithm == "streebog256"


@pytest.mark.django_db
def test_complete_rejects_wrong_document() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=b"other bytes", signer=(info, key))

    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)

    prepared.session.refresh_from_db()
    assert prepared.session.status == SigningStatus.PREPARED
    assert not SignatureRecord.objects.exists()


@pytest.mark.django_db
def test_complete_rejects_wrong_certificate() -> None:
    info, _ = make_rsa_certificate()
    other, other_key = make_rsa_certificate(common_name="Other Signer")
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(
        data=prepared.bytes_to_sign, signer=(other, other_key)
    )

    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)


@pytest.mark.django_db
def test_complete_rejects_tampered_signature() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    content_info = cms.ContentInfo.load(cms_bytes)
    signer_info = content_info["content"]["signer_infos"][0]
    signature = bytearray(signer_info["signature"].native)
    signature[0] ^= 0x01
    signer_info["signature"] = bytes(signature)
    tampered = content_info.dump()

    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=tampered)


@pytest.mark.django_db
def test_complete_rejects_reuse() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    complete_signing(session_id=prepared.session.pk, cms=cms_bytes)

    with pytest.raises(SessionError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    assert SignatureRecord.objects.count() == 1


@pytest.mark.django_db
def test_complete_rejects_expired_session() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    session = prepared.session
    session.expires_at = timezone.now() - timedelta(seconds=1)
    session.save(update_fields=["expires_at"])
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    with pytest.raises(SessionError):
        complete_signing(session_id=session.pk, cms=cms_bytes)

    session.refresh_from_db()
    assert session.status == SigningStatus.EXPIRED


@pytest.mark.django_db
def test_complete_rejects_other_user() -> None:
    user_model = get_user_model()
    owner = user_model.objects.create_user(username="owner")
    other = user_model.objects.create_user(username="other")
    info, key = make_rsa_certificate()
    prepared = prepare_signing(
        document=_document(), certificate_der=info.der, user=owner
    )
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    with pytest.raises(SessionError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes, user=other)


@pytest.mark.django_db
def test_complete_rejects_missing_session() -> None:
    with pytest.raises(SessionError):
        complete_signing(session_id="00000000-0000-0000-0000-000000000000", cms=b"")


@pytest.mark.django_db
def test_complete_rejects_garbage_cms() -> None:
    info, _ = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=b"garbage")


@pytest.mark.django_db
def test_complete_accepts_matching_user() -> None:
    user_model = get_user_model()
    owner = user_model.objects.create_user(username="owner")
    info, key = make_rsa_certificate()
    prepared = prepare_signing(
        document=_document(), certificate_der=info.der, user=owner
    )
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes, user=owner)
    assert result.session.status == SigningStatus.COMPLETED


@pytest.mark.django_db
def test_complete_with_trusted_chain() -> None:
    ca_info, ca_key = make_gost_certificate(common_name="Test CA", is_ca=True)
    leaf_info, leaf_key = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    prepared = prepare_signing(document=_document(), certificate_der=leaf_info.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(leaf_info, leaf_key)
    )
    policy = VerificationPolicy(
        check_chain=True, trust_roots=(ca_info.der,), moment=NOW
    )
    result = complete_signing(
        session_id=prepared.session.pk, cms=cms_bytes, policy=policy
    )
    assert result.record.verification_status == VerificationStatus.VALID
    assert result.record.verification_details["chain_ok"] is True
    assert result.record.chain_status == "valid"
    assert result.record.revocation_status == "not_checked"
    assert result.record.trusted is True


@pytest.mark.django_db
def test_complete_rejects_untrusted_chain() -> None:
    ca_info, ca_key = make_gost_certificate(common_name="Test CA", is_ca=True)
    other_info, _ = make_gost_certificate(common_name="Other CA", is_ca=True)
    leaf_info, leaf_key = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    prepared = prepare_signing(document=_document(), certificate_der=leaf_info.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(leaf_info, leaf_key)
    )
    policy = VerificationPolicy(
        check_chain=True, trust_roots=(other_info.der,), moment=NOW
    )
    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes, policy=policy)
    assert not SignatureRecord.objects.exists()
