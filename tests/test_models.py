"""Tests for the signing models."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus, VerificationStatus
from django_pdf_sign.models import SignatureRecord, SigningSession
from tests.helpers import make_gost_certificate, minimal_pdf


def _create_session(**overrides: object) -> SigningSession:
    info, _ = make_gost_certificate()
    values: dict[str, object] = {
        "certificate_der": info.der,
        "certificate_subject": info.subject,
        "certificate_common_name": info.common_name,
        "certificate_organization": info.organization or "",
        "certificate_serial": info.serial_number,
        "certificate_thumbprint": info.thumbprint_sha256,
        "certificate_not_before": info.not_before,
        "certificate_not_after": info.not_after,
        "digest_algorithm": "streebog256",
        "subfilter": "/adbe.pkcs7.detached",
        "field_name": "Sig1",
        "page": 0,
        "bytes_reserved": 16384,
        "prepared_pdf": ContentFile(minimal_pdf(), name="prepared.pdf"),
        "reserved_region_start": 0,
        "reserved_region_end": 0,
        "expires_at": timezone.now() + timedelta(seconds=60),
    }
    values.update(overrides)
    return SigningSession.objects.create(**values)


@pytest.mark.django_db
def test_session_defaults_to_prepared() -> None:
    session = _create_session()
    assert session.status == SigningStatus.PREPARED
    assert session.is_expired is False
    assert session.completed_at is None


@pytest.mark.django_db
def test_expired_session() -> None:
    session = _create_session(expires_at=timezone.now() - timedelta(seconds=1))
    assert session.is_expired is True


@pytest.mark.django_db
def test_mark_failed() -> None:
    session = _create_session()
    session.mark_failed("bad cms")
    session.refresh_from_db()
    assert session.status == SigningStatus.FAILED
    assert session.error == "bad cms"


@pytest.mark.django_db
def test_signature_record_is_immutable() -> None:
    session = _create_session()
    info, _ = make_gost_certificate()
    record = SignatureRecord.objects.create(
        session=session,
        certificate_der=info.der,
        certificate_subject=info.subject,
        certificate_serial=info.serial_number,
        certificate_thumbprint=info.thumbprint_sha256,
        digest_algorithm="streebog256",
        subfilter="/adbe.pkcs7.detached",
        cms_size=1024,
        verification_status=VerificationStatus.VALID,
        signed_pdf=ContentFile(minimal_pdf(), name="signed.pdf"),
    )
    record.cms_size = 2048
    with pytest.raises(ValidationError):
        record.save()
