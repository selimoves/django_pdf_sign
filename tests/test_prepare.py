"""Tests for the prepare_signing service."""

from __future__ import annotations

import pytest
from django.core.files.base import ContentFile
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.exceptions import CertificateError, SigningError
from django_pdf_sign.models import SigningSession
from django_pdf_sign.services import prepare_signing
from tests.helpers import make_gost_certificate, make_rsa_certificate, minimal_pdf
from tests.models import Document


def _document() -> Document:
    return Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))


@pytest.mark.django_db
def test_prepare_creates_session_and_bytes_to_sign() -> None:
    info, _ = make_rsa_certificate()
    document = _document()
    prepared = prepare_signing(document=document, certificate_der=info.der)
    assert prepared.session.status == SigningStatus.PREPARED
    assert prepared.bytes_to_sign
    assert prepared.session.certificate_thumbprint == info.thumbprint_sha256
    assert prepared.session.digest_algorithm == "sha256"
    assert prepared.session.subfilter == "/ETSI.CAdES.detached"
    assert prepared.expires_at > timezone.now()
    assert prepared.session.prepared_pdf.read()


@pytest.mark.django_db
def test_prepare_uses_gost_subfilter_and_digest() -> None:
    info, _ = make_gost_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    assert prepared.session.digest_algorithm == "streebog256"
    assert prepared.session.subfilter == "/adbe.pkcs7.detached"


@pytest.mark.django_db
def test_prepare_links_document() -> None:
    info, _ = make_rsa_certificate()
    document = _document()
    prepared = prepare_signing(document=document, certificate_der=info.der)
    assert prepared.session.object_id == str(document.pk)
    assert prepared.session.document == document


@pytest.mark.django_db
def test_prepare_uses_unique_field_names() -> None:
    info, _ = make_rsa_certificate()
    first = prepare_signing(document=_document(), certificate_der=info.der)
    second = prepare_signing(document=_document(), certificate_der=info.der)
    assert first.session.field_name != second.session.field_name


@pytest.mark.django_db
def test_prepare_rejects_bad_certificate() -> None:
    with pytest.raises(CertificateError):
        prepare_signing(document=_document(), certificate_der=b"garbage")


@pytest.mark.django_db
def test_prepare_rejects_oversized_document(settings) -> None:
    settings.DJANGO_PDF_SIGN = {"MAX_DOCUMENT_BYTES": 10}
    info, _ = make_rsa_certificate()
    with pytest.raises(SigningError):
        prepare_signing(document=_document(), certificate_der=info.der)


@pytest.mark.django_db
def test_prepare_requires_saved_document() -> None:
    info, _ = make_rsa_certificate()
    with pytest.raises(SigningError):
        prepare_signing(document=Document(), certificate_der=info.der)


@pytest.mark.django_db
def test_prepare_rejects_missing_file() -> None:
    info, _ = make_rsa_certificate()
    document = Document.objects.create()
    with pytest.raises(SigningError):
        prepare_signing(document=document, certificate_der=info.der)


@pytest.mark.django_db
def test_session_stores_box_and_page() -> None:
    info, _ = make_rsa_certificate()
    prepared = prepare_signing(
        document=_document(), certificate_der=info.der, box=(10, 10, 200, 100)
    )
    prepared.session.refresh_from_db()
    assert prepared.session.box == [10, 10, 200, 100]
    assert prepared.session.page == 0
    assert SigningSession.objects.count() == 1


@pytest.mark.django_db
def test_prepare_uses_configured_subfilter(settings) -> None:
    settings.DJANGO_PDF_SIGN = {"SUBFILTER": "/adbe.pkcs7.detached"}
    info, _ = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    assert prepared.session.subfilter == "/adbe.pkcs7.detached"


@pytest.mark.django_db
def test_prepare_uses_configured_default_page(settings) -> None:
    settings.DJANGO_PDF_SIGN = {"DEFAULT_PAGE": 0}
    info, _ = make_rsa_certificate()
    document = Document.objects.create(
        file=ContentFile(minimal_pdf(pages=2), name="doc.pdf")
    )
    prepared = prepare_signing(document=document, certificate_der=info.der)
    assert prepared.session.page == 0


@pytest.mark.django_db
def test_explicit_page_overrides_setting(settings) -> None:
    settings.DJANGO_PDF_SIGN = {"DEFAULT_PAGE": 0}
    info, _ = make_rsa_certificate()
    document = Document.objects.create(
        file=ContentFile(minimal_pdf(pages=2), name="doc.pdf")
    )
    prepared = prepare_signing(document=document, certificate_der=info.der, page=1)
    assert prepared.session.page == 1
