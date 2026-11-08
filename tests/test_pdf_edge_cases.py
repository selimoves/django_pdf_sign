import io

import pytest
from django.core.files.base import ContentFile
from django.test import override_settings
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.exceptions import SigningError
from django_pdf_sign.models import SigningSession
from django_pdf_sign.services import (
    complete_signing,
    prepare_signing,
    verify_signed_pdf,
)
from tests.helpers import make_rsa_certificate, make_rsa_cms, minimal_pdf
from tests.models import Document


def _document(data: bytes) -> Document:
    return Document.objects.create(file=ContentFile(data, name="doc.pdf"))


def _prepared_bytes(session: SigningSession) -> bytes:
    session.prepared_pdf.open("rb")
    try:
        return bytes(session.prepared_pdf.read())
    finally:
        session.prepared_pdf.close()


def _encrypted_pdf() -> bytes:
    writer = PdfFileWriter()
    page = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Page"),
            generic.NameObject("/MediaBox"): generic.ArrayObject(
                [generic.NumberObject(value) for value in (0, 0, 612, 792)]
            ),
            generic.NameObject("/Resources"): generic.DictionaryObject(),
        }
    )
    writer.insert_page(page)
    writer.encrypt("owner", "user")
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _sign(pdf: bytes) -> bytes:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(pdf), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    return complete_signing(session_id=prepared.session.pk, cms=cms_bytes).signed_pdf


@pytest.mark.django_db
def test_encrypted_pdf_rejected() -> None:
    info, _ = make_rsa_certificate()
    with pytest.raises(SigningError):
        prepare_signing(document=_document(_encrypted_pdf()), certificate_der=info.der)


@pytest.mark.django_db
def test_pdf_with_incremental_update_signs() -> None:
    first_signed = _sign(minimal_pdf())
    second_signed = _sign(first_signed)
    result = verify_signed_pdf(second_signed)
    assert result.valid


@pytest.mark.django_db
def test_corrupted_pdf_rejected() -> None:
    info, _ = make_rsa_certificate()
    broken = minimal_pdf()[: len(minimal_pdf()) // 3]
    with pytest.raises(SigningError):
        prepare_signing(document=_document(broken), certificate_der=info.der)


@pytest.mark.django_db
def test_existing_signature_fields_are_kept() -> None:
    info, _ = make_rsa_certificate()
    first = prepare_signing(document=_document(minimal_pdf()), certificate_der=info.der)
    second = prepare_signing(
        document=_document(_prepared_bytes(first.session)), certificate_der=info.der
    )
    third = prepare_signing(
        document=_document(_prepared_bytes(second.session)), certificate_der=info.der
    )
    reader = PdfFileReader(io.BytesIO(_prepared_bytes(third.session)))
    fields = reader.root["/AcroForm"]["/Fields"]
    assert len(fields) == 3
    names = {field.get_object()["/T"] for field in fields}
    assert len(names) == 3


@pytest.mark.django_db
def test_empty_document_rejected() -> None:
    info, _ = make_rsa_certificate()
    with pytest.raises(SigningError):
        prepare_signing(document=_document(b""), certificate_der=info.der)


@pytest.mark.django_db
def test_document_size_limit_boundary() -> None:
    info, _ = make_rsa_certificate()
    pdf = minimal_pdf()
    with override_settings(DJANGO_PDF_SIGN={"MAX_DOCUMENT_BYTES": len(pdf)}):
        prepare_signing(document=_document(pdf), certificate_der=info.der)
    with (
        override_settings(DJANGO_PDF_SIGN={"MAX_DOCUMENT_BYTES": len(pdf) - 1}),
        pytest.raises(SigningError),
    ):
        prepare_signing(document=_document(pdf), certificate_der=info.der)


@pytest.mark.django_db
def test_cms_larger_than_placeholder_rejected() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(
        document=_document(minimal_pdf()),
        certificate_der=info.der,
        bytes_reserved=1000,
    )
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    assert len(cms_bytes) > 1002
    with pytest.raises(SigningError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    refreshed = SigningSession.objects.get(pk=prepared.session.pk)
    assert refreshed.status == SigningStatus.PREPARED
