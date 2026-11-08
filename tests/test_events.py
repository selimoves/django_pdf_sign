import logging

import pytest
from django.core.files.base import ContentFile

from django_pdf_sign.exceptions import VerificationError
from django_pdf_sign.services import complete_signing, prepare_signing
from tests.helpers import make_rsa_certificate, make_rsa_cms, minimal_pdf
from tests.models import Document


def _document() -> Document:
    return Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))


@pytest.mark.django_db
def test_session_prepared_event(settings) -> None:
    events: list[tuple[str, dict]] = []
    settings.DJANGO_PDF_SIGN = {
        "ON_EVENT": lambda event, fields: events.append((event, fields))
    }
    info, _ = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    assert events[0][0] == "session_prepared"
    assert events[0][1]["session_id"] == str(prepared.session.pk)


@pytest.mark.django_db
def test_signing_completed_event(settings) -> None:
    events: list[tuple[str, dict]] = []
    settings.DJANGO_PDF_SIGN = {
        "ON_EVENT": lambda event, fields: events.append((event, fields))
    }
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    assert [event for event, _ in events] == [
        "session_prepared",
        "signing_completed",
    ]


@pytest.mark.django_db
def test_verification_failed_event_and_no_cms_in_logs(settings, caplog) -> None:
    events: list[tuple[str, dict]] = []
    settings.DJANGO_PDF_SIGN = {
        "ON_EVENT": lambda event, fields: events.append((event, fields))
    }
    caplog.set_level(logging.INFO, logger="django_pdf_sign")
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=b"other data", signer=(info, key))
    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    assert events[-1][0] == "verification_failed"
    assert cms_bytes.hex() not in caplog.text
    assert cms_bytes.hex().upper() not in caplog.text


@pytest.mark.django_db
def test_broken_event_handler_does_not_break_signing(settings) -> None:
    def broken(event: str, fields: dict) -> None:
        raise RuntimeError("обработчик упал")

    settings.DJANGO_PDF_SIGN = {"ON_EVENT": broken}
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    assert result.signed_pdf
