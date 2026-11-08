"""Pin the public protocol contract used by clients."""

from __future__ import annotations

from dataclasses import fields

import pytest
from django.core.files.base import ContentFile

from django_pdf_sign.constants import (
    DIGEST_SHA256,
    DIGEST_STREEBOG_256,
    DIGEST_STREEBOG_512,
    SUBFILTER_ADOBE_PKCS7,
    SUBFILTER_PADES,
)
from django_pdf_sign.services import (
    CompletionResult,
    PreparedSigning,
    prepare_signing,
)
from tests.helpers import make_rsa_certificate, minimal_pdf
from tests.models import Document


def test_digest_algorithm_names() -> None:
    assert DIGEST_STREEBOG_256 == "streebog256"
    assert DIGEST_STREEBOG_512 == "streebog512"
    assert DIGEST_SHA256 == "sha256"


def test_subfilter_values() -> None:
    assert SUBFILTER_ADOBE_PKCS7 == "/adbe.pkcs7.detached"
    assert SUBFILTER_PADES == "/ETSI.CAdES.detached"


def test_prepared_signing_fields() -> None:
    names = {field.name for field in fields(PreparedSigning)}
    assert names == {"session", "bytes_to_sign", "digest_algorithm", "expires_at"}


def test_completion_result_fields() -> None:
    names = {field.name for field in fields(CompletionResult)}
    assert names == {"session", "record", "signed_pdf"}


@pytest.mark.django_db
def test_prepare_response_is_json_ready() -> None:
    info, _ = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    assert isinstance(prepared.bytes_to_sign, bytes)
    assert prepared.digest_algorithm in {"streebog256", "streebog512", "sha256"}
    assert prepared.session.pk is not None
