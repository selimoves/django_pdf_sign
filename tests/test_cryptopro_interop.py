"""Интероп-проверка с реальным КриптоПро CSP через Docker.

Тест выполняется только при ``RUN_CRYPTOPRO_INTEROP=1`` и наличии Docker и
архива ``docker/cryptopro/dist/linux-amd64_deb.tgz``. В остальных случаях
пропускается, поэтому обычный прогон не требует КриптоПро.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from django.core.files.base import ContentFile

from django_pdf_sign.constants import SigningStatus, VerificationStatus
from django_pdf_sign.services import complete_signing, prepare_signing
from tests.helpers import minimal_pdf
from tests.models import Document

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import cryptopro_interop

pytestmark = pytest.mark.cryptopro_interop


def _enabled() -> bool:
    return (
        os.environ.get("RUN_CRYPTOPRO_INTEROP") == "1"
        and cryptopro_interop.docker_available()
        and cryptopro_interop.archive_available()
    )


@pytest.mark.django_db
def test_cryptopro_end_to_end() -> None:
    if not _enabled():
        pytest.skip("Нужны RUN_CRYPTOPRO_INTEROP=1, Docker и docker/cryptopro/dist")

    cryptopro_interop.build_image()
    certificate_der = cryptopro_interop.export_certificate()

    document = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=document, certificate_der=certificate_der)
    cms = cryptopro_interop.sign_bytes(prepared.bytes_to_sign)
    result = complete_signing(session_id=prepared.session.pk, cms=cms)

    assert result.session.status == SigningStatus.COMPLETED
    assert result.record.verification_status == VerificationStatus.VALID
    assert result.record.digest_algorithm == "streebog256"
