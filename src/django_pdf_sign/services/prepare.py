"""Сервис подготовки подписи."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
from django.db.models import Model
from django.utils import timezone

from django_pdf_sign.conf import get_setting
from django_pdf_sign.constants import SUBFILTER_ADOBE_PKCS7, SUBFILTER_PADES
from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.events import emit
from django_pdf_sign.exceptions import SigningError
from django_pdf_sign.models import SigningSession
from django_pdf_sign.pdf.embedder import prepare_document


@dataclass(frozen=True)
class PreparedSigning:
    """Результат подготовки документа к клиентской подписи."""

    session: SigningSession
    bytes_to_sign: bytes
    digest_algorithm: str
    expires_at: datetime


def _read_document(document: Model, file_field: str) -> bytes:
    if document.pk is None:
        raise SigningError("Документ должен быть сохранён до подписи")

    field_file = getattr(document, file_field, None)
    if field_file is None:
        raise SigningError(f"У документа нет поля {file_field!r}")
    if not field_file:
        raise SigningError(f"В поле {file_field!r} нет файла документа")

    limit = int(get_setting("MAX_DOCUMENT_BYTES"))
    try:
        size = field_file.size
    except OSError as exc:
        raise SigningError(f"Не удалось прочитать файл документа: {exc}") from exc
    if size > limit:
        raise SigningError(f"Документ больше лимита {limit} байт")

    try:
        field_file.open("rb")
        try:
            return bytes(field_file.read())
        finally:
            field_file.close()
    except OSError as exc:
        raise SigningError(f"Не удалось прочитать файл документа: {exc}") from exc


def prepare_signing(
    *,
    document: Model,
    certificate_der: bytes,
    user: Any = None,
    file_field: str = "file",
    page: int | None = None,
    box: tuple[int, int, int, int] | None = None,
    reason: str | None = None,
    location: str | None = None,
    field_name: str | None = None,
    subfilter: str | None = None,
    bytes_reserved: int | None = None,
) -> PreparedSigning:
    """Подготовить документ, сохранить сессию и вернуть байты для подписи."""
    certificate = parse_certificate(certificate_der)
    pdf = _read_document(document, file_field)

    resolved_page = int(get_setting("DEFAULT_PAGE")) if page is None else page
    resolved_subfilter = (
        subfilter
        or get_setting("SUBFILTER")
        or (SUBFILTER_ADOBE_PKCS7 if certificate.is_gost else SUBFILTER_PADES)
    )
    prepared = prepare_document(
        pdf=pdf,
        certificate=certificate,
        field_name=field_name or f"Signature{uuid.uuid4().hex[:8]}",
        page=resolved_page,
        box=box,
        reason=reason,
        location=location,
        subfilter=resolved_subfilter,
        bytes_reserved=bytes_reserved,
    )

    expires_at = timezone.now() + timedelta(seconds=int(get_setting("SESSION_TTL")))
    session_user = user if user is not None and user.is_authenticated else None
    session = SigningSession(
        user=session_user,
        content_type=ContentType.objects.get_for_model(document),
        object_id=str(document.pk),
        certificate_der=certificate.der,
        certificate_subject=certificate.subject,
        certificate_common_name=certificate.common_name or "",
        certificate_organization=certificate.organization or "",
        certificate_serial=certificate.serial_number,
        certificate_thumbprint=certificate.thumbprint_sha256,
        certificate_not_before=certificate.not_before,
        certificate_not_after=certificate.not_after,
        digest_algorithm=prepared.digest_algorithm,
        subfilter=resolved_subfilter,
        field_name=prepared.field_name,
        page=prepared.page,
        box=list(box) if box is not None else None,
        bytes_reserved=bytes_reserved or int(get_setting("BYTES_RESERVED")),
        reserved_region_start=prepared.reserved_region_start,
        reserved_region_end=prepared.reserved_region_end,
        expires_at=expires_at,
        metadata={"reason": reason, "location": location},
    )
    session.prepared_pdf.save(
        f"{session.pk}.pdf",
        ContentFile(prepared.pdf_with_placeholder),
        save=False,
    )
    session.save()
    emit("session_prepared", session_id=str(session.pk), status=session.status)

    return PreparedSigning(
        session=session,
        bytes_to_sign=prepared.bytes_to_sign,
        digest_algorithm=prepared.digest_algorithm,
        expires_at=expires_at,
    )
