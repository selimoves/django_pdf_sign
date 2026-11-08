"""Signing completion service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus, VerificationStatus
from django_pdf_sign.crypto.cms import ParsedCms, parse_cms
from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.pades import verify_pades
from django_pdf_sign.exceptions import SessionError, VerificationError
from django_pdf_sign.models import SignatureRecord, SigningSession
from django_pdf_sign.pdf.embedder import embed_cms


@dataclass(frozen=True)
class CompletionResult:
    """Result of completing a signing session."""

    session: SigningSession
    record: SignatureRecord
    signed_pdf: bytes


class _ExpiredSessionError(Exception):
    def __init__(self, session_id: Any) -> None:
        self.session_id = session_id


def _load_session(session_id: Any) -> SigningSession:
    try:
        return SigningSession.objects.select_for_update().get(pk=session_id)
    except (SigningSession.DoesNotExist, ValidationError, ValueError) as exc:
        raise SessionError("Signing session not found") from exc


def _check_session(session: SigningSession, user: Any) -> None:
    if session.status != SigningStatus.PREPARED:
        raise SessionError(f"Signing session is {session.status}, not prepared")
    if session.is_expired:
        raise _ExpiredSessionError(session.pk)
    if session.user_id is not None and (
        user is None or getattr(user, "pk", None) != session.user_id
    ):
        raise SessionError("Signing session belongs to another user")


def _prepared_bytes(session: SigningSession) -> bytes:
    session.prepared_pdf.open("rb")
    try:
        return bytes(session.prepared_pdf.read())
    finally:
        session.prepared_pdf.close()


def _verify(parsed: ParsedCms, session: SigningSession) -> None:
    if parsed.certificate.thumbprint_sha256 != session.certificate_thumbprint:
        raise VerificationError("CMS certificate does not match the session")
    if parsed.digest_algorithm != session.digest_algorithm:
        raise VerificationError("CMS digest algorithm does not match the session")

    now = timezone.now()
    if not parsed.certificate.not_before <= now <= parsed.certificate.not_after:
        raise VerificationError("Signer certificate is not valid at signing time")

    prepared_pdf = _prepared_bytes(session)
    start = session.reserved_region_start
    end = session.reserved_region_end
    signed_bytes = prepared_pdf[:start] + prepared_pdf[end:]

    if parsed.message_digest != digest_for(session.digest_algorithm, signed_bytes):
        raise VerificationError("CMS messageDigest does not match the document")

    if parsed.certificate.is_gost:
        if parsed.certificate.curve_oid is None:
            raise VerificationError("GOST certificate has no curve parameters")
        attributes_digest = digest_for(parsed.digest_algorithm, parsed.signed_attrs_der)
        signature_valid = verify_gost(
            public_key=parsed.certificate.public_key,
            curve_oid=parsed.certificate.curve_oid,
            digest=attributes_digest,
            signature=parsed.signature,
            key_size=parsed.certificate.key_size,
        )
    else:
        signature_valid = verify_pades(
            certificate_der=parsed.certificate.der,
            signed_attrs_der=parsed.signed_attrs_der,
            signature=parsed.signature,
            digest_algorithm=parsed.digest_algorithm,
        )

    if not signature_valid:
        raise VerificationError("CMS signature is invalid")


def complete_signing(
    *, session_id: Any, cms: bytes, user: Any = None
) -> CompletionResult:
    """Verify a client CMS, embed it into the prepared PDF and record the result."""
    try:
        with transaction.atomic():
            session = _load_session(session_id)
            _check_session(session, user)
            parsed = parse_cms(cms)
            _verify(parsed, session)

            prepared_pdf = _prepared_bytes(session)
            signed_pdf = embed_cms(
                prepared_pdf=prepared_pdf,
                reserved_region_start=session.reserved_region_start,
                reserved_region_end=session.reserved_region_end,
                cms=cms,
            )

            record = SignatureRecord(
                session=session,
                content_type=session.content_type,
                object_id=session.object_id,
                user=session.user,
                certificate_der=parsed.certificate.der,
                certificate_subject=parsed.certificate.subject,
                certificate_common_name=parsed.certificate.common_name or "",
                certificate_organization=parsed.certificate.organization or "",
                certificate_serial=parsed.certificate.serial_number,
                certificate_thumbprint=parsed.certificate.thumbprint_sha256,
                digest_algorithm=parsed.digest_algorithm,
                subfilter=session.subfilter,
                cms_size=len(cms),
                verification_status=VerificationStatus.VALID,
                verification_details={
                    "message_digest_ok": True,
                    "signature_ok": True,
                    "certificate_matches": True,
                },
            )
            record.signed_pdf.save(
                f"{session.pk}.pdf", ContentFile(signed_pdf), save=False
            )
            record.save()

            session.status = SigningStatus.COMPLETED
            session.completed_at = timezone.now()
            session.save(update_fields=["status", "completed_at"])

            return CompletionResult(
                session=session, record=record, signed_pdf=signed_pdf
            )
    except _ExpiredSessionError as exc:
        SigningSession.objects.filter(pk=exc.session_id).update(
            status=SigningStatus.EXPIRED
        )
        raise SessionError("Signing session has expired") from None
