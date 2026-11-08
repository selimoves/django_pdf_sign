"""Сервис завершения подписи."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone

from django_pdf_sign.constants import (
    ChainStatus,
    RevocationStatus,
    SigningStatus,
    TimestampStatus,
    VerificationStatus,
)
from django_pdf_sign.crypto.cms import ParsedCms, parse_cms
from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.pades import verify_pades
from django_pdf_sign.crypto.policy import VerificationPolicy
from django_pdf_sign.crypto.timestamp import verify_timestamp_token
from django_pdf_sign.crypto.validation import validate_chain
from django_pdf_sign.exceptions import SessionError, VerificationError
from django_pdf_sign.models import SignatureRecord, SigningSession
from django_pdf_sign.pdf.embedder import embed_cms


@dataclass(frozen=True)
class CompletionResult:
    """Результат завершения сессии подписи."""

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
        raise SessionError("Сессия подписи не найдена") from exc


def _check_session(session: SigningSession, user: Any) -> None:
    if session.status != SigningStatus.PREPARED:
        raise SessionError(f"Сессия в статусе {session.status}, а не prepared")
    if session.is_expired:
        raise _ExpiredSessionError(session.pk)
    if session.user_id is not None and (
        user is None or getattr(user, "pk", None) != session.user_id
    ):
        raise SessionError("Сессия принадлежит другому пользователю")


def _prepared_bytes(session: SigningSession) -> bytes:
    session.prepared_pdf.open("rb")
    try:
        return bytes(session.prepared_pdf.read())
    finally:
        session.prepared_pdf.close()


def _verify(
    parsed: ParsedCms,
    session: SigningSession,
    policy: VerificationPolicy,
) -> dict[str, object]:
    if parsed.certificate.thumbprint_sha256 != session.certificate_thumbprint:
        raise VerificationError("Сертификат CMS не совпадает с сессией")
    if parsed.digest_algorithm != session.digest_algorithm:
        raise VerificationError("Алгоритм дайджеста CMS не совпадает с сессией")

    prepared_pdf = _prepared_bytes(session)
    start = session.reserved_region_start
    end = session.reserved_region_end
    signed_bytes = prepared_pdf[:start] + prepared_pdf[end:]

    if parsed.message_digest != digest_for(session.digest_algorithm, signed_bytes):
        raise VerificationError("messageDigest CMS не совпадает с документом")

    if parsed.certificate.is_gost:
        if parsed.certificate.curve_oid is None:
            raise VerificationError("В сертификате ГОСТ нет параметров кривой")
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
        raise VerificationError("Подпись CMS неверна")

    details: dict[str, object] = {
        "message_digest_ok": True,
        "signature_ok": True,
        "certificate_matches": True,
        "chain_ok": None,
        "trusted": None,
        "revoked": False,
        "validation_path": [],
        "timestamp_ok": None,
        "signing_time": None,
    }

    validation_moment = timezone.now()
    if parsed.timestamp_token is not None:
        timestamp = verify_timestamp_token(
            parsed.timestamp_token, signature_value=parsed.signature
        )
        details["timestamp_ok"] = timestamp.valid
        details["signing_time"] = (
            timestamp.gen_time.isoformat() if timestamp.gen_time else None
        )
        if timestamp.gen_time is not None and timestamp.valid:
            validation_moment = timestamp.gen_time
        if policy.check_timestamps and not timestamp.valid:
            reason = "; ".join(timestamp.errors) or "метка времени неверна"
            raise VerificationError(f"Проверка метки времени не пройдена: {reason}")
    elif policy.require_timestamp:
        details["timestamp_ok"] = False
        raise VerificationError("Требуется метка времени, но она отсутствует")

    if not (
        parsed.certificate.not_before
        <= validation_moment
        <= parsed.certificate.not_after
    ):
        raise VerificationError(
            "Сертификат подписанта недействителен на момент подписи"
        )

    if policy.check_chain:
        chain_policy = policy
        if validation_moment != policy.moment and parsed.timestamp_token is not None:
            from dataclasses import replace

            chain_policy = replace(policy, moment=validation_moment)
        chain = validate_chain(parsed.certificate.der, chain_policy)
        details.update(
            {
                "chain_ok": chain.valid,
                "trusted": chain.trusted,
                "revoked": chain.revoked,
                "validation_path": list(chain.validation_path),
                "chain_errors": list(chain.errors),
            }
        )
        if not chain.valid:
            reason = "; ".join(chain.errors) or "цепочка недействительна"
            raise VerificationError(f"Проверка цепочки не пройдена: {reason}")

    return details


def _chain_status(details: dict[str, object]) -> str:
    chain_ok = details.get("chain_ok")
    if chain_ok is None:
        return ChainStatus.NOT_CHECKED
    return ChainStatus.VALID if chain_ok else ChainStatus.INVALID


def _revocation_status(details: dict[str, object]) -> str:
    if details.get("revoked"):
        return RevocationStatus.REVOKED
    chain_ok = details.get("chain_ok")
    if chain_ok is None:
        return RevocationStatus.NOT_CHECKED
    return RevocationStatus.GOOD if chain_ok else RevocationStatus.UNKNOWN


def _timestamp_status(details: dict[str, object]) -> str:
    timestamp_ok = details.get("timestamp_ok")
    if timestamp_ok is None:
        return TimestampStatus.ABSENT
    return TimestampStatus.VALID if timestamp_ok else TimestampStatus.INVALID


def _signing_time(details: dict[str, object]) -> datetime | None:
    value = details.get("signing_time")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _trusted(details: dict[str, object]) -> bool | None:
    value = details.get("trusted")
    return value if isinstance(value, bool) else None


def complete_signing(
    *,
    session_id: Any,
    cms: bytes,
    user: Any = None,
    policy: VerificationPolicy | None = None,
) -> CompletionResult:
    """Проверить CMS клиента, встроить её в подготовленный PDF и записать результат."""
    effective_policy = policy or VerificationPolicy()
    try:
        with transaction.atomic():
            session = _load_session(session_id)
            _check_session(session, user)
            parsed = parse_cms(cms)
            details = _verify(parsed, session, effective_policy)

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
                verification_details=details,
                chain_status=_chain_status(details),
                revocation_status=_revocation_status(details),
                timestamp_status=_timestamp_status(details),
                trusted=_trusted(details),
                signing_time=_signing_time(details),
                validation_path=details.get("validation_path") or [],
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
        raise SessionError("Срок сессии истёк") from None
