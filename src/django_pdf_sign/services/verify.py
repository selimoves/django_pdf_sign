"""Публичные проверки CMS и подписанных PDF."""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime

from pyhanko.pdf_utils.reader import PdfFileReader

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.pades import verify_pades
from django_pdf_sign.crypto.policy import VerificationPolicy
from django_pdf_sign.crypto.timestamp import verify_timestamp_token
from django_pdf_sign.crypto.validation import validate_chain
from django_pdf_sign.exceptions import CertificateError, VerificationError


@dataclass(frozen=True)
class VerificationResult:
    """Итог проверки CMS или подписанного PDF."""

    valid: bool
    message_digest_ok: bool
    signature_ok: bool
    certificate_matches: bool
    errors: tuple[str, ...] = ()
    chain_ok: bool | None = None
    trusted: bool | None = None
    revoked: bool = False
    timestamp_ok: bool | None = None
    signing_time: datetime | None = None
    validation_path: tuple[str, ...] = ()
    details: dict[str, object] = field(default_factory=dict)


def _invalid(message: str) -> VerificationResult:
    return VerificationResult(
        valid=False,
        message_digest_ok=False,
        signature_ok=False,
        certificate_matches=False,
        errors=(message,),
    )


def _signature_ok(parsed: object) -> bool:
    if parsed.certificate.is_gost:  # type: ignore[attr-defined]
        if parsed.certificate.curve_oid is None:  # type: ignore[attr-defined]
            raise VerificationError("В сертификате ГОСТ нет параметров кривой")
        return verify_gost(
            public_key=parsed.certificate.public_key,  # type: ignore[attr-defined]
            curve_oid=parsed.certificate.curve_oid,  # type: ignore[attr-defined]
            digest=digest_for(
                parsed.digest_algorithm,  # type: ignore[attr-defined]
                parsed.signed_attrs_der,  # type: ignore[attr-defined]
            ),
            signature=parsed.signature,  # type: ignore[attr-defined]
            key_size=parsed.certificate.key_size,  # type: ignore[attr-defined]
        )
    return verify_pades(
        certificate_der=parsed.certificate.der,  # type: ignore[attr-defined]
        signed_attrs_der=parsed.signed_attrs_der,  # type: ignore[attr-defined]
        signature=parsed.signature,  # type: ignore[attr-defined]
        digest_algorithm=parsed.digest_algorithm,  # type: ignore[attr-defined]
    )


def verify_cms_over_bytes(
    *,
    cms: bytes,
    data: bytes,
    expected_certificate_der: bytes | None = None,
    policy: VerificationPolicy | None = None,
) -> VerificationResult:
    """Проверить отсоединённую CMS над `data`.

    Цепочка и отзыв проверяются только при ``policy.check_chain``.
    """
    try:
        parsed = parse_cms(cms)
    except VerificationError as exc:
        return _invalid(str(exc))

    errors: list[str] = []

    certificate_matches = True
    if expected_certificate_der is not None:
        try:
            expected = parse_certificate(expected_certificate_der)
            certificate_matches = (
                parsed.certificate.thumbprint_sha256 == expected.thumbprint_sha256
            )
        except CertificateError as exc:
            certificate_matches = False
            errors.append(str(exc))
        if not certificate_matches:
            errors.append("Сертификат не совпадает с ожидаемым")

    message_digest_ok = parsed.message_digest == digest_for(
        parsed.digest_algorithm, data
    )
    if not message_digest_ok:
        errors.append("messageDigest не совпадает")

    try:
        signature_ok = _signature_ok(parsed)
    except (VerificationError, ValueError) as exc:
        signature_ok = False
        errors.append(str(exc))
    if not signature_ok:
        errors.append("Подпись неверна")

    chain_ok: bool | None = None
    trusted: bool | None = None
    revoked = False
    validation_path: tuple[str, ...] = ()
    if policy is not None and policy.check_chain:
        chain = validate_chain(parsed.certificate.der, policy)
        chain_ok = chain.valid
        trusted = chain.trusted
        revoked = chain.revoked
        validation_path = chain.validation_path
        errors.extend(chain.errors)

    timestamp_ok: bool | None = None
    signing_time = parsed.signing_time
    if parsed.timestamp_token is not None:
        timestamp = verify_timestamp_token(
            parsed.timestamp_token, signature_value=parsed.signature
        )
        timestamp_ok = timestamp.valid
        signing_time = timestamp.gen_time or signing_time
        if policy is not None and policy.check_timestamps:
            errors.extend(timestamp.errors)
    elif policy is not None and policy.require_timestamp:
        timestamp_ok = False
        errors.append("Метка времени отсутствует")

    return VerificationResult(
        valid=(
            certificate_matches
            and message_digest_ok
            and signature_ok
            and chain_ok is not False
            and timestamp_ok is not False
        ),
        message_digest_ok=message_digest_ok,
        signature_ok=signature_ok,
        certificate_matches=certificate_matches,
        errors=tuple(errors),
        chain_ok=chain_ok,
        trusted=trusted,
        revoked=revoked,
        timestamp_ok=timestamp_ok,
        signing_time=signing_time,
        validation_path=validation_path,
    )


def verify_signed_pdf(
    pdf: bytes,
    policy: VerificationPolicy | None = None,
    signature_index: int = 0,
) -> VerificationResult:
    """Проверить подпись PDF по индексу без оценки доверия (если не задана политика)."""
    try:
        reader = PdfFileReader(io.BytesIO(pdf))
        signatures = reader.embedded_signatures
    except Exception as exc:
        return _invalid(f"Не удалось прочитать PDF: {exc}")
    if not signatures:
        return _invalid("В PDF нет подписей")
    if not 0 <= signature_index < len(signatures):
        return _invalid(f"Индекс подписи вне диапазона: {signature_index}")

    signature = signatures[signature_index]
    try:
        contents = signature.sig_object["/Contents"].original_bytes
        byte_range = [int(value) for value in signature.sig_object["/ByteRange"]]
    except (KeyError, TypeError, ValueError) as exc:
        return _invalid(f"Не удалось прочитать подпись: {exc}")

    if len(byte_range) != 4:
        return _invalid("Некорректный ByteRange")

    start, length, offset, tail = byte_range
    data = pdf[start : start + length] + pdf[offset : offset + tail]
    return verify_cms_over_bytes(cms=contents, data=data, policy=policy)
