"""Public verification helpers for CMS objects and signed PDFs."""

from __future__ import annotations

import io
from dataclasses import dataclass

from pyhanko.pdf_utils.reader import PdfFileReader

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.pades import verify_pades
from django_pdf_sign.exceptions import CertificateError, VerificationError


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a CMS or a signed PDF."""

    valid: bool
    message_digest_ok: bool
    signature_ok: bool
    certificate_matches: bool
    errors: tuple[str, ...]


def _invalid(message: str) -> VerificationResult:
    return VerificationResult(
        valid=False,
        message_digest_ok=False,
        signature_ok=False,
        certificate_matches=False,
        errors=(message,),
    )


def verify_cms_over_bytes(
    *,
    cms: bytes,
    data: bytes,
    expected_certificate_der: bytes | None = None,
) -> VerificationResult:
    """Verify a detached CMS over ``data`` without evaluating trust."""
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
            errors.append("Certificate does not match")

    message_digest_ok = parsed.message_digest == digest_for(
        parsed.digest_algorithm, data
    )
    if not message_digest_ok:
        errors.append("messageDigest does not match")

    try:
        if parsed.certificate.is_gost:
            if parsed.certificate.curve_oid is None:
                raise VerificationError("GOST certificate has no curve parameters")
            signature_ok = verify_gost(
                public_key=parsed.certificate.public_key,
                curve_oid=parsed.certificate.curve_oid,
                digest=digest_for(parsed.digest_algorithm, parsed.signed_attrs_der),
                signature=parsed.signature,
                key_size=parsed.certificate.key_size,
            )
        else:
            signature_ok = verify_pades(
                certificate_der=parsed.certificate.der,
                signed_attrs_der=parsed.signed_attrs_der,
                signature=parsed.signature,
                digest_algorithm=parsed.digest_algorithm,
            )
    except VerificationError as exc:
        signature_ok = False
        errors.append(str(exc))
    if not signature_ok:
        errors.append("Signature is invalid")

    return VerificationResult(
        valid=certificate_matches and message_digest_ok and signature_ok,
        message_digest_ok=message_digest_ok,
        signature_ok=signature_ok,
        certificate_matches=certificate_matches,
        errors=tuple(errors),
    )


def verify_signed_pdf(pdf: bytes) -> VerificationResult:
    """Verify the first embedded signature of a signed PDF without evaluating trust."""
    try:
        reader = PdfFileReader(io.BytesIO(pdf))
        signatures = reader.embedded_signatures
    except Exception as exc:
        return _invalid(f"Cannot read PDF: {exc}")
    if not signatures:
        return _invalid("PDF has no signatures")

    signature = signatures[0]
    try:
        contents = signature.sig_object["/Contents"].original_bytes
        byte_range = [int(value) for value in signature.sig_object["/ByteRange"]]
    except (KeyError, TypeError, ValueError) as exc:
        return _invalid(f"Cannot read signature: {exc}")

    if len(byte_range) != 4:
        return _invalid("Invalid ByteRange")

    start, length, offset, tail = byte_range
    data = pdf[start : start + length] + pdf[offset : offset + tail]
    return verify_cms_over_bytes(cms=contents, data=data)
