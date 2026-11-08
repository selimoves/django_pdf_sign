"""Parsing of X.509 certificates, including GOST public keys."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from asn1crypto import core, keys, x509
from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from django_pdf_sign.crypto.oids import EC_KEY_OID, GOST_KEY_OIDS, RSA_KEY_OID
from django_pdf_sign.exceptions import CertificateError


def _gost_public_key_spec(self: Any) -> Any:
    if self["algorithm"]["algorithm"].dotted in GOST_KEY_OIDS:
        return core.OctetBitString, None
    return keys.PublicKeyInfo._public_key_spec(self)


class GostPublicKeyInfo(keys.PublicKeyInfo):
    """``PublicKeyInfo`` that accepts the GOST 34.10-2012 key algorithm OIDs."""

    _spec_callbacks: ClassVar[dict[str, Any]] = {"public_key": _gost_public_key_spec}


@dataclass(frozen=True)
class CertificateInfo:
    """Parsed certificate fields used for stamping and verification."""

    der: bytes
    subject: str
    common_name: str | None
    organization: str | None
    serial_number: str
    thumbprint_sha256: str
    not_before: datetime
    not_after: datetime
    key_oid: str
    signature_oid: str
    curve_oid: str | None
    public_key: bytes
    key_size: int
    is_gost: bool


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _hex_serial(value: int) -> str:
    hexed = format(value, "X")
    return hexed if len(hexed) % 2 == 0 else "0" + hexed


def _gost_public_key(spki: keys.PublicKeyInfo) -> bytes:
    raw = GostPublicKeyInfo.load(spki.dump())["public_key"].native
    if not raw or raw[0] != 0x04:
        raise CertificateError("Unsupported GOST public key point encoding")
    return bytes(raw[1:])


def _key_size(der: bytes, key_oid: str) -> int:
    if key_oid in GOST_KEY_OIDS:
        return GOST_KEY_OIDS[key_oid]
    public_key = cryptography_x509.load_der_x509_certificate(der).public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.curve.key_size
    raise CertificateError(f"Unsupported public key type: {type(public_key).__name__}")


def parse_certificate(der: bytes) -> CertificateInfo:
    """Parse a DER-encoded X.509 certificate into a :class:`CertificateInfo`."""
    try:
        cert = x509.Certificate.load(der)
    except Exception as exc:
        raise CertificateError("Cannot parse certificate") from exc

    tbs = cert["tbs_certificate"]
    spki = GostPublicKeyInfo.load(tbs["subject_public_key_info"].dump())
    key_oid = spki["algorithm"]["algorithm"].dotted
    signature_oid = cert["signature_algorithm"]["algorithm"].dotted

    if key_oid not in GOST_KEY_OIDS and key_oid not in {RSA_KEY_OID, EC_KEY_OID}:
        raise CertificateError(f"Unsupported public key algorithm: {key_oid}")

    is_gost = key_oid in GOST_KEY_OIDS
    parameters = spki["algorithm"]["parameters"]
    curve_oid = str(parameters.native) if is_gost and parameters is not None else None

    native_subject = cert.subject.native
    validity = tbs["validity"]

    return CertificateInfo(
        der=bytes(der),
        subject=cert.subject.human_friendly,
        common_name=native_subject.get("common_name"),
        organization=native_subject.get("organization_name"),
        serial_number=_hex_serial(cert.serial_number),
        thumbprint_sha256=hashlib.sha256(der).hexdigest().upper(),
        not_before=_aware(validity["not_before"].native),
        not_after=_aware(validity["not_after"].native),
        key_oid=key_oid,
        signature_oid=signature_oid,
        curve_oid=curve_oid,
        public_key=_gost_public_key(spki) if is_gost else spki.dump(),
        key_size=_key_size(der, key_oid),
        is_gost=is_gost,
    )


def display_name(info: CertificateInfo) -> str:
    """Return the human-readable signer name for the stamp."""
    if info.organization and info.common_name:
        return f"{info.organization}, {info.common_name}"
    return info.common_name or info.organization or info.subject
