"""Разбор отсоединённых контейнеров CMS (CAdES-BES / PAdES)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from asn1crypto import cms, x509

from django_pdf_sign.crypto.certs import CertificateInfo, parse_certificate
from django_pdf_sign.crypto.oids import GOST_DIGEST_OIDS, SHA2_DIGEST_OIDS
from django_pdf_sign.exceptions import VerificationError


@dataclass(frozen=True)
class ParsedCms:
    """Поля отсоединённой CMS, нужные для проверки подписи PDF."""

    certificate: CertificateInfo
    message_digest: bytes
    digest_algorithm: str
    signature: bytes
    signed_attrs_der: bytes
    signing_time: datetime | None
    signature_algorithm_oid: str
    timestamp_token: bytes | None = None


def _certificate_set(signed_data: Any) -> Any:
    try:
        certificates = signed_data["certificates"]
    except (KeyError, TypeError) as exc:
        raise VerificationError("В CMS нет сертификатов") from exc
    if certificates is None:
        raise VerificationError("В CMS нет сертификатов")
    return certificates


def _find_certificate(signed_data: Any, signer_id: Any) -> x509.Certificate:
    certificates = _certificate_set(signed_data)
    if signer_id.name == "issuer_and_serial_number":
        issuer_and_serial = signer_id.chosen
        issuer_der = issuer_and_serial["issuer"].dump()
        serial = issuer_and_serial["serial_number"].native
        for choice in certificates:
            if choice.name != "certificate":
                continue
            certificate = choice.chosen
            if (
                certificate.issuer.dump() == issuer_der
                and certificate.serial_number == serial
            ):
                return certificate
    elif signer_id.name == "subject_key_identifier":
        key_identifier = signer_id.chosen.native
        for choice in certificates:
            if choice.name != "certificate":
                continue
            certificate = choice.chosen
            try:
                if certificate.key_identifier == key_identifier:
                    return certificate
            except (KeyError, ValueError):
                continue
    raise VerificationError("Сертификат подписанта не найден в CMS")


def _signed_attribute(attributes: Any, name: str) -> Any:
    for attribute in attributes:
        if attribute["type"].native == name:
            return attribute["values"][0].native
    return None


def _timestamp_token(signer_info: Any) -> bytes | None:
    try:
        unsigned = signer_info["unsigned_attrs"]
    except (KeyError, TypeError):
        return None
    if unsigned is None:
        return None
    try:
        for attribute in unsigned:
            if attribute["type"].native == "signature_time_stamp_token":
                return bytes(attribute["values"][0].dump())
    except (TypeError, KeyError):
        return None
    return None


def parse_cms(cms_bytes: bytes) -> ParsedCms:
    """Разобрать отсоединённую CMS в DER в :class:`ParsedCms`."""
    try:
        return _parse_cms(cms_bytes)
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("Не удалось разобрать CMS") from exc


def _parse_cms(cms_bytes: bytes) -> ParsedCms:
    content_info = cms.ContentInfo.load(cms_bytes)

    if content_info["content_type"].native != "signed_data":
        raise VerificationError("CMS не является контейнером SignedData")

    signed_data = content_info["content"]
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) != 1:
        raise VerificationError("CMS должна содержать ровно один SignerInfo")
    signer_info = signer_infos[0]

    try:
        attributes = signer_info["signed_attrs"]
    except (KeyError, TypeError) as exc:
        raise VerificationError("В CMS нет подписанных атрибутов") from exc
    if attributes is None:
        raise VerificationError("В CMS нет подписанных атрибутов")

    message_digest = _signed_attribute(attributes, "message_digest")
    if not isinstance(message_digest, bytes):
        raise VerificationError("В CMS нет атрибута messageDigest")

    digest_oid = signer_info["digest_algorithm"]["algorithm"].dotted
    digest_algorithm = GOST_DIGEST_OIDS.get(digest_oid) or SHA2_DIGEST_OIDS.get(
        digest_oid
    )
    if digest_algorithm is None:
        raise VerificationError(
            f"Неподдерживаемый алгоритм дайджеста CMS: {digest_oid}"
        )

    certificate = _find_certificate(signed_data, signer_info["sid"])
    signing_time = _signed_attribute(attributes, "signing_time")

    return ParsedCms(
        certificate=parse_certificate(certificate.dump()),
        message_digest=message_digest,
        digest_algorithm=digest_algorithm,
        signature=bytes(signer_info["signature"].native),
        signed_attrs_der=b"\x31" + attributes.dump()[1:],
        signing_time=signing_time if isinstance(signing_time, datetime) else None,
        signature_algorithm_oid=signer_info["signature_algorithm"]["algorithm"].dotted,
        timestamp_token=_timestamp_token(signer_info),
    )
