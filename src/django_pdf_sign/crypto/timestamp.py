"""Проверка метки времени CAdES-T (RFC 3161)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from asn1crypto import cms, core, tsp
from gostcrypto import gosthash

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.oids import (
    GOST_DIGEST_OIDS,
    GOST_SIGNATURE_OIDS,
    SHA2_DIGEST_OIDS,
    SIGNATURE_DIGEST_OIDS,
)
from django_pdf_sign.crypto.pades import verify_pades

SHA1_OID = "1.3.14.3.2.26"


@dataclass(frozen=True)
class TimestampResult:
    """Результат проверки метки времени."""

    present: bool
    valid: bool
    imprint_ok: bool
    gen_time: datetime | None
    errors: tuple[str, ...]


def _digest_name(oid: str) -> str | None:
    if oid == SHA1_OID:
        return "sha1"
    return GOST_DIGEST_OIDS.get(oid) or SHA2_DIGEST_OIDS.get(oid)


def _hash(name: str, data: bytes) -> bytes:
    if name in ("streebog256", "streebog512"):
        return bytes(gosthash.new(name, data=data).digest())
    import hashlib

    return hashlib.new(name, data).digest()


def _find_attribute(attributes: Any, name: str) -> Any:
    if attributes is None:
        return None
    try:
        for attribute in attributes:
            if attribute["type"].native == name:
                return attribute["values"][0]
    except (TypeError, KeyError):
        return None
    return None


def _signature_digest(oid: str) -> str | None:
    mapped = SIGNATURE_DIGEST_OIDS.get(oid)
    if mapped is not None:
        return mapped
    for name in ("sha512", "sha384", "sha256", "sha1"):
        if name in oid.lower():
            return name
    return None


def _verify_token_signature(
    signed_data: cms.SignedData,
) -> tuple[bool, tuple[str, ...]]:
    signer_info = signed_data["signer_infos"][0]
    certificates = signed_data["certificates"]
    if certificates is None or len(certificates) == 0:
        return False, ("В метке времени нет сертификата TSA",)
    certificate = certificates[0].chosen
    certificate_der = certificate.dump()
    algorithm_oid = signer_info["signature_algorithm"]["algorithm"].dotted
    signature = signer_info["signature"].native

    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is not None and signed_attrs is not core.VOID:
        signed_bytes = b"\x31" + signed_attrs.dump()[1:]
        message_digest = _find_attribute(signed_attrs, "message_digest")
        content = signed_data["encap_content_info"]["content"]
        if message_digest is not None and content is not None:
            digest_name = _digest_name(
                signer_info["digest_algorithm"]["algorithm"].dotted
            )
            if digest_name is not None and message_digest.native != _hash(
                digest_name, bytes(content)
            ):
                return False, ("messageDigest метки времени не совпадает",)
    else:
        signed_bytes = bytes(signed_data["encap_content_info"]["content"])

    try:
        if algorithm_oid in GOST_SIGNATURE_OIDS:
            info = parse_certificate(certificate_der)
            if info.curve_oid is None:
                return False, ("В сертификате TSA нет параметров кривой",)
            digest_name = "streebog256" if info.key_size == 256 else "streebog512"
            ok = verify_gost(
                public_key=info.public_key,
                curve_oid=info.curve_oid,
                digest=_hash(digest_name, signed_bytes),
                signature=signature,
                key_size=info.key_size,
            )
        else:
            digest_name = _signature_digest(algorithm_oid)
            if digest_name is None:
                return False, ("Неподдерживаемый алгоритм подписи TSA",)
            ok = verify_pades(
                certificate_der=certificate_der,
                signed_attrs_der=signed_bytes,
                signature=signature,
                digest_algorithm=digest_name,
            )
    except Exception as exc:
        return False, (f"Ошибка проверки подписи TSA: {exc}",)

    if not ok:
        return False, ("Подпись метки времени неверна",)
    return True, ()


def verify_timestamp_token(
    token_der: bytes,
    *,
    signature_value: bytes | None = None,
    imprinted_data: bytes | None = None,
) -> TimestampResult:
    """Проверить метку времени и её imprint.

    Для CAdES-T imprint считается над значением подписи
    (``signature_value``), для PDF DocTimeStamp — над байтами документа
    (``imprinted_data``).
    """
    covered = imprinted_data if imprinted_data is not None else signature_value
    if covered is None:
        raise ValueError("Нужно передать signature_value или imprinted_data")
    try:
        token = cms.ContentInfo.load(token_der)
        signed_data = token["content"]
        tst_info_der = bytes(signed_data["encap_content_info"]["content"])
        tst_info = tsp.TSTInfo.load(tst_info_der)

        errors: list[str] = []
        imprint = tst_info["message_imprint"]
        digest_name = _digest_name(imprint["hash_algorithm"]["algorithm"].dotted)
        imprint_ok = False
        if digest_name is None:
            errors.append("Неподдерживаемый алгоритм imprint метки времени")
        else:
            imprint_ok = imprint["hashed_message"].native == _hash(digest_name, covered)
            if not imprint_ok:
                errors.append("Imprint метки времени не совпадает с данными")

        signature_ok, signature_errors = _verify_token_signature(signed_data)
        errors.extend(signature_errors)
        gen_time = tst_info["gen_time"].native
    except Exception as exc:
        return TimestampResult(
            present=True,
            valid=False,
            imprint_ok=False,
            gen_time=None,
            errors=(f"Не удалось разобрать метку времени: {exc}",),
        )

    return TimestampResult(
        present=True,
        valid=imprint_ok and signature_ok,
        imprint_ok=imprint_ok,
        gen_time=gen_time,
        errors=tuple(errors),
    )


def verify_document_timestamp(
    token_der: bytes, document_bytes: bytes
) -> TimestampResult:
    """Проверить метку времени PDF DocTimeStamp над байтами документа."""
    return verify_timestamp_token(token_der, imprinted_data=document_bytes)
