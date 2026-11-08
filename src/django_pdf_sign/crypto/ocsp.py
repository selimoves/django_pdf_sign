"""Проверка ответов OCSP, включая ГОСТ-идентификаторы сертификатов."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from asn1crypto import ocsp, x509
from gostcrypto import gosthash

from django_pdf_sign.crypto.certs import (
    GostPublicKeyInfo,
    parse_certificate,
)
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.oids import (
    GOST_DIGEST_OIDS,
    GOST_KEY_OIDS,
    GOST_SIGNATURE_OIDS,
    SHA2_DIGEST_OIDS,
)
from django_pdf_sign.crypto.pades import verify_pades

SHA1_OID = "1.3.14.3.2.26"
_TIME_TOLERANCE = timedelta(seconds=60)


@dataclass(frozen=True)
class OcspStatus:
    """Результат проверки ответа OCSP для конкретного сертификата."""

    applicable: bool
    good: bool
    revoked: bool
    errors: tuple[str, ...]
    this_update: datetime | None = None
    next_update: datetime | None = None
    produced_at: datetime | None = None


def _digest_name(oid: str) -> str | None:
    if oid == SHA1_OID:
        return "sha1"
    return GOST_DIGEST_OIDS.get(oid) or SHA2_DIGEST_OIDS.get(oid)


def _hash(name: str, data: bytes) -> bytes:
    if name in ("streebog256", "streebog512"):
        return bytes(gosthash.new(name, data=data).digest())
    return hashlib.new(name, data).digest()


def _spki_bits(certificate: x509.Certificate) -> bytes:
    spki = certificate["tbs_certificate"]["subject_public_key_info"]
    algorithm = spki["algorithm"]["algorithm"].dotted
    if algorithm in GOST_KEY_OIDS:
        return bytes(GostPublicKeyInfo.load(spki.dump())["public_key"].native)
    return bytes(spki["public_key"].native)


def _cert_id_matches(
    cert_id: ocsp.CertId,
    target: x509.Certificate,
    issuer: x509.Certificate,
) -> bool:
    name = _digest_name(cert_id["hash_algorithm"]["algorithm"].dotted)
    if name is None:
        return False
    try:
        name_hash = _hash(name, issuer.subject.dump())
        key_hash = _hash(name, _spki_bits(issuer))
    except Exception:
        return False
    return bool(
        cert_id["serial_number"].native == target.serial_number
        and cert_id["issuer_name_hash"].native == name_hash
        and cert_id["issuer_key_hash"].native == key_hash
    )


def _signature_digest(signature_algorithm: str) -> str | None:
    lowered = signature_algorithm.lower()
    for name in ("sha512", "sha384", "sha256", "sha1"):
        if name in lowered:
            return name
    return None


def _responder_certificate(
    basic: ocsp.BasicOCSPResponse, issuer: x509.Certificate
) -> tuple[x509.Certificate, bytes]:
    certificates = basic["certs"]
    if certificates is not None and len(certificates) > 0:
        responder = certificates[0].chosen
        return responder, responder.dump()
    return issuer, issuer.dump()


def _verify_ocsp_signature(
    basic: ocsp.BasicOCSPResponse, issuer: x509.Certificate
) -> tuple[bool, tuple[str, ...]]:
    responder, responder_der = _responder_certificate(basic, issuer)
    signed_data = basic["tbs_response_data"].dump()
    signature = basic["signature"].native
    algorithm_oid = basic["signature_algorithm"]["algorithm"].dotted

    responder_id = basic["tbs_response_data"]["responder_id"]
    if responder_id.name == "by_name":
        if responder_id.chosen.native != responder.subject.native:
            return False, ("ResponderID не совпадает с сертификатом ответчика",)
    elif responder_id.name == "by_key":
        try:
            key_hash = hashlib.sha1(_spki_bits(responder)).digest()
        except Exception:
            key_hash = b""
        if responder_id.chosen.native != key_hash:
            return False, ("ResponderID по ключу не совпадает",)

    try:
        if algorithm_oid in GOST_SIGNATURE_OIDS:
            info = parse_certificate(responder_der)
            if info.curve_oid is None:
                return False, ("В сертификате ответчика нет параметров кривой",)
            digest_name = "streebog256" if info.key_size == 256 else "streebog512"
            ok = verify_gost(
                public_key=info.public_key,
                curve_oid=info.curve_oid,
                digest=_hash(digest_name, signed_data),
                signature=signature,
                key_size=info.key_size,
            )
        else:
            pades_digest = _signature_digest(algorithm_oid)
            if pades_digest is None:
                return False, ("Неподдерживаемый алгоритм подписи OCSP",)
            ok = verify_pades(
                certificate_der=responder_der,
                signed_attrs_der=signed_data,
                signature=signature,
                digest_algorithm=pades_digest,
            )
    except Exception as exc:
        return False, (f"Ошибка проверки подписи OCSP: {exc}",)

    if not ok:
        return False, ("Подпись ответа OCSP неверна",)
    return True, ()


def _now(moment: datetime | None) -> datetime:
    return moment or datetime.now(UTC)


def evaluate_ocsps(
    responses: tuple[bytes, ...],
    *,
    target_der: bytes,
    issuer_der: bytes,
    moment: datetime | None = None,
) -> OcspStatus:
    """Найти и проверить ответ OCSP для ``target_der``.

    Возвращает ``applicable=False``, если ни один ответ не относится к
    сертификату.
    """
    if not responses:
        return OcspStatus(False, False, False, ())

    target = x509.Certificate.load(target_der)
    issuer = x509.Certificate.load(issuer_der)
    now = _now(moment)
    last_errors: tuple[str, ...] = ()
    best: tuple[datetime, ocsp.SingleResponse, ocsp.BasicOCSPResponse] | None = None

    for der in responses:
        try:
            response = ocsp.OCSPResponse.load(der)
            if response["response_status"].native != "successful":
                last_errors = (f"Статус OCSP: {response['response_status'].native}",)
                continue
            response_bytes = response["response_bytes"]
            basic = response_bytes["response"].parsed
            if basic is None:
                basic = ocsp.BasicOCSPResponse.load(response_bytes["response"].native)
            data = basic["tbs_response_data"]
            for single in data["responses"]:
                if _cert_id_matches(single["cert_id"], target, issuer):
                    produced_at = data["produced_at"].native
                    if best is None or produced_at > best[0]:
                        best = (produced_at, single, basic)
        except Exception as exc:
            last_errors = (f"Не удалось разобрать OCSP: {exc}",)
            continue

    if best is None:
        return OcspStatus(False, False, False, last_errors)

    try:
        produced_at, single, basic = best
        errors: list[str] = []
        signature_ok, signature_errors = _verify_ocsp_signature(basic, issuer)
        errors.extend(signature_errors)

        this_update = single["this_update"].native
        next_update = single["next_update"].native
        status = single["cert_status"].name
    except Exception as exc:
        return OcspStatus(False, False, False, (f"Не удалось разобрать OCSP: {exc}",))

    if this_update is not None and this_update - _TIME_TOLERANCE > now:
        errors.append("Ответ OCSP ещё не вступил в силу")
    if next_update is not None and next_update + _TIME_TOLERANCE < now:
        errors.append("Срок действия ответа OCSP истёк")

    revoked = False
    good = status == "good"
    if status == "revoked":
        revoked = True
        good = False
    elif status == "unknown":
        good = False
        errors.append("Статус сертификата в OCSP неизвестен")

    if errors:
        signature_ok = signature_ok and not any(
            "неверна" in error or "не совпадает" in error for error in errors
        )

    applicable = signature_ok and not errors
    return OcspStatus(
        applicable=applicable,
        good=good and applicable,
        revoked=revoked and signature_ok,
        errors=tuple(errors),
        this_update=this_update,
        next_update=next_update,
        produced_at=produced_at,
    )
