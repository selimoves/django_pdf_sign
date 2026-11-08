"""Проверка цепочки сертификатов и отзыва для ГОСТ и PAdES."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from asn1crypto import x509
from gostcrypto import gosthash
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import (  # type: ignore[attr-defined]
    InvalidSignature,
    RevokedError,
)
from pyhanko_certvalidator.sig_validate import (  # type: ignore[attr-defined]
    DEFAULT_VALIDATION_CONTEXT,
    DefaultSignatureValidator,
    PublicKeyInfo,
    SignatureValidationContext,
    SignatureValidator,
)

from django_pdf_sign.crypto.certs import (
    GostPublicKeyInfo,
    curve_oid_from_parameters,
    gost_public_key_from_spki,
)
from django_pdf_sign.crypto.fetchers import AllowlistFetcherBackend
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.ocsp import evaluate_ocsps
from django_pdf_sign.crypto.oids import GOST_KEY_OIDS
from django_pdf_sign.crypto.policy import VerificationPolicy, resolve_moment
from django_pdf_sign.exceptions import VerificationError


@dataclass(frozen=True)
class ChainResult:
    """Результат проверки цепочки и отзыва."""

    checked: bool
    valid: bool
    trusted: bool
    revoked: bool
    errors: tuple[str, ...]
    validation_path: tuple[str, ...]
    validation_time: datetime | None
    certificates: tuple[bytes, ...] = ()


class GostSignatureValidator(SignatureValidator):
    """Проверка подписи сертификата: ГОСТ через `gostcrypto`, остальное — pyca."""

    def validate_signature(
        self,
        signature: bytes,
        signed_data: bytes,
        public_key_info: PublicKeyInfo,
        signature_algorithm: Any,
        context: SignatureValidationContext = DEFAULT_VALIDATION_CONTEXT,
    ) -> None:
        key_oid = public_key_info["algorithm"]["algorithm"].dotted
        if key_oid not in GOST_KEY_OIDS:
            DefaultSignatureValidator().validate_signature(
                signature,
                signed_data,
                public_key_info,
                signature_algorithm,
                context=context,
            )
            return

        key_size = GOST_KEY_OIDS[key_oid]
        curve_oid = curve_oid_from_parameters(
            public_key_info["algorithm"]["parameters"]
        )
        if curve_oid is None:
            raise InvalidSignature("В сертификате нет параметров кривой ГОСТ")

        spki = GostPublicKeyInfo.load(public_key_info.dump())
        public_key = gost_public_key_from_spki(spki, key_size)
        digest_name = "streebog256" if key_size == 256 else "streebog512"
        digest = bytes(gosthash.new(digest_name, data=signed_data).digest())

        if not verify_gost(
            public_key=public_key,
            curve_oid=curve_oid,
            digest=digest,
            signature=signature,
            key_size=key_size,
        ):
            raise InvalidSignature("Неверная подпись ГОСТ")


def _run(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def validate_chain(certificate_der: bytes, policy: VerificationPolicy) -> ChainResult:
    """Проверить цепочку сертификата и статус отзыва по политике."""
    if not policy.check_chain:
        return ChainResult(
            checked=False,
            valid=True,
            trusted=False,
            revoked=False,
            errors=(),
            validation_path=(),
            validation_time=None,
        )

    if policy.allow_fetching and not policy.fetch_allowed_hosts:
        raise VerificationError(
            "ALLOW_FETCHING=True требует непустой FETCH_ALLOWED_HOSTS"
        )

    certificate = x509.Certificate.load(certificate_der)
    intermediates = [x509.Certificate.load(der) for der in policy.intermediate_certs]
    trust_roots = [x509.Certificate.load(der) for der in policy.trust_roots]
    moment = resolve_moment(policy)

    ocsp_only = bool(policy.ocsps) and not policy.crls
    chain_mode = policy.revocation_mode
    if ocsp_only and chain_mode == "require":
        chain_mode = "soft-fail"

    validation_context = ValidationContext(
        trust_roots=trust_roots,
        other_certs=intermediates,
        allow_fetching=policy.allow_fetching,
        fetcher_backend=(
            AllowlistFetcherBackend(policy.fetch_allowed_hosts)
            if policy.allow_fetching
            else None
        ),
        crls=list(policy.crls),
        revocation_mode=chain_mode,
        moment=moment,
        signature_validator=GostSignatureValidator(),
    )

    async def validate() -> Any:
        validator = CertificateValidator(
            certificate,
            intermediate_certs=intermediates,
            validation_context=validation_context,
        )
        return await validator.async_validate_usage(set())  # type: ignore[no-untyped-call]

    try:
        path = _run(validate())
    except RevokedError as exc:
        return ChainResult(
            checked=True,
            valid=False,
            trusted=True,
            revoked=True,
            errors=(str(exc),),
            validation_path=(),
            validation_time=moment,
        )
    except Exception as exc:
        return ChainResult(
            checked=True,
            valid=False,
            trusted=False,
            revoked=False,
            errors=(f"{type(exc).__name__}: {exc}",),
            validation_path=(),
            validation_time=moment,
        )

    certificates = tuple(cert.dump() for cert in path)
    errors: list[str] = []
    revoked = False

    if policy.ocsps:
        issuer_der = certificates[-2] if len(certificates) > 1 else certificates[0]
        ocsp_status = evaluate_ocsps(
            policy.ocsps,
            target_der=certificate_der,
            issuer_der=issuer_der,
            moment=moment,
        )
        revoked = ocsp_status.revoked
        errors.extend(ocsp_status.errors)
        if (
            ocsp_only
            and policy.revocation_mode == "require"
            and (not ocsp_status.applicable or not ocsp_status.good)
        ):
            errors.append("Нет пригодных данных отзыва (OCSP)")
            revoked = revoked or ocsp_status.revoked

    valid = not revoked and not errors
    return ChainResult(
        checked=True,
        valid=valid,
        trusted=True,
        revoked=revoked,
        errors=tuple(errors),
        validation_path=tuple(cert.subject.human_friendly for cert in path),
        validation_time=moment,
        certificates=certificates,
    )
