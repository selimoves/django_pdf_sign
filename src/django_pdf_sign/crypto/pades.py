"""Проверка подписей RSA и ECDSA, используемых в PAdES."""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from django_pdf_sign.exceptions import VerificationError

_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def verify_pades(
    *,
    certificate_der: bytes,
    signed_attrs_der: bytes,
    signature: bytes,
    digest_algorithm: str,
) -> bool:
    """Проверить подпись RSA (PKCS#1 v1.5) или ECDSA над атрибутами."""
    hash_class = _HASHES.get(digest_algorithm)
    if hash_class is None:
        raise VerificationError(
            f"Неподдерживаемый алгоритм дайджеста: {digest_algorithm}"
        )

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except Exception as exc:
        raise VerificationError("Не удалось разобрать сертификат подписанта") from exc

    public_key = certificate.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature, signed_attrs_der, padding.PKCS1v15(), hash_class()
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_attrs_der, ec.ECDSA(hash_class()))
        else:
            raise VerificationError(
                f"Неподдерживаемый тип открытого ключа: {type(public_key).__name__}"
            )
    except InvalidSignature:
        return False
    return True
