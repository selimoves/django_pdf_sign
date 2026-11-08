"""Verification of RSA and ECDSA signatures used by PAdES."""

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
    """Verify an RSA (PKCS#1 v1.5) or ECDSA signature over signed attributes."""
    hash_class = _HASHES.get(digest_algorithm)
    if hash_class is None:
        raise VerificationError(f"Unsupported digest algorithm: {digest_algorithm}")

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except Exception as exc:
        raise VerificationError("Cannot parse signer certificate") from exc

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
                f"Unsupported public key type: {type(public_key).__name__}"
            )
    except InvalidSignature:
        return False
    return True
