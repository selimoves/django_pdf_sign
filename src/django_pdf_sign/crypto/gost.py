"""Verification of GOST 34.10-2012 signatures."""

from __future__ import annotations

from gostcrypto import gostsignature
from gostcrypto.gostsignature import (
    CURVES_R_1323565_1_024_2019 as CURVES,
)
from gostcrypto.gostsignature import (
    MODE_256,
    MODE_512,
)

from django_pdf_sign.crypto.oids import GOST_CURVE_OIDS
from django_pdf_sign.exceptions import VerificationError

_MODES = {256: MODE_256, 512: MODE_512}


def verify_gost(
    *,
    public_key: bytes,
    curve_oid: str,
    digest: bytes,
    signature: bytes,
    key_size: int,
) -> bool:
    """Verify a GOST 34.10-2012 signature over ``digest``."""
    curve_name = GOST_CURVE_OIDS.get(curve_oid)
    if curve_name is None:
        raise VerificationError(f"Unsupported GOST curve: {curve_oid}")
    mode = _MODES.get(key_size)
    if mode is None:
        raise VerificationError(f"Unsupported GOST key size: {key_size}")

    point_size = key_size // 4
    if len(public_key) != point_size:
        raise VerificationError("Malformed GOST public key")
    if len(signature) != point_size:
        raise VerificationError("Malformed GOST signature")

    try:
        result = gostsignature.new(mode, CURVES[curve_name]).verify(
            bytearray(public_key),
            bytearray(digest),
            bytearray(signature),
        )
    except Exception:
        return False
    return bool(result)
