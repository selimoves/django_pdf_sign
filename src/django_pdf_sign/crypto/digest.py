"""Дайджесты ГОСТ и SHA-2."""

from __future__ import annotations

import hashlib

from gostcrypto import gosthash

from django_pdf_sign.constants import (
    DIGEST_SHA256,
    DIGEST_STREEBOG_256,
    DIGEST_STREEBOG_512,
)
from django_pdf_sign.crypto.oids import EC_KEY_OID, GOST_KEY_OIDS, RSA_KEY_OID

_HASHLIB_ALGORITHMS = frozenset({DIGEST_SHA256, "sha384", "sha512"})
_STREEBOG_ALGORITHMS = frozenset({DIGEST_STREEBOG_256, DIGEST_STREEBOG_512})


def digest_for(algorithm: str, data: bytes) -> bytes:
    """Вернуть дайджест ``data`` указанным алгоритмом."""
    if algorithm in _STREEBOG_ALGORITHMS:
        return bytes(gosthash.new(algorithm, data=data).digest())
    if algorithm in _HASHLIB_ALGORITHMS:
        return hashlib.new(algorithm, data).digest()
    raise ValueError(f"Неподдерживаемый алгоритм дайджеста: {algorithm}")


def algorithm_for_key_oid(key_oid: str) -> str:
    """Вернуть алгоритм дайджеста для OID алгоритма открытого ключа."""
    if key_oid in GOST_KEY_OIDS:
        return (
            DIGEST_STREEBOG_256
            if GOST_KEY_OIDS[key_oid] == 256
            else DIGEST_STREEBOG_512
        )
    if key_oid in {RSA_KEY_OID, EC_KEY_OID}:
        return DIGEST_SHA256
    raise ValueError(f"Неподдерживаемый алгоритм открытого ключа: {key_oid}")
