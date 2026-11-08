"""Идентификаторы объектов для подписей ГОСТ и PAdES."""

from __future__ import annotations

GOST_KEY_OIDS: dict[str, int] = {
    "1.2.643.7.1.1.1.1": 256,
    "1.2.643.7.1.1.1.2": 512,
}

GOST_SIGNATURE_OIDS: dict[str, int] = {
    "1.2.643.7.1.1.3.2": 256,
    "1.2.643.7.1.1.3.3": 512,
}

GOST_DIGEST_OIDS: dict[str, str] = {
    "1.2.643.7.1.1.2.2": "streebog256",
    "1.2.643.7.1.1.2.3": "streebog512",
}

SHA2_DIGEST_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

GOST_CURVE_OIDS: dict[str, str] = {
    "1.2.643.7.1.2.1.1.1": "id-tc26-gost-3410-2012-256-paramSetA",
    "1.2.643.7.1.2.1.1.2": "id-tc26-gost-3410-2012-256-paramSetB",
    "1.2.643.7.1.2.1.1.3": "id-tc26-gost-3410-2012-256-paramSetC",
    "1.2.643.7.1.2.1.1.4": "id-tc26-gost-3410-2012-256-paramSetD",
    "1.2.643.7.1.2.1.2.1": "id-tc26-gost-3410-12-512-paramSetA",
    "1.2.643.7.1.2.1.2.2": "id-tc26-gost-3410-12-512-paramSetB",
    "1.2.643.7.1.2.1.2.3": "id-tc26-gost-3410-2012-512-paramSetC",
    # Устаревшие OID КриптоПро (RFC 4357). Параметры совпадают с наборами TC26:
    # CryptoPro-A и XchA — paramSetB, CryptoPro-B и XchB — paramSetC,
    # CryptoPro-C — paramSetD.
    "1.2.643.2.2.35.1": "id-tc26-gost-3410-2012-256-paramSetB",
    "1.2.643.2.2.35.2": "id-tc26-gost-3410-2012-256-paramSetC",
    "1.2.643.2.2.35.3": "id-tc26-gost-3410-2012-256-paramSetD",
    "1.2.643.2.2.36.0": "id-tc26-gost-3410-2012-256-paramSetB",
    "1.2.643.2.2.36.1": "id-tc26-gost-3410-2012-256-paramSetC",
}

RSA_KEY_OID = "1.2.840.113549.1.1.1"
EC_KEY_OID = "1.2.840.10045.2.1"

SIGNATURE_DIGEST_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
