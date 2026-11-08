"""Проверка подписей ГОСТ Р 34.10-2012.

КриптоПро хранит открытый ключ как `X ‖ Y` в little-endian (RFC 4491),
подпись — как `s ‖ r`, а хэш интерпретирует как число в little-endian.
`gostcrypto` работает в big-endian и порядке `r ‖ s`. Поэтому перед
проверкой ключ, подпись и дайджест нормализуются, а для совместимости
проверяются обе конвенции кодирования.
"""

from __future__ import annotations

from typing import Any

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


def _curve(curve_oid: str) -> dict[str, Any]:
    name = GOST_CURVE_OIDS.get(curve_oid)
    if name is None:
        raise VerificationError(f"Неподдерживаемая кривая ГОСТ: {curve_oid}")
    curve: dict[str, Any] = CURVES[name]
    return curve


def _on_curve(x: int, y: int, curve: dict[str, Any]) -> bool:
    p = curve["p"]
    a = curve["a"]
    b = curve["b"]
    return bool((y * y - (x * x * x + a * x + b)) % p == 0)


def normalize_public_key(public_key: bytes, *, curve_oid: str, key_size: int) -> bytes:
    """Привести точку `X ‖ Y` к big-endian виду, ожидаемому `gostcrypto`.

    Кодировка определяется проверкой принадлежности точки кривой: сначала
    проверяется big-endian, затем little-endian.
    """
    size = key_size // 8
    if len(public_key) != 2 * size:
        raise VerificationError("Некорректная длина открытого ключа ГОСТ")

    x_bytes = public_key[:size]
    y_bytes = public_key[size:]
    curve = _curve(curve_oid)

    if _on_curve(int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"), curve):
        return x_bytes + y_bytes
    if _on_curve(
        int.from_bytes(x_bytes, "little"), int.from_bytes(y_bytes, "little"), curve
    ):
        return x_bytes[::-1] + y_bytes[::-1]
    raise VerificationError("Открытый ключ ГОСТ не лежит на заявленной кривой")


def verify_gost(
    *,
    public_key: bytes,
    curve_oid: str,
    digest: bytes,
    signature: bytes,
    key_size: int,
) -> bool:
    """Проверить подпись ГОСТ Р 34.10-2012 над `digest`."""
    mode = _MODES.get(key_size)
    if mode is None:
        raise VerificationError(f"Неподдерживаемый размер ключа ГОСТ: {key_size}")

    size = key_size // 8
    if len(signature) != 2 * size:
        raise VerificationError("Некорректная длина подписи ГОСТ")

    normalized_key = normalize_public_key(
        public_key, curve_oid=curve_oid, key_size=key_size
    )
    curve = _curve(curve_oid)
    verifier = gostsignature.new(mode, curve)

    # Порядок `r ‖ s` (gostcrypto) и `s ‖ r` (RFC 4491), а также big-endian
    # и little-endian дайджест — обе комбинации допустимы.
    digest_variants = (digest, digest[::-1])
    signature_variants = (signature, signature[size:] + signature[:size])

    for digest_variant in digest_variants:
        for signature_variant in signature_variants:
            try:
                if verifier.verify(
                    bytearray(normalized_key),
                    bytearray(digest_variant),
                    bytearray(signature_variant),
                ):
                    return True
            except Exception:
                continue
    return False
