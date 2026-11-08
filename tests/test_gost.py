"""Tests for GOST 34.10-2012 signature verification."""

from __future__ import annotations

import os

import pytest
from gostcrypto import gostsignature
from gostcrypto.gostsignature import CURVES_R_1323565_1_024_2019 as CURVES
from gostcrypto.gostsignature import MODE_256, MODE_512

from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.exceptions import VerificationError

CURVE_256_OID = "1.2.643.7.1.2.1.1.1"
CURVE_512_OID = "1.2.643.7.1.2.1.2.1"


def _keypair(key_size: int = 256) -> tuple[bytes, bytes]:
    curve = CURVES[
        "id-tc26-gost-3410-2012-256-paramSetA"
        if key_size == 256
        else "id-tc26-gost-3410-12-512-paramSetA"
    ]
    mode = MODE_256 if key_size == 256 else MODE_512
    private = os.urandom(key_size // 8)
    public = bytes(
        gostsignature.new(mode, curve).public_key_generate(bytearray(private))
    )
    return private, public


def test_valid_signature() -> None:
    private, public = _keypair()
    digest = digest_for("streebog256", b"payload")
    curve = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
    signature = bytes(
        gostsignature.new(MODE_256, curve).sign(bytearray(private), digest)
    )
    assert verify_gost(
        public_key=public,
        curve_oid=CURVE_256_OID,
        digest=digest,
        signature=signature,
        key_size=256,
    )


def test_tampered_digest_rejected() -> None:
    private, public = _keypair()
    digest = digest_for("streebog256", b"payload")
    curve = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
    signature = bytes(
        gostsignature.new(MODE_256, curve).sign(bytearray(private), digest)
    )
    assert not verify_gost(
        public_key=public,
        curve_oid=CURVE_256_OID,
        digest=digest_for("streebog256", b"other"),
        signature=signature,
        key_size=256,
    )


def test_valid_512_signature() -> None:
    private, public = _keypair(512)
    digest = digest_for("streebog512", b"payload")
    curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
    signature = bytes(
        gostsignature.new(MODE_512, curve).sign(bytearray(private), digest)
    )
    assert verify_gost(
        public_key=public,
        curve_oid=CURVE_512_OID,
        digest=digest,
        signature=signature,
        key_size=512,
    )


def test_unknown_curve_raises() -> None:
    with pytest.raises(VerificationError):
        verify_gost(
            public_key=b"\x00" * 64,
            curve_oid="1.2.3.4",
            digest=b"\x00" * 32,
            signature=b"\x00" * 64,
            key_size=256,
        )


def test_malformed_key_raises() -> None:
    with pytest.raises(VerificationError):
        verify_gost(
            public_key=b"\x00" * 10,
            curve_oid=CURVE_256_OID,
            digest=b"\x00" * 32,
            signature=b"\x00" * 64,
            key_size=256,
        )
