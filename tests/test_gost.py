"""Проверка подписей ГОСТ Р 34.10-2012."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from asn1crypto import crl, x509
from gostcrypto import gosthash, gostsignature
from gostcrypto.gostsignature import CURVES_R_1323565_1_024_2019 as CURVES
from gostcrypto.gostsignature import MODE_256, MODE_512

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import normalize_public_key, verify_gost
from django_pdf_sign.exceptions import VerificationError
from tests.helpers import gost_sign

CURVE_256_OID = "1.2.643.7.1.2.1.1.1"
CURVE_512_OID = "1.2.643.7.1.2.1.2.1"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "crypto"


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


def test_native_signature() -> None:
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


def test_cryptopro_convention_signature() -> None:
    private, public = _keypair()
    # КриптоПро хранит ключ в little-endian, подпись — как s ‖ r.
    public_le = public[:32][::-1] + public[32:][::-1]
    digest = digest_for("streebog256", b"payload")
    signature = gost_sign(private, b"payload")
    assert verify_gost(
        public_key=public_le,
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


def test_legacy_curve_oid_is_accepted() -> None:
    private = os.urandom(32)
    curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
    public = bytes(
        gostsignature.new(MODE_256, curve).public_key_generate(bytearray(private))
    )
    public_le = public[:32][::-1] + public[32:][::-1]
    digest = digest_for("streebog256", b"payload")
    signature = gost_sign(private, b"payload", curve_oid="1.2.643.2.2.36.0")
    assert verify_gost(
        public_key=public_le,
        curve_oid="1.2.643.2.2.36.0",
        digest=digest,
        signature=signature,
        key_size=256,
    )


def test_normalize_detects_endianness() -> None:
    _, public = _keypair()
    assert normalize_public_key(public, curve_oid=CURVE_256_OID, key_size=256) == public
    public_le = public[:32][::-1] + public[32:][::-1]
    assert (
        normalize_public_key(public_le, curve_oid=CURVE_256_OID, key_size=256) == public
    )


def test_point_off_curve_raises() -> None:
    with pytest.raises(VerificationError):
        normalize_public_key(b"\x01" * 64, curve_oid=CURVE_256_OID, key_size=256)


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


def test_real_cryptopro_certificate_signature() -> None:
    root_der = (FIXTURES / "pycades-root.cer").read_bytes()
    info = parse_certificate(root_der)
    certificate = x509.Certificate.load(root_der)
    assert verify_gost(
        public_key=info.public_key,
        curve_oid=info.curve_oid or "",
        digest=gosthash.new(
            "streebog256", data=certificate["tbs_certificate"].dump()
        ).digest(),
        signature=certificate["signature_value"].native,
        key_size=info.key_size,
    )


def test_real_cryptopro_crl_signature() -> None:
    info = parse_certificate((FIXTURES / "pycades-root.cer").read_bytes())
    certificate_list = crl.CertificateList.load(
        (FIXTURES / "pycades-root.crl").read_bytes()
    )
    assert verify_gost(
        public_key=info.public_key,
        curve_oid=info.curve_oid or "",
        digest=gosthash.new(
            "streebog256", data=certificate_list["tbs_cert_list"].dump()
        ).digest(),
        signature=certificate_list["signature"].native,
        key_size=info.key_size,
    )
