"""Проверка реальной подписи КриптоПро из закоммиченной фикстуры.

Фикстура создана ``tools/make_cryptopro_fixture.py`` на настоящем
КриптоПро CSP. Здесь она проверяется без Docker и без CSP, поэтому тест
работает в CI.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.services import (
    VerificationPolicy,
    verify_cms_over_bytes,
    verify_signed_pdf,
)
from tests.helpers import make_gost_certificate

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CRYPTOPRO = FIXTURES / "cryptopro"
ROOT_CER = FIXTURES / "crypto" / "pycades-root.cer"
ROOT_CRL = FIXTURES / "crypto" / "pycades-root.crl"
MOMENT = datetime.datetime(2026, 11, 8, tzinfo=datetime.UTC)


def _read(name: str) -> bytes:
    return (CRYPTOPRO / name).read_bytes()


def test_fixture_certificate_parses() -> None:
    info = parse_certificate(_read("pycades-test.cer"))
    assert info.is_gost is True
    assert info.key_size == 256
    assert info.common_name == "pycades-test"
    assert info.curve_oid == "1.2.643.2.2.36.0"


def test_real_cryptopro_cms_verifies() -> None:
    result = verify_cms_over_bytes(
        cms=_read("pycades-test.cms"),
        data=_read("pycades-test.bytes"),
        expected_certificate_der=_read("pycades-test.cer"),
    )
    assert result.valid
    assert result.message_digest_ok
    assert result.signature_ok
    assert result.certificate_matches


def test_real_cryptopro_cms_rejects_tampered_bytes() -> None:
    data = bytearray(_read("pycades-test.bytes"))
    data[0] ^= 0xFF
    result = verify_cms_over_bytes(cms=_read("pycades-test.cms"), data=bytes(data))
    assert not result.valid
    assert not result.message_digest_ok


def test_real_cryptopro_signed_pdf_verifies() -> None:
    result = verify_signed_pdf(_read("pycades-test-signed.pdf"))
    assert result.valid
    assert result.signature_ok


def test_real_cryptopro_chain_and_crl() -> None:
    policy = VerificationPolicy(
        check_chain=True,
        trust_roots=(ROOT_CER.read_bytes(),),
        crls=(ROOT_CRL.read_bytes(),),
        revocation_mode="require",
        moment=MOMENT,
    )
    result = verify_signed_pdf(_read("pycades-test-signed.pdf"), policy=policy)
    assert result.valid
    assert result.chain_ok is True
    assert result.trusted is True
    assert result.revoked is False
    assert result.validation_path == (
        "Common Name: pycades-root",
        "Common Name: pycades-test",
    )


def test_real_cryptopro_chain_rejects_other_root() -> None:
    unrelated_root, _ = make_gost_certificate(common_name="Other CA", is_ca=True)
    policy = VerificationPolicy(
        check_chain=True,
        trust_roots=(unrelated_root.der,),
        moment=MOMENT,
    )
    result = verify_signed_pdf(_read("pycades-test-signed.pdf"), policy=policy)
    assert not result.valid
    assert result.chain_ok is False
