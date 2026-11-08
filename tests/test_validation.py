"""Проверка цепочки сертификатов и CRL."""

from __future__ import annotations

import datetime

from django_pdf_sign.crypto.policy import VerificationPolicy
from django_pdf_sign.crypto.validation import validate_chain
from tests.helpers import make_gost_certificate, make_gost_crl

NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


def _ca() -> tuple[bytes, bytes]:
    info, key = make_gost_certificate(common_name="Test CA", is_ca=True)
    return info.der, key


def _leaf(ca_der: bytes, ca_key: bytes, **kwargs: object):
    return make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_der,
        issuer_private_key=ca_key,
        **kwargs,
    )


def test_chain_trusted() -> None:
    ca_der, ca_key = _ca()
    leaf_info, _ = _leaf(ca_der, ca_key)
    result = validate_chain(
        leaf_info.der,
        VerificationPolicy(check_chain=True, trust_roots=(ca_der,), moment=NOW),
    )
    assert result.checked
    assert result.valid
    assert result.trusted
    assert result.validation_path[0] == "Common Name: Test CA, Country: RU"


def test_chain_untrusted_root() -> None:
    ca_der, ca_key = _ca()
    other_der, _ = _ca()
    leaf_info, _ = _leaf(ca_der, ca_key)
    result = validate_chain(
        leaf_info.der,
        VerificationPolicy(check_chain=True, trust_roots=(other_der,), moment=NOW),
    )
    assert result.checked
    assert not result.valid
    assert not result.trusted
    assert result.errors


def test_chain_expired_certificate() -> None:
    ca_der, ca_key = _ca()
    leaf_info, _ = _leaf(
        ca_der,
        ca_key,
        not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
        not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC),
    )
    result = validate_chain(
        leaf_info.der,
        VerificationPolicy(check_chain=True, trust_roots=(ca_der,), moment=NOW),
    )
    assert not result.valid
    assert result.errors


def test_chain_revoked_certificate() -> None:
    ca_der, ca_key = _ca()
    leaf_info, _ = _leaf(ca_der, ca_key)
    crl_der = make_gost_crl(
        issuer_cert_der=ca_der,
        issuer_private_key=ca_key,
        revoked_serials=(int(leaf_info.serial_number, 16),),
    )
    result = validate_chain(
        leaf_info.der,
        VerificationPolicy(
            check_chain=True,
            trust_roots=(ca_der,),
            crls=(crl_der,),
            revocation_mode="require",
            moment=NOW,
        ),
    )
    assert result.checked
    assert not result.valid
    assert result.revoked


def test_chain_good_crl() -> None:
    ca_der, ca_key = _ca()
    leaf_info, _ = _leaf(ca_der, ca_key)
    crl_der = make_gost_crl(issuer_cert_der=ca_der, issuer_private_key=ca_key)
    result = validate_chain(
        leaf_info.der,
        VerificationPolicy(
            check_chain=True,
            trust_roots=(ca_der,),
            crls=(crl_der,),
            revocation_mode="require",
            moment=NOW,
        ),
    )
    assert result.valid


def test_chain_disabled_by_default() -> None:
    ca_der, ca_key = _ca()
    leaf_info, _ = _leaf(ca_der, ca_key)
    result = validate_chain(leaf_info.der, VerificationPolicy())
    assert not result.checked
