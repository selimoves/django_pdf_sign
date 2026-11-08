"""Проверка ответов OCSP, включая ГОСТ-идентификаторы."""

from __future__ import annotations

import datetime

import pytest

from django_pdf_sign.crypto.ocsp import evaluate_ocsps
from django_pdf_sign.crypto.policy import VerificationPolicy
from django_pdf_sign.crypto.validation import validate_chain
from tests.helpers import make_gost_certificate, make_gost_ocsp

NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


def _chain():
    ca_info, ca_key = make_gost_certificate(common_name="Test CA", is_ca=True)
    leaf_info, _ = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    return ca_info, ca_key, leaf_info


def test_good_ocsp() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf.der, issuer_der=ca_info.der, moment=NOW
    )
    assert status.applicable
    assert status.good
    assert not status.revoked


def test_good_ocsp_sha256() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        hash_name="sha256",
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf.der, issuer_der=ca_info.der, moment=NOW
    )
    assert status.applicable
    assert status.good


def test_revoked_ocsp() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        status="revoked",
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf.der, issuer_der=ca_info.der, moment=NOW
    )
    assert status.applicable
    assert status.revoked
    assert not status.good


def test_unknown_ocsp() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        status="unknown",
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf.der, issuer_der=ca_info.der, moment=NOW
    )
    assert not status.applicable
    assert not status.good


def test_ocsp_for_other_certificate_not_applicable() -> None:
    ca_info, ca_key, _ = _chain()
    other_info, _ = make_gost_certificate(
        common_name="Other Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=other_info.der,
    )
    leaf_info, _ = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf_info.der, issuer_der=ca_info.der, moment=NOW
    )
    assert not status.applicable


def test_expired_ocsp() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        this_update=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
        next_update=datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC),
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf.der, issuer_der=ca_info.der, moment=NOW
    )
    assert not status.applicable
    assert status.errors


def test_tampered_ocsp_signature() -> None:
    ca_info, ca_key, leaf = _chain()
    response = bytearray(
        make_gost_ocsp(
            issuer_cert_der=ca_info.der,
            issuer_private_key=ca_key,
            target_cert_der=leaf.der,
        )
    )
    response[-5] ^= 0xFF
    status = evaluate_ocsps(
        (bytes(response),),
        target_der=leaf.der,
        issuer_der=ca_info.der,
        moment=NOW,
    )
    assert not status.applicable


def test_chain_with_ocsp_require() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
    )
    result = validate_chain(
        leaf.der,
        VerificationPolicy(
            check_chain=True,
            trust_roots=(ca_info.der,),
            ocsps=(response,),
            revocation_mode="require",
            moment=NOW,
        ),
    )
    assert result.valid
    assert not result.revoked


def test_chain_with_ocsp_revoked() -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        status="revoked",
    )
    result = validate_chain(
        leaf.der,
        VerificationPolicy(
            check_chain=True,
            trust_roots=(ca_info.der,),
            ocsps=(response,),
            revocation_mode="require",
            moment=NOW,
        ),
    )
    assert result.revoked
    assert not result.valid


def test_chain_require_without_revinfo() -> None:
    ca_info, _ca_key, leaf = _chain()
    result = validate_chain(
        leaf.der,
        VerificationPolicy(
            check_chain=True,
            trust_roots=(ca_info.der,),
            revocation_mode="require",
            moment=NOW,
        ),
    )
    assert not result.valid


@pytest.mark.parametrize("hash_name", ["streebog512", "sha1"])
def test_ocsp_hash_algorithms(hash_name: str) -> None:
    ca_info, ca_key, leaf = _chain()
    response = make_gost_ocsp(
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        hash_name=hash_name,
    )
    status = evaluate_ocsps(
        (response,), target_der=leaf.der, issuer_der=ca_info.der, moment=NOW
    )
    assert status.applicable
    assert status.good
