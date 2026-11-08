"""Проверка меток времени CAdES-T."""

from __future__ import annotations

import datetime

from asn1crypto import cms

from django_pdf_sign.crypto.timestamp import (
    verify_document_timestamp,
    verify_timestamp_token,
)
from django_pdf_sign.services import VerificationPolicy, verify_cms_over_bytes
from tests.helpers import (
    add_cms_timestamp,
    make_gost_certificate,
    make_gost_cms,
    make_gost_timestamp,
)

GEN_TIME = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.UTC)


def _signed_with_timestamp():
    signer_info, signer_key = make_gost_certificate(common_name="Signer")
    tsa_info, tsa_key = make_gost_certificate(common_name="TSA")
    cms_bytes, _, data = make_gost_cms(signer=(signer_info, signer_key))
    parsed = cms.ContentInfo.load(cms_bytes)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    token = make_gost_timestamp(
        signature_value=signature_value,
        tsa_cert_der=tsa_info.der,
        tsa_private_key=tsa_key,
        gen_time=GEN_TIME,
    )
    return add_cms_timestamp(cms_bytes, token), data


def test_timestamp_valid() -> None:
    cms_bytes, data = _signed_with_timestamp()
    result = verify_cms_over_bytes(
        cms=cms_bytes, data=data, policy=VerificationPolicy(check_timestamps=True)
    )
    assert result.valid
    assert result.timestamp_ok is True
    assert result.signing_time == GEN_TIME


def test_timestamp_token_imprint() -> None:
    signer_info, signer_key = make_gost_certificate(common_name="Signer")
    tsa_info, tsa_key = make_gost_certificate(common_name="TSA")
    cms_bytes, _, _data = make_gost_cms(signer=(signer_info, signer_key))
    parsed = cms.ContentInfo.load(cms_bytes)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    token = make_gost_timestamp(
        signature_value=b"wrong signature",
        tsa_cert_der=tsa_info.der,
        tsa_private_key=tsa_key,
    )
    result = verify_timestamp_token(token, signature_value=signature_value)
    assert not result.valid
    assert not result.imprint_ok


def test_timestamp_required_but_missing() -> None:
    signer_info, signer_key = make_gost_certificate(common_name="Signer")
    cms_bytes, _, data = make_gost_cms(signer=(signer_info, signer_key))
    result = verify_cms_over_bytes(
        cms=cms_bytes,
        data=data,
        policy=VerificationPolicy(check_timestamps=True, require_timestamp=True),
    )
    assert not result.valid
    assert result.timestamp_ok is False


def test_timestamp_present_without_policy() -> None:
    cms_bytes, data = _signed_with_timestamp()
    result = verify_cms_over_bytes(cms=cms_bytes, data=data)
    assert result.valid
    assert result.timestamp_ok is True


def test_document_timestamp() -> None:
    tsa_info, tsa_key = make_gost_certificate(common_name="TSA")
    document_bytes = b"pdf bytes"
    token = make_gost_timestamp(
        signature_value=document_bytes,
        tsa_cert_der=tsa_info.der,
        tsa_private_key=tsa_key,
        gen_time=GEN_TIME,
    )
    result = verify_document_timestamp(token, document_bytes)
    assert result.valid
    assert result.imprint_ok
    assert result.gen_time == GEN_TIME


def test_document_timestamp_wrong_data() -> None:
    tsa_info, tsa_key = make_gost_certificate(common_name="TSA")
    token = make_gost_timestamp(
        signature_value=b"original",
        tsa_cert_der=tsa_info.der,
        tsa_private_key=tsa_key,
    )
    result = verify_document_timestamp(token, b"changed")
    assert not result.valid
    assert not result.imprint_ok
