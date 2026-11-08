import asyncio
import datetime
import pathlib

import pytest
import requests
from asn1crypto import cms as asn1cms
from django.core.files.base import ContentFile
from django.test import override_settings

from django_pdf_sign.checks import check_settings
from django_pdf_sign.constants import RevocationStatus
from django_pdf_sign.crypto import fetchers as fetchers_module
from django_pdf_sign.crypto.timestamp import verify_timestamp_token
from django_pdf_sign.crypto.validation import validate_chain
from django_pdf_sign.exceptions import SigningError, VerificationError
from django_pdf_sign.services import (
    VerificationPolicy,
    complete_signing,
    prepare_signing,
    verify_signed_pdf,
)
from tests.helpers import (
    add_cms_timestamp,
    make_gost_certificate,
    make_gost_cms,
    make_gost_ocsp,
    make_gost_timestamp,
    make_rsa_certificate,
    make_rsa_cms,
    make_rsa_timestamp,
    minimal_pdf,
)
from tests.models import Document

NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


def _document() -> Document:
    return Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))


def _sign(pdf: bytes) -> bytes:
    info, key = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(pdf, name="doc.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    return complete_signing(session_id=prepared.session.pk, cms=cms_bytes).signed_pdf


def _gost_timestamp_token(gen_time: datetime.datetime) -> tuple[bytes, bytes, bytes]:
    signer, signer_key = make_gost_certificate(common_name="Signer")
    tsa, tsa_key = make_gost_certificate(common_name="TSA")
    cms_bytes, _, _ = make_gost_cms(signer=(signer, signer_key))
    parsed = asn1cms.ContentInfo.load(cms_bytes)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    token = make_gost_timestamp(
        signature_value=signature_value,
        tsa_cert_der=tsa.der,
        tsa_private_key=tsa_key,
        gen_time=gen_time,
    )
    return cms_bytes, add_cms_timestamp(cms_bytes, token), token


def test_rsa_timestamp_token_is_verified() -> None:
    tsa, tsa_key = make_rsa_certificate(common_name="TSA")
    token = make_rsa_timestamp(
        signature_value=b"signature",
        tsa_cert_der=tsa.der,
        tsa_private_key=tsa_key,
    )
    result = verify_timestamp_token(token, signature_value=b"signature")
    assert result.valid
    assert result.imprint_ok


def test_timestamp_without_signer_infos_returns_invalid() -> None:
    token, _, _ = _gost_timestamp_token(NOW)
    info = asn1cms.ContentInfo.load(token)
    info["content"]["signer_infos"] = []
    result = verify_timestamp_token(info.dump(), signature_value=b"any")
    assert result.present
    assert not result.valid


def test_timestamp_with_empty_attribute_values_returns_invalid() -> None:
    token, _, _ = _gost_timestamp_token(NOW)
    info = asn1cms.ContentInfo.load(token)
    for attribute in info["content"]["signer_infos"][0]["signed_attrs"]:
        attribute["values"] = []
    result = verify_timestamp_token(info.dump(), signature_value=b"any")
    assert result.present
    assert not result.valid


@pytest.mark.django_db
def test_complete_rejects_crafted_timestamp_as_domain_error() -> None:
    signer, signer_key = make_gost_certificate(common_name="Signer")
    prepared = prepare_signing(document=_document(), certificate_der=signer.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(signer, signer_key)
    )
    token, _, _ = _gost_timestamp_token(NOW)
    token_info = asn1cms.ContentInfo.load(token)
    for attribute in token_info["content"]["signer_infos"][0]["signed_attrs"]:
        attribute["values"] = []
    with pytest.raises(VerificationError):
        complete_signing(
            session_id=prepared.session.pk,
            cms=add_cms_timestamp(cms_bytes, token_info.dump()),
            policy=VerificationPolicy(check_timestamps=True),
        )


@pytest.mark.django_db
def test_untrusted_timestamp_does_not_extend_certificate_validity() -> None:
    signer, signer_key = make_gost_certificate(common_name="Signer 2")
    prepared = prepare_signing(document=_document(), certificate_der=signer.der)
    real_cms, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(signer, signer_key)
    )
    parsed = asn1cms.ContentInfo.load(real_cms)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    tsa, tsa_key = make_gost_certificate(common_name="TSA 2")
    token = make_gost_timestamp(
        signature_value=signature_value,
        tsa_cert_der=tsa.der,
        tsa_private_key=tsa_key,
        gen_time=datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC),
    )
    result = complete_signing(
        session_id=prepared.session.pk,
        cms=add_cms_timestamp(real_cms, token),
    )
    assert result.record.timestamp_status == "valid"
    assert result.session.status == "completed"


@pytest.mark.django_db
def test_verify_signed_pdf_rejects_uncovered_incremental_update() -> None:
    twice_signed = _sign(_sign(minimal_pdf()))
    first = verify_signed_pdf(twice_signed)
    second = verify_signed_pdf(twice_signed, signature_index=1)
    assert not first.valid
    assert "не покрывает" in first.errors[0]
    assert second.valid


@pytest.mark.django_db
def test_complete_uses_verify_settings() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    with (
        override_settings(DJANGO_PDF_SIGN={"VERIFY": {"REQUIRE_TIMESTAMP": True}}),
        pytest.raises(VerificationError),
    ):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)


def test_fetchers_disable_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    class _Response:
        status_code = 302

    def fake_get(**kwargs: object) -> _Response:
        calls.append(kwargs)
        return _Response()

    monkeypatch.setattr(fetchers_module.requests, "get", fake_get)
    fetcher = (
        fetchers_module.AllowlistFetcherBackend(("allowed.example",))
        .get_fetchers()
        .crl_fetcher
    )
    with pytest.raises(requests.RequestException):
        asyncio.run(
            fetcher._get(
                "https://allowed.example/crl",
                acceptable_content_types=("application/pkix-crl",),
            )
        )
    assert calls[0]["allow_redirects"] is False


def test_checks_reject_non_iterable_paths() -> None:
    with override_settings(DJANGO_PDF_SIGN={"VERIFY": {"TRUST_ROOTS": 5}}):
        errors = check_settings(None)
    assert errors
    assert errors[0].id.startswith("django_pdf_sign.")


def test_checks_reject_bad_hosts_and_page() -> None:
    with override_settings(
        DJANGO_PDF_SIGN={
            "DEFAULT_PAGE": "last",
            "VERIFY": {"ALLOW_FETCHING": True, "FETCH_ALLOWED_HOSTS": 5},
        }
    ):
        errors = check_settings(None)
    assert len(errors) >= 2


def _expired_ocsp() -> tuple[bytes, bytes, bytes]:
    ca, ca_key = make_gost_certificate(common_name="Test CA", is_ca=True)
    leaf, _ = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca.der,
        issuer_private_key=ca_key,
    )
    response = make_gost_ocsp(
        issuer_cert_der=ca.der,
        issuer_private_key=ca_key,
        target_cert_der=leaf.der,
        this_update=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        next_update=datetime.datetime(2026, 2, 1, tzinfo=datetime.UTC),
    )
    return ca.der, leaf.der, response


@pytest.mark.parametrize("mode", ["none", "soft-fail"])
def test_soft_revocation_modes_do_not_invalidate(mode: str) -> None:
    ca_der, leaf_der, response = _expired_ocsp()
    policy = VerificationPolicy(
        check_chain=True,
        trust_roots=(ca_der,),
        ocsps=(response,),
        revocation_mode=mode,
        moment=NOW,
    )
    assert validate_chain(leaf_der, policy).valid


def test_require_revocation_mode_invalidates() -> None:
    ca_der, leaf_der, response = _expired_ocsp()
    policy = VerificationPolicy(
        check_chain=True,
        trust_roots=(ca_der,),
        ocsps=(response,),
        revocation_mode="require",
        moment=NOW,
    )
    assert not validate_chain(leaf_der, policy).valid


@pytest.mark.django_db
def test_cms_size_checked_before_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(
        document=_document(), certificate_der=info.der, bytes_reserved=1000
    )
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    def explode(cms: bytes) -> object:
        raise AssertionError("parse_cms must not be called")

    monkeypatch.setattr("django_pdf_sign.services.complete.parse_cms", explode)
    with pytest.raises(SigningError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)


def test_source_has_no_broken_cyrillic() -> None:
    root = pathlib.Path("src/django_pdf_sign")
    broken = [
        str(path)
        for path in root.rglob("*.py")
        if "?????" in path.read_text(encoding="utf-8")
        or "\ufffd" in path.read_text(encoding="utf-8")
    ]
    assert broken == []


@pytest.mark.django_db
def test_revocation_status_not_checked_without_data() -> None:
    ca_info, ca_key = make_gost_certificate(common_name="Test CA", is_ca=True)
    leaf_info, leaf_key = make_gost_certificate(
        common_name="Test Leaf",
        issuer_cert_der=ca_info.der,
        issuer_private_key=ca_key,
    )
    prepared = prepare_signing(document=_document(), certificate_der=leaf_info.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(leaf_info, leaf_key)
    )
    result = complete_signing(
        session_id=prepared.session.pk,
        cms=cms_bytes,
        policy=VerificationPolicy(
            check_chain=True, trust_roots=(ca_info.der,), moment=NOW
        ),
    )
    assert result.record.revocation_status == RevocationStatus.NOT_CHECKED
