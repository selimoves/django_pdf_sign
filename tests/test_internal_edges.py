import asyncio
import datetime
import logging

import pytest
from asn1crypto import cms as asn1cms
from asn1crypto import x509
from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.test import override_settings
from pyhanko_certvalidator.errors import CertificateFetchError, OCSPFetchError

from django_pdf_sign import events as events_module
from django_pdf_sign.checks import check_settings
from django_pdf_sign.conf import get_setting, get_stamp_setting
from django_pdf_sign.constants import SigningStatus, TimestampStatus
from django_pdf_sign.crypto.certs import (
    curve_oid_from_parameters,
    gost_public_key_from_spki,
    parse_certificate,
)
from django_pdf_sign.crypto.cms import _find_certificate, _signed_attribute, parse_cms
from django_pdf_sign.crypto.fetchers import AllowlistFetcherBackend
from django_pdf_sign.crypto.validation import validate_chain
from django_pdf_sign.events import emit
from django_pdf_sign.exceptions import (
    CertificateError,
    SigningError,
    VerificationError,
)
from django_pdf_sign.models import SignatureRecord, SigningSession
from django_pdf_sign.services import (
    VerificationPolicy,
    complete_signing,
    prepare_signing,
    verify_cms_over_bytes,
    verify_signed_pdf,
)
from django_pdf_sign.services.complete import _signing_time, _trusted
from tests.helpers import (
    add_cms_timestamp,
    make_gost_certificate,
    make_gost_cms,
    make_gost_timestamp,
    make_rsa_certificate,
    make_rsa_cms,
    minimal_pdf,
)
from tests.models import Document


def _document() -> Document:
    return Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))


def _load(cms_bytes: bytes) -> asn1cms.ContentInfo:
    return asn1cms.ContentInfo.load(cms_bytes)


def test_parse_cms_rejects_two_signer_infos() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = _load(cms_bytes)
    signer_infos = info["content"]["signer_infos"]
    signer_infos.append(signer_infos[0])
    with pytest.raises(VerificationError):
        parse_cms(info.dump())


def test_parse_cms_rejects_missing_message_digest() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = _load(cms_bytes)
    signer_info = info["content"]["signer_infos"][0]
    signer_info["signed_attrs"] = [
        attribute
        for attribute in signer_info["signed_attrs"]
        if attribute["type"].native != "message_digest"
    ]
    with pytest.raises(VerificationError):
        parse_cms(info.dump())


def test_parse_cms_rejects_unknown_digest_algorithm() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = _load(cms_bytes)
    info["content"]["signer_infos"][0]["digest_algorithm"]["algorithm"] = "1.2.3.4"
    with pytest.raises(VerificationError):
        parse_cms(info.dump())


def test_parse_cms_rejects_missing_certificates() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = _load(cms_bytes)
    del info["content"]["certificates"]
    with pytest.raises(VerificationError):
        parse_cms(info.dump())


def test_find_certificate_by_subject_key_identifier() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = _load(cms_bytes)
    signed_data = info["content"]
    parsed_certificate = signed_data["certificates"][0].chosen

    class _Chosen:
        def __init__(self, native: bytes) -> None:
            self.native = native

    class _SignerId:
        name = "subject_key_identifier"

        def __init__(self, native: bytes) -> None:
            self.chosen = _Chosen(native)

    found = _find_certificate(signed_data, _SignerId(parsed_certificate.key_identifier))
    assert found.dump() == parsed_certificate.dump()


def test_signed_attribute_missing_returns_none() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    attributes = _load(cms_bytes)["content"]["signer_infos"][0]["signed_attrs"]
    assert _signed_attribute(attributes, "signing_time_absent") is None


def test_timestamp_token_ignores_unrelated_unsigned_attribute() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = _load(cms_bytes)
    signer_info = info["content"]["signer_infos"][0]
    signer_info["unsigned_attrs"] = [
        asn1cms.CMSAttribute({"type": "signing_time", "values": []})
    ]
    parsed = parse_cms(info.dump())
    assert parsed.timestamp_token is None


class _Native:
    def __init__(self, value: object) -> None:
        self.native = value


def test_curve_oid_from_parameters_variants() -> None:
    assert curve_oid_from_parameters(_Native({"curve": "1.2.3"})) == "1.2.3"
    assert curve_oid_from_parameters(_Native(["1.2.3", "4.5.6"])) == "1.2.3"
    assert curve_oid_from_parameters(_Native([None])) is None
    assert curve_oid_from_parameters(_Native(123)) is None


def test_gost_public_key_from_spki_rejects_wrong_length() -> None:
    info, _ = make_gost_certificate()
    certificate = x509.Certificate.load(info.der)
    spki = certificate["tbs_certificate"]["subject_public_key_info"]
    with pytest.raises(CertificateError):
        gost_public_key_from_spki(spki, 512)


def test_parse_certificate_rejects_unsupported_key_type() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    name = cryptography_x509.Name(
        [cryptography_x509.NameAttribute(NameOID.COMMON_NAME, "Ed25519")]
    )
    certificate = (
        cryptography_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cryptography_x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=datetime.UTC))
        .sign(key, None)
    )
    with pytest.raises(CertificateError):
        parse_certificate(certificate.public_bytes(Encoding.DER))


def test_conf_rejects_invalid_nested_settings() -> None:
    cases = [
        {"STAMP": "not-a-dict"},
        {"STAMP": {"UNKNOWN": 1}},
        {"VERIFY": "not-a-dict"},
        {"VERIFY": {"UNKNOWN": 1}},
        {"UNKNOWN": 1},
    ]
    for config in cases:
        with (
            override_settings(DJANGO_PDF_SIGN=config),
            pytest.raises(ImproperlyConfigured),
        ):
            get_setting("SESSION_TTL")
    with override_settings(DJANGO_PDF_SIGN={}), pytest.raises(ImproperlyConfigured):
        get_stamp_setting("UNKNOWN")


def test_verify_expected_certificate_parse_error() -> None:
    cms_bytes, _, data = make_rsa_cms()
    result = verify_cms_over_bytes(
        cms=cms_bytes, data=data, expected_certificate_der=b"garbage"
    )
    assert not result.valid
    assert not result.certificate_matches


def test_verify_reports_signature_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    cms_bytes, _, data = make_rsa_cms()

    def broken(**kwargs: object) -> bool:
        raise ValueError("сломанная криптография")

    monkeypatch.setattr("django_pdf_sign.services.verify.verify_pades", broken)
    result = verify_cms_over_bytes(cms=cms_bytes, data=data)
    assert not result.valid
    assert not result.signature_ok


def test_verify_signed_pdf_rejects_garbage() -> None:
    result = verify_signed_pdf(b"not a pdf")
    assert not result.valid


def test_fetchers_reject_ocsp_and_certificate_hosts() -> None:
    backend = AllowlistFetcherBackend(("allowed.example",))
    fetchers = backend.get_fetchers()
    with pytest.raises(OCSPFetchError):
        asyncio.run(fetchers.ocsp_fetcher._fetch_single("https://evil/ocsp", b""))
    with pytest.raises(CertificateFetchError):
        asyncio.run(fetchers.cert_fetcher.fetch_certs("https://evil/ca", "certificate"))


def test_emit_survives_broken_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        events_module,
        "get_setting",
        lambda name: (_ for _ in ()).throw(ImproperlyConfigured("boom")),
    )
    emit("session_prepared", session_id="1")


def test_checks_report_unknown_keys_and_stamp_paths() -> None:
    with override_settings(DJANGO_PDF_SIGN={"UNKNOWN": 1}):
        errors = check_settings(None)
    assert errors and errors[0].id == "django_pdf_sign.E001"

    with override_settings(
        DJANGO_PDF_SIGN={
            "STAMP": {"FONT_SIZE": 0, "FONT_PATH": "/nonexistent/font.ttf"}
        }
    ):
        errors = check_settings(None)
    assert {error.id for error in errors} >= {
        "django_pdf_sign.E008",
        "django_pdf_sign.E009",
    }


def test_model_str_methods() -> None:
    session = SigningSession(status="prepared")
    record = SignatureRecord(verification_status="valid")
    assert "(prepared)" in str(session)
    assert "(valid)" in str(record)


def test_validation_rejects_fetching_without_allowlist() -> None:
    info, _ = make_rsa_certificate()
    policy = VerificationPolicy(check_chain=True, allow_fetching=True)
    with pytest.raises(VerificationError):
        validate_chain(info.der, policy)


def test_signing_time_and_trusted_helpers() -> None:
    assert _signing_time({"signing_time": "not-a-date"}) is None
    assert _signing_time({"signing_time": 123}) is None
    assert _trusted({"trusted": "yes"}) is None


@pytest.mark.django_db
def test_complete_with_valid_timestamp() -> None:
    signer, signer_key = make_gost_certificate(common_name="Signer")
    tsa, tsa_key = make_gost_certificate(common_name="TSA")
    prepared = prepare_signing(document=_document(), certificate_der=signer.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(signer, signer_key)
    )
    parsed = _load(cms_bytes)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    token = make_gost_timestamp(
        signature_value=signature_value,
        tsa_cert_der=tsa.der,
        tsa_private_key=tsa_key,
        gen_time=datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC),
    )
    result = complete_signing(
        session_id=prepared.session.pk,
        cms=add_cms_timestamp(cms_bytes, token),
        policy=VerificationPolicy(check_timestamps=True),
    )
    assert result.record.timestamp_status == TimestampStatus.VALID
    assert result.record.signing_time is not None


@pytest.mark.django_db
def test_complete_requires_timestamp_when_configured() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(document=_document(), certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    with pytest.raises(VerificationError):
        complete_signing(
            session_id=prepared.session.pk,
            cms=cms_bytes,
            policy=VerificationPolicy(require_timestamp=True),
        )


@pytest.mark.django_db
def test_complete_ignores_timestamp_for_certificate_validity() -> None:
    signer, signer_key = make_gost_certificate(common_name="Signer")
    tsa, tsa_key = make_gost_certificate(common_name="TSA")
    prepared = prepare_signing(document=_document(), certificate_der=signer.der)
    cms_bytes, _, _ = make_gost_cms(
        data=prepared.bytes_to_sign, signer=(signer, signer_key)
    )
    parsed = _load(cms_bytes)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    token = make_gost_timestamp(
        signature_value=signature_value,
        tsa_cert_der=tsa.der,
        tsa_private_key=tsa_key,
        gen_time=datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC),
    )
    result = complete_signing(
        session_id=prepared.session.pk,
        cms=add_cms_timestamp(cms_bytes, token),
    )
    assert result.session.status == SigningStatus.COMPLETED


@pytest.mark.django_db
def test_complete_rejects_cms_that_does_not_fit() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_signing(
        document=_document(), certificate_der=info.der, bytes_reserved=1000
    )
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    with pytest.raises(SigningError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)


def test_logger_name_is_package(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="django_pdf_sign")
    emit("session_prepared", session_id="1")
    assert any(record.name == "django_pdf_sign" for record in caplog.records)
