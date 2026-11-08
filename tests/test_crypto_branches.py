import asyncio
import datetime
import hashlib

import pytest
from asn1crypto import cms as asn1cms
from asn1crypto import core, ocsp, x509
from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from pyhanko_certvalidator.fetchers import requests_fetchers

from django_pdf_sign.conf import get_setting
from django_pdf_sign.crypto import gost as gost_module
from django_pdf_sign.crypto import ocsp as ocsp_module
from django_pdf_sign.crypto import timestamp as timestamp_module
from django_pdf_sign.crypto.certs import (
    _key_size,
    curve_oid_from_parameters,
)
from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.crypto.fetchers import AllowlistFetcherBackend
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.crypto.oids import RSA_KEY_OID
from django_pdf_sign.crypto.pades import verify_pades
from django_pdf_sign.crypto.validation import validate_chain  # noqa: F401
from django_pdf_sign.exceptions import CertificateError, VerificationError
from tests.helpers import (
    make_gost_certificate,
    make_gost_cms,
    make_gost_ocsp,
    make_gost_timestamp,
    make_rsa_cms,
)

NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


def _token_and_signature() -> tuple[bytes, bytes]:
    signer, key = make_gost_certificate(common_name="Signer")
    tsa, tsa_key = make_gost_certificate(common_name="TSA")
    cms_bytes, _, _ = make_gost_cms(signer=(signer, key))
    parsed = asn1cms.ContentInfo.load(cms_bytes)
    signature_value = parsed["content"]["signer_infos"][0]["signature"].native
    token = make_gost_timestamp(
        signature_value=signature_value,
        tsa_cert_der=tsa.der,
        tsa_private_key=tsa_key,
    )
    return token, signature_value


def _verify_token(token: bytes, signature_value: bytes):
    return timestamp_module.verify_timestamp_token(
        token, signature_value=signature_value
    )


def test_timestamp_without_certificate() -> None:
    token, signature_value = _token_and_signature()
    info = asn1cms.ContentInfo.load(token)
    del info["content"]["certificates"]
    result = _verify_token(info.dump(), signature_value)
    assert not result.valid
    assert "TSA" in result.errors[0]


def test_timestamp_unsupported_signature_algorithm() -> None:
    token, signature_value = _token_and_signature()
    info = asn1cms.ContentInfo.load(token)
    info["content"]["signer_infos"][0]["signature_algorithm"]["algorithm"] = "1.2.3.4"
    assert not _verify_token(info.dump(), signature_value).valid


def test_timestamp_bad_signature() -> None:
    token, signature_value = _token_and_signature()
    info = asn1cms.ContentInfo.load(token)
    signer_info = info["content"]["signer_infos"][0]
    signer_info["signature"] = b"\x00" * len(signer_info["signature"].native)
    assert not _verify_token(info.dump(), signature_value).valid


def test_timestamp_message_digest_mismatch() -> None:
    token, signature_value = _token_and_signature()
    info = asn1cms.ContentInfo.load(token)
    attributes = info["content"]["signer_infos"][0]["signed_attrs"]
    for attribute in attributes:
        if attribute["type"].native == "message_digest":
            attribute["values"] = [core.OctetString(b"wrong")]
    assert not _verify_token(info.dump(), signature_value).valid


def test_timestamp_requires_covered_data() -> None:
    token, _ = _token_and_signature()
    with pytest.raises(ValueError):
        timestamp_module.verify_timestamp_token(token)


def test_find_attribute_none_and_broken() -> None:
    assert timestamp_module._find_attribute(None, "message_digest") is None
    assert timestamp_module._find_attribute([1], "message_digest") is None


def test_digest_and_hash_sha1() -> None:
    assert timestamp_module._digest_name(timestamp_module.SHA1_OID) == "sha1"
    assert timestamp_module._hash("sha1", b"data") == hashlib.sha1(b"data").digest()
    assert timestamp_module._signature_digest("sha256WithRSAEncryption") == "sha256"
    assert timestamp_module._signature_digest("1.2.840.113549.1.1.11") == "sha256"
    assert ocsp_module._signature_digest("1.2.840.10045.4.3.2") == "sha256"
    assert timestamp_module._signature_digest("1.2.3.4") is None


def _ocsp_response(
    status: str = "good", **kwargs: object
) -> tuple[bytes, bytes, bytes]:
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
        status=status,
        **kwargs,
    )
    return ca.der, leaf.der, response


def test_ocsp_unknown_status() -> None:
    issuer, target, response = _ocsp_response(status="unknown")
    status = ocsp_module.evaluate_ocsps(
        (response,), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable
    assert any("неизвестен" in error for error in status.errors)


def test_ocsp_expired_response() -> None:
    issuer, target, response = _ocsp_response(
        this_update=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        next_update=datetime.datetime(2026, 2, 1, tzinfo=datetime.UTC),
    )
    status = ocsp_module.evaluate_ocsps(
        (response,), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable
    assert any("истёк" in error for error in status.errors)


def test_ocsp_not_yet_valid_response() -> None:
    issuer, target, response = _ocsp_response(
        this_update=datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC),
    )
    status = ocsp_module.evaluate_ocsps(
        (response,), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable
    assert any("не вступил" in error for error in status.errors)


def test_ocsp_non_success_status() -> None:
    issuer, target, _ = _ocsp_response()
    response = ocsp.OCSPResponse({"response_status": "try_later"}).dump()
    status = ocsp_module.evaluate_ocsps(
        (response,), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable
    assert any("Статус OCSP" in error for error in status.errors)


def test_ocsp_unsupported_signature_algorithm() -> None:
    issuer, target, response = _ocsp_response()
    parsed = ocsp.OCSPResponse.load(response)
    basic = parsed["response_bytes"]["response"].parsed
    basic["signature_algorithm"]["algorithm"] = "1.2.3.4"
    parsed["response_bytes"]["response"] = basic
    status = ocsp_module.evaluate_ocsps(
        (parsed.dump(),), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable


def test_ocsp_responder_id_mismatch() -> None:
    issuer, target, response = _ocsp_response()
    parsed = ocsp.OCSPResponse.load(response)
    basic = parsed["response_bytes"]["response"].parsed
    basic["tbs_response_data"]["responder_id"] = ocsp.ResponderId(
        name="by_key", value=b"\x00" * 20
    )
    parsed["response_bytes"]["response"] = basic
    status = ocsp_module.evaluate_ocsps(
        (parsed.dump(),), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable
    assert any("ResponderID" in error for error in status.errors)


def test_ocsp_cert_id_unknown_digest() -> None:
    issuer, target, response = _ocsp_response()
    parsed = ocsp.OCSPResponse.load(response)
    basic = parsed["response_bytes"]["response"].parsed
    cert_id = basic["tbs_response_data"]["responses"][0]["cert_id"]
    cert_id["hash_algorithm"]["algorithm"] = "1.2.3.4"
    assert not ocsp_module._cert_id_matches(
        cert_id, x509.Certificate.load(target), x509.Certificate.load(issuer)
    )


def test_ocsp_cert_id_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer, target, response = _ocsp_response()
    parsed = ocsp.OCSPResponse.load(response)
    basic = parsed["response_bytes"]["response"].parsed
    cert_id = basic["tbs_response_data"]["responses"][0]["cert_id"]

    def broken(certificate: object) -> bytes:
        raise ValueError("broken spki")

    monkeypatch.setattr(ocsp_module, "_spki_bits", broken)
    assert not ocsp_module._cert_id_matches(
        cert_id, x509.Certificate.load(target), x509.Certificate.load(issuer)
    )


def test_ocsp_signature_verification_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer, target, response = _ocsp_response()

    def broken(*args: object, **kwargs: object) -> tuple[bool, tuple[str, ...]]:
        raise RuntimeError("broken")

    monkeypatch.setattr(ocsp_module, "_verify_ocsp_signature", broken)
    status = ocsp_module.evaluate_ocsps(
        (response,), target_der=target, issuer_der=issuer, moment=NOW
    )
    assert not status.applicable


def test_ocsp_spki_bits_gost() -> None:
    ca, _ = make_gost_certificate(common_name="Test CA", is_ca=True)
    bits = ocsp_module._spki_bits(x509.Certificate.load(ca.der))
    assert len(bits) == 65


def _ec_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = cryptography_x509.Name(
        [cryptography_x509.NameAttribute(NameOID.COMMON_NAME, "EC")]
    )
    certificate = (
        cryptography_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cryptography_x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def test_pades_ecdsa_signature() -> None:
    key, certificate = _ec_certificate()
    data = b"payload"
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
    assert verify_pades(
        certificate_der=certificate.public_bytes(serialization.Encoding.DER),
        signed_attrs_der=data,
        signature=signature,
        digest_algorithm="sha256",
    )


def _ed25519_der() -> bytes:
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
    return certificate.public_bytes(serialization.Encoding.DER)


def test_pades_unsupported_key_type() -> None:
    with pytest.raises(VerificationError):
        verify_pades(
            certificate_der=_ed25519_der(),
            signed_attrs_der=b"data",
            signature=b"signature",
            digest_algorithm="sha256",
        )


def test_curve_oid_none_and_key_size_unsupported() -> None:
    assert curve_oid_from_parameters(None) is None
    with pytest.raises(CertificateError):
        _key_size(_ed25519_der(), RSA_KEY_OID)


def test_gost_unsupported_key_size() -> None:
    with pytest.raises(VerificationError):
        verify_gost(
            public_key=b"",
            curve_oid="1.2.643.7.1.2.1.1.1",
            digest=b"",
            signature=b"",
            key_size=123,
        )


def test_gost_wrong_signature_length() -> None:
    with pytest.raises(VerificationError):
        verify_gost(
            public_key=b"\x00" * 64,
            curve_oid="1.2.643.7.1.2.1.1.1",
            digest=b"\x00" * 32,
            signature=b"\x00",
            key_size=256,
        )


def test_gost_verifier_exception_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Broken:
        def verify(self, *args: object) -> bool:
            raise ValueError("broken")

    monkeypatch.setattr(gost_module, "normalize_public_key", lambda *a, **k: b"\x00")
    monkeypatch.setattr(gost_module, "_curve", lambda oid: object())
    monkeypatch.setattr(gost_module.gostsignature, "new", lambda *a, **k: _Broken())
    assert not verify_gost(
        public_key=b"\x00" * 64,
        curve_oid="1.2.643.7.1.2.1.1.1",
        digest=b"\x00" * 32,
        signature=b"\x00" * 64,
        key_size=256,
    )


def test_conf_rejects_non_dict_settings() -> None:
    with override_settings(DJANGO_PDF_SIGN="bad"), pytest.raises(ImproperlyConfigured):
        get_setting("SESSION_TTL")


def test_parse_cms_without_unsigned_attrs() -> None:
    cms_bytes, _, _ = make_rsa_cms()
    info = asn1cms.ContentInfo.load(cms_bytes)
    del info["content"]["signer_infos"][0]["unsigned_attrs"]
    assert parse_cms(info.dump()).timestamp_token is None


def test_fetchers_allow_known_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_ocsp(self: object, url: str, request: bytes) -> bytes:
        return b"ocsp"

    async def fake_cert(self: object, url: str, origin: str) -> bytes:
        return b"cert"

    monkeypatch.setattr(
        requests_fetchers.RequestsOCSPFetcher, "_fetch_single", fake_ocsp
    )
    monkeypatch.setattr(
        requests_fetchers.RequestsCertificateFetcher, "fetch_certs", fake_cert
    )
    fetchers = AllowlistFetcherBackend(("allowed.example",)).get_fetchers()
    assert (
        asyncio.run(fetchers.ocsp_fetcher._fetch_single("https://allowed.example", b""))
        == b"ocsp"
    )
    assert (
        asyncio.run(
            fetchers.cert_fetcher.fetch_certs("https://allowed.example", "certificate")
        )
        == b"cert"
    )
