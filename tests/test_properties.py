import contextlib

from hypothesis import given, settings
from hypothesis import strategies as st

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.crypto.ocsp import evaluate_ocsps
from django_pdf_sign.crypto.timestamp import verify_timestamp_token
from django_pdf_sign.exceptions import CertificateError, VerificationError
from tests.helpers import make_rsa_certificate


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=4096))
def test_parse_cms_never_raises_other(data: bytes) -> None:
    with contextlib.suppress(VerificationError):
        parse_cms(data)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=4096))
def test_parse_certificate_never_raises_other(data: bytes) -> None:
    with contextlib.suppress(CertificateError):
        parse_certificate(data)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=4096))
def test_evaluate_ocsps_never_raises_other(data: bytes) -> None:
    info, _ = make_rsa_certificate()
    evaluate_ocsps((data,), target_der=info.der, issuer_der=info.der)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=4096))
def test_verify_timestamp_token_never_raises_other(data: bytes) -> None:
    verify_timestamp_token(data, imprinted_data=b"payload")
