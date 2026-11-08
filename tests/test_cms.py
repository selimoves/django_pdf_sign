"""Tests for detached CMS parsing."""

from __future__ import annotations

import hashlib

import pytest
from gostcrypto import gosthash

from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.exceptions import VerificationError
from tests.helpers import make_gost_cms, make_rsa_cms


def test_parse_rsa_cms() -> None:
    cms_bytes, info, data = make_rsa_cms()
    parsed = parse_cms(cms_bytes)
    assert parsed.certificate.thumbprint_sha256 == info.thumbprint_sha256
    assert parsed.message_digest == hashlib.sha256(data).digest()
    assert parsed.digest_algorithm == "sha256"
    assert parsed.signed_attrs_der[:1] == b"\x31"
    assert parsed.signing_time is not None


def test_parse_gost_cms() -> None:
    cms_bytes, info, data = make_gost_cms()
    parsed = parse_cms(cms_bytes)
    assert parsed.certificate.is_gost is True
    assert parsed.certificate.thumbprint_sha256 == info.thumbprint_sha256
    assert parsed.digest_algorithm == "streebog256"
    assert parsed.message_digest == bytes(
        gosthash.new("streebog256", data=data).digest()
    )
    assert parsed.signed_attrs_der[:1] == b"\x31"


def test_garbage_raises() -> None:
    with pytest.raises(VerificationError):
        parse_cms(b"garbage")
