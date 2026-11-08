"""Tests for digest primitives."""

from __future__ import annotations

import hashlib

import pytest

from django_pdf_sign.crypto.digest import algorithm_for_key_oid, digest_for


def test_sha256_matches_hashlib() -> None:
    assert digest_for("sha256", b"abc") == hashlib.sha256(b"abc").digest()


def test_streebog256_known_vector() -> None:
    # GOST R 34.11-2012 test vector for the message "abc".
    assert (
        digest_for("streebog256", b"abc").hex()
        == "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481"
    )


def test_streebog512_known_vector() -> None:
    # GOST R 34.11-2012 test vector for the message "abc".
    assert digest_for("streebog512", b"abc").hex() == (
        "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8"
        "d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728"
    )


def test_unknown_algorithm_raises() -> None:
    with pytest.raises(ValueError):
        digest_for("md5", b"abc")


def test_algorithm_for_gost_256() -> None:
    assert algorithm_for_key_oid("1.2.643.7.1.1.1.1") == "streebog256"


def test_algorithm_for_gost_512() -> None:
    assert algorithm_for_key_oid("1.2.643.7.1.1.1.2") == "streebog512"


def test_algorithm_for_rsa() -> None:
    assert algorithm_for_key_oid("1.2.840.113549.1.1.1") == "sha256"


def test_algorithm_for_ec() -> None:
    assert algorithm_for_key_oid("1.2.840.10045.2.1") == "sha256"


def test_algorithm_for_unknown_key_raises() -> None:
    with pytest.raises(ValueError):
        algorithm_for_key_oid("1.2.643.2.2.19")
