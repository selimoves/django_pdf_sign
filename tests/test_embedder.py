"""Tests for PDF preparation and CMS embedding."""

from __future__ import annotations

import io

import pytest
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import enumerate_sig_fields

from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.exceptions import SigningError
from django_pdf_sign.pdf.embedder import embed_cms, prepare_document
from tests.helpers import (
    make_gost_certificate,
    make_rsa_certificate,
    make_rsa_cms,
    minimal_pdf,
)


def test_prepare_produces_signature_field_and_placeholder() -> None:
    info, _ = make_rsa_certificate()
    prepared = prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1")
    reader = PdfFileReader(io.BytesIO(prepared.pdf_with_placeholder))
    assert [name for name, _, _ in enumerate_sig_fields(reader)] == ["Sig1"]
    assert prepared.bytes_to_sign == (
        prepared.pdf_with_placeholder[: prepared.reserved_region_start]
        + prepared.pdf_with_placeholder[prepared.reserved_region_end :]
    )
    assert len(prepared.bytes_to_sign) < len(prepared.pdf_with_placeholder)


def test_prepare_uses_streebog_for_gost() -> None:
    info, _ = make_gost_certificate()
    prepared = prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1")
    assert prepared.digest_algorithm == "streebog256"
    assert digest_for(prepared.digest_algorithm, prepared.bytes_to_sign)


def test_prepare_uses_sha256_for_rsa() -> None:
    info, _ = make_rsa_certificate()
    prepared = prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1")
    assert prepared.digest_algorithm == "sha256"


def test_embed_roundtrip_pades() -> None:
    info, key = make_rsa_certificate()
    prepared = prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1")
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))
    signed = embed_cms(
        prepared_pdf=prepared.pdf_with_placeholder,
        reserved_region_start=prepared.reserved_region_start,
        reserved_region_end=prepared.reserved_region_end,
        cms=cms_bytes,
    )
    reader = PdfFileReader(io.BytesIO(signed))
    signature = reader.embedded_signatures[0]
    assert signature.field_name == "Sig1"
    assert signature.sig_object["/Contents"].original_bytes


def test_page_minus_one_uses_last_page() -> None:
    info, _ = make_rsa_certificate()
    prepared = prepare_document(
        pdf=minimal_pdf(pages=2), certificate=info, field_name="Sig1", page=-1
    )
    assert prepared.page == 1
    reader = PdfFileReader(io.BytesIO(prepared.pdf_with_placeholder))
    assert [name for name, _, _ in enumerate_sig_fields(reader)] == ["Sig1"]


def test_embed_rejects_oversized_cms() -> None:
    info, _ = make_rsa_certificate()
    prepared = prepare_document(
        pdf=minimal_pdf(), certificate=info, field_name="Sig1", bytes_reserved=64
    )
    with pytest.raises(SigningError):
        embed_cms(
            prepared_pdf=prepared.pdf_with_placeholder,
            reserved_region_start=prepared.reserved_region_start,
            reserved_region_end=prepared.reserved_region_end,
            cms=b"\x30" * 200,
        )


def test_out_of_range_page_raises() -> None:
    info, _ = make_rsa_certificate()
    with pytest.raises(SigningError):
        prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1", page=5)
