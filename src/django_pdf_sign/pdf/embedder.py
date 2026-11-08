"""Подготовить PDF к клиентской подписи и встроить полученную CMS."""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import UTC, datetime

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields
from pyhanko.sign.signers import cms_embedder
from pyhanko.sign.signers.pdf_byterange import (
    PreparedByteRangeDigest,
    SignatureObject,
)

from django_pdf_sign.conf import get_setting
from django_pdf_sign.constants import SUBFILTER_ADOBE_PKCS7, SUBFILTER_PADES
from django_pdf_sign.crypto.certs import CertificateInfo, display_name
from django_pdf_sign.crypto.digest import algorithm_for_key_oid
from django_pdf_sign.exceptions import SigningError
from django_pdf_sign.pdf.stamp import (
    StampConfig,
    build_stamp_style,
    stamp_text_params,
)

_SUBFILTERS = {
    SUBFILTER_ADOBE_PKCS7: fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
    SUBFILTER_PADES: fields.SigSeedSubFilter.PADES,
}


@dataclass(frozen=True)
class PreparedDocument:
    """PDF с местом подписи и точные байты для подписи."""

    pdf_with_placeholder: bytes
    bytes_to_sign: bytes
    reserved_region_start: int
    reserved_region_end: int
    digest_algorithm: str
    field_name: str
    page: int


def _page_count(pdf: bytes) -> int:
    reader = PdfFileReader(io.BytesIO(pdf))
    return int(reader.root["/Pages"]["/Count"])


def _resolve_page(pdf: bytes, page: int) -> int:
    count = _page_count(pdf)
    resolved = page if page >= 0 else count + page
    if not 0 <= resolved < count:
        raise SigningError(f"Индекс страницы вне диапазона: {page}")
    return resolved


def _subfilter(value: str) -> fields.SigSeedSubFilter:
    try:
        return _SUBFILTERS[value]
    except KeyError as exc:
        raise SigningError(f"Неподдерживаемый SubFilter подписи: {value}") from exc


def prepare_document(
    *,
    pdf: bytes,
    certificate: CertificateInfo,
    field_name: str,
    page: int = -1,
    box: tuple[int, int, int, int] | None = None,
    stamp: StampConfig | None = None,
    reason: str | None = None,
    location: str | None = None,
    subfilter: str | None = None,
    bytes_reserved: int | None = None,
    timestamp: datetime | None = None,
) -> PreparedDocument:
    """Добавить штамп и место подписи и вернуть байты для подписи."""
    resolved_page = _resolve_page(pdf, page)
    digest_algorithm = algorithm_for_key_oid(certificate.key_oid)
    subfilter_value = subfilter or (
        SUBFILTER_ADOBE_PKCS7 if certificate.is_gost else SUBFILTER_PADES
    )
    stamp_time = timestamp or datetime.now(UTC)
    stamp_config = stamp or StampConfig.from_settings()

    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    field_spec = fields.SigFieldSpec(
        field_name,
        on_page=resolved_page,
        box=box or tuple(get_setting("DEFAULT_BOX")),
    )
    embedder = cms_embedder.PdfCMSEmbedder(new_field_spec=field_spec)
    generator = embedder.write_cms(field_name, writer)
    next(generator)

    placeholder = SignatureObject(
        timestamp=stamp_time,
        subfilter=_subfilter(subfilter_value),
        reason=reason,
        location=location,
        bytes_reserved=bytes_reserved or get_setting("BYTES_RESERVED"),
    )
    appearance = cms_embedder.SigAppearanceSetup(
        style=build_stamp_style(stamp_config),
        timestamp=stamp_time,
        name=display_name(certificate),
        text_params=stamp_text_params(certificate, timestamp=stamp_time),
    )
    generator.send(
        cms_embedder.SigObjSetup(
            sig_placeholder=placeholder, appearance_setup=appearance
        )
    )
    prepared_digest, output = generator.send(
        cms_embedder.SigIOSetup(md_algorithm="sha256")
    )

    data = output.getvalue()
    start = prepared_digest.reserved_region_start
    end = prepared_digest.reserved_region_end

    return PreparedDocument(
        pdf_with_placeholder=data,
        bytes_to_sign=data[:start] + data[end:],
        reserved_region_start=start,
        reserved_region_end=end,
        digest_algorithm=digest_algorithm,
        field_name=field_name,
        page=resolved_page,
    )


def embed_cms(
    *,
    prepared_pdf: bytes,
    reserved_region_start: int,
    reserved_region_end: int,
    cms: bytes,
) -> bytes:
    """Записать CMS в DER в подготовленное место."""
    stream = io.BytesIO(prepared_pdf)
    prepared = PreparedByteRangeDigest(
        document_digest=b"",
        reserved_region_start=reserved_region_start,
        reserved_region_end=reserved_region_end,
    )
    try:
        prepared.fill_with_cms(stream, cms)
    except Exception as exc:
        raise SigningError("CMS не помещается в зарезервированное место") from exc
    return stream.getvalue()
