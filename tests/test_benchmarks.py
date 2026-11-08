import io

import pytest
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.writer import PdfFileWriter

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.pdf.embedder import prepare_document
from tests.helpers import make_rsa_certificate

pytestmark = pytest.mark.benchmark

SIZES_MB = (1, 10, 50)


def _big_pdf(size_bytes: int) -> bytes:
    writer = PdfFileWriter()
    page = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Page"),
            generic.NameObject("/MediaBox"): generic.ArrayObject(
                [generic.NumberObject(value) for value in (0, 0, 612, 792)]
            ),
            generic.NameObject("/Resources"): generic.DictionaryObject(),
            generic.NameObject("/Contents"): generic.ArrayObject(),
        }
    )
    writer.insert_page(page)
    stream_ref = writer.add_object(
        generic.StreamObject(stream_data=b"%" + b"x" * size_bytes)
    )
    writer.add_stream_to_page(0, stream_ref)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


@pytest.mark.parametrize("size_mb", SIZES_MB)
def test_digest_streebog256(benchmark, size_mb: int) -> None:
    data = b"x" * (size_mb * 1024 * 1024)
    benchmark.pedantic(digest_for, args=("streebog256", data), rounds=1, iterations=1)


@pytest.mark.parametrize("size_mb", SIZES_MB)
def test_digest_streebog512(benchmark, size_mb: int) -> None:
    data = b"x" * (size_mb * 1024 * 1024)
    benchmark.pedantic(digest_for, args=("streebog512", data), rounds=1, iterations=1)


@pytest.mark.parametrize("size_mb", SIZES_MB)
def test_prepare_document(benchmark, size_mb: int) -> None:
    info, _ = make_rsa_certificate()
    certificate = parse_certificate(info.der)
    pdf = _big_pdf(size_mb * 1024 * 1024)
    benchmark.pedantic(
        prepare_document,
        kwargs={
            "pdf": pdf,
            "certificate": certificate,
            "field_name": f"Signature{size_mb}",
            "box": (57, 57, 284, 170),
        },
        rounds=1,
        iterations=1,
    )
