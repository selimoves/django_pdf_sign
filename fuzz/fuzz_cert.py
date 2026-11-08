import contextlib
import sys

import atheris

with atheris.instrument_imports():
    from django_pdf_sign.crypto.certs import parse_certificate
    from django_pdf_sign.exceptions import CertificateError


def test_one_input(data: bytes) -> None:
    with contextlib.suppress(CertificateError):
        parse_certificate(data)


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
