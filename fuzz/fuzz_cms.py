import contextlib
import sys

import atheris

with atheris.instrument_imports():
    from django_pdf_sign.crypto.cms import parse_cms
    from django_pdf_sign.exceptions import VerificationError


def test_one_input(data: bytes) -> None:
    with contextlib.suppress(VerificationError):
        parse_cms(data)


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
