import sys

import atheris

with atheris.instrument_imports():
    from django_pdf_sign.crypto.timestamp import verify_timestamp_token


def test_one_input(data: bytes) -> None:
    verify_timestamp_token(data, imprinted_data=b"payload")


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
