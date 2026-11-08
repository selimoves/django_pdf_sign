import sys
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from django_pdf_sign.crypto.ocsp import evaluate_ocsps

ROOT = Path("tests/fixtures/crypto/pycades-root.cer").read_bytes()


def test_one_input(data: bytes) -> None:
    evaluate_ocsps((data,), target_der=ROOT, issuer_der=ROOT)


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
