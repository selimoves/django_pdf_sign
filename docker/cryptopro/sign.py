"""Подпись байтов через КриптоПро CSP внутри контейнера.

Режимы:
    sign.py export-cert <out.der>
    sign.py sign <bytes.bin> <cms.der> [--thumbprint HEX]

Подпись отсоединённая (CAdES-BES), как её возвращает браузерный плагин.
"""

from __future__ import annotations

import argparse
import base64
import sys

import pycades


def _open_store() -> "pycades.Store":
    store = pycades.Store()
    store.Open(
        pycades.CADESCOM_CONTAINER_STORE,
        pycades.CAPICOM_MY_STORE,
        pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED,
    )
    return store


def _pick_certificate(store: "pycades.Store", thumbprint: str | None) -> object:
    certificates = store.Certificates
    if certificates.Count == 0:
        raise SystemExit("В хранилище нет сертификатов с закрытым ключом")
    for index in range(1, certificates.Count + 1):
        certificate = certificates.Item(index)
        if thumbprint is None or certificate.Thumbprint.upper() == thumbprint.upper():
            return certificate
    raise SystemExit(f"Сертификат {thumbprint} не найден")


def export_certificate(out_path: str) -> None:
    certificate = _pick_certificate(_open_store(), None)
    encoded = certificate.Export(pycades.CADESCOM_ENCODE_BASE64)
    with open(out_path, "wb") as handle:
        handle.write(base64.b64decode(encoded))
    print(f"certificate exported: {certificate.SubjectName}")


def sign_bytes(bytes_path: str, cms_path: str, thumbprint: str | None) -> None:
    with open(bytes_path, "rb") as handle:
        payload = handle.read()

    signer = pycades.Signer()
    signer.Certificate = _pick_certificate(_open_store(), thumbprint)
    signer.CheckCertificate = True

    signed_data = pycades.SignedData()
    signed_data.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
    signed_data.Content = base64.b64encode(payload).decode("ascii")
    signature = signed_data.SignCades(
        signer, pycades.CADESCOM_CADES_BES, True
    )
    with open(cms_path, "wb") as handle:
        handle.write(base64.b64decode(signature))
    print(f"signed {len(payload)} bytes")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export-cert")
    export_parser.add_argument("out")

    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("bytes_path")
    sign_parser.add_argument("cms_path")
    sign_parser.add_argument("--thumbprint", default=None)

    args = parser.parse_args(argv)
    if args.command == "export-cert":
        export_certificate(args.out)
    else:
        sign_bytes(args.bytes_path, args.cms_path, args.thumbprint)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
