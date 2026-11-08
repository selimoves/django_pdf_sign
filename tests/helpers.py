"""Shared test fixtures and builders."""

from __future__ import annotations

import datetime
import io
import os

from asn1crypto import algos, core, keys, x509
from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from gostcrypto import gosthash, gostsignature
from gostcrypto.gostsignature import (
    CURVES_R_1323565_1_024_2019 as CURVES,
)
from gostcrypto.gostsignature import (
    MODE_256,
    MODE_512,
)

from django_pdf_sign.crypto.certs import (
    CertificateInfo,
    GostPublicKeyInfo,
    parse_certificate,
)
from django_pdf_sign.crypto.oids import GOST_CURVE_OIDS

GOST_SIGNATURE_OIDS = {256: "1.2.643.7.1.1.3.2", 512: "1.2.643.7.1.1.3.3"}
GOST_KEY_OIDS = {256: "1.2.643.7.1.1.1.1", 512: "1.2.643.7.1.1.1.2"}
DEFAULT_GOST_CURVES = {
    256: "1.2.643.7.1.2.1.1.1",
    512: "1.2.643.7.1.2.1.2.1",
}
GOST_MODES = {256: MODE_256, 512: MODE_512}


def minimal_pdf(pages: int = 1) -> bytes:
    """Build a minimal, valid PDF with the requested number of pages."""
    if pages < 1:
        raise ValueError("pages must be positive")

    kids = " ".join(f"{4 + 2 * index} 0 R" for index in range(pages))
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids ["
        + kids.encode()
        + b"] /Count "
        + str(pages).encode()
        + b" >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for index in range(pages):
        content_id = 5 + 2 * index
        content = f"BT /F1 12 Tf 72 770 Td (Page {index + 1}) Tj ET".encode()
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 3 0 R >> >> /Contents "
            + str(content_id).encode()
            + b" 0 R >>"
        )
        objects.append(
            b"<< /Length "
            + str(len(content)).encode()
            + b" >>\nstream\n"
            + content
            + b"\nendstream"
        )

    output = io.BytesIO()
    output.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(output.tell())
        output.write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")

    xref_offset = output.tell()
    output.write(f"xref\n0 {len(objects) + 1}\n".encode())
    output.write(b"0000000000 65535 f \n")
    for offset in offsets:
        output.write(f"{offset:010d} 00000 n \n".encode())
    output.write(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode()
    )
    return output.getvalue()


def make_rsa_certificate(
    *, common_name: str = "Test Signer", organization: str | None = None
) -> tuple[CertificateInfo, rsa.RSAPrivateKey]:
    """Create a self-signed RSA certificate and return it with its private key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attributes = [cryptography_x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.insert(
            0, cryptography_x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
        )
    name = cryptography_x509.Name(attributes)
    certificate = (
        cryptography_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cryptography_x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    return parse_certificate(der), key


def make_gost_certificate(
    *,
    common_name: str = "GOST Test Signer",
    organization: str | None = None,
    key_size: int = 256,
    curve_oid: str | None = None,
) -> tuple[CertificateInfo, bytes]:
    """Create a self-signed GOST certificate and return it with its private key."""
    if key_size not in (256, 512):
        raise ValueError("key_size must be 256 or 512")
    curve_oid = curve_oid or DEFAULT_GOST_CURVES[key_size]
    curve = CURVES[GOST_CURVE_OIDS[curve_oid]]
    mode = GOST_MODES[key_size]

    private_key = os.urandom(key_size // 8)
    public_key = bytes(
        gostsignature.new(mode, curve).public_key_generate(bytearray(private_key))
    )

    spki = GostPublicKeyInfo(
        {
            "algorithm": keys.PublicKeyAlgorithm(
                {
                    "algorithm": GOST_KEY_OIDS[key_size],
                    "parameters": core.ObjectIdentifier(curve_oid),
                }
            ),
            "public_key": b"\x04" + public_key,
        }
    )
    name_attributes: dict[str, str] = {"common_name": common_name, "country_name": "RU"}
    if organization:
        name_attributes["organization_name"] = organization
    name = x509.Name.build(name_attributes)
    signature_oid = GOST_SIGNATURE_OIDS[key_size]
    signature_algorithm = algos.SignedDigestAlgorithm(
        {"algorithm": signature_oid, "parameters": core.ObjectIdentifier(curve_oid)}
    )
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(os.urandom(8), "big") | (1 << 63),
            "signature": signature_algorithm,
            "issuer": name,
            "validity": {
                "not_before": core.UTCTime(
                    datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
                ),
                "not_after": core.UTCTime(
                    datetime.datetime(2034, 1, 1, tzinfo=datetime.UTC)
                ),
            },
            "subject": name,
            "subject_public_key_info": spki,
        }
    )
    digest_name = "streebog256" if key_size == 256 else "streebog512"
    digest = gosthash.new(digest_name, data=tbs.dump()).digest()
    signature = bytes(
        gostsignature.new(mode, curve).sign(bytearray(private_key), digest)
    )
    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": signature_algorithm,
            "signature_value": core.OctetBitString(signature),
        }
    )
    return parse_certificate(certificate.dump()), private_key
