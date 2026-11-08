"""Shared test fixtures and builders."""

from __future__ import annotations

import datetime
import hashlib
import io
import os

from asn1crypto import algos, cms, core, crl, keys, ocsp, tsp, x509
from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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


def sign_rsa(key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign ``data`` with RSA PKCS#1 v1.5 and SHA-256."""
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


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


def gost_sign(
    private_key: bytes,
    data: bytes,
    *,
    key_size: int = 256,
    curve_oid: str | None = None,
) -> bytes:
    """Подписать данные в конвенции КриптоПро: `s ‖ r`, дайджест little-endian."""
    curve_oid = curve_oid or DEFAULT_GOST_CURVES[key_size]
    curve = CURVES[GOST_CURVE_OIDS[curve_oid]]
    mode = GOST_MODES[key_size]
    digest_name = "streebog256" if key_size == 256 else "streebog512"
    digest = bytes(gosthash.new(digest_name, data=data).digest())
    raw = bytes(
        gostsignature.new(mode, curve).sign(
            bytearray(private_key), bytearray(digest[::-1])
        )
    )
    size = key_size // 8
    return raw[size:] + raw[:size]


def make_gost_certificate(
    *,
    common_name: str = "GOST Test Signer",
    organization: str | None = None,
    key_size: int = 256,
    curve_oid: str | None = None,
    issuer_cert_der: bytes | None = None,
    issuer_private_key: bytes | None = None,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    is_ca: bool = False,
    serial: int | None = None,
) -> tuple[CertificateInfo, bytes]:
    """Создать сертификат ГОСТ и вернуть его вместе с закрытым ключом.

    Без ``issuer_cert_der`` сертификат самоподписанный. Кодировка открытого
    ключа и подписи соответствует КриптоПро (RFC 4491).
    """
    if key_size not in (256, 512):
        raise ValueError("key_size must be 256 or 512")
    curve_oid = curve_oid or DEFAULT_GOST_CURVES[key_size]
    curve = CURVES[GOST_CURVE_OIDS[curve_oid]]
    mode = GOST_MODES[key_size]
    size = key_size // 8

    private_key = os.urandom(size)
    public_key = bytes(
        gostsignature.new(mode, curve).public_key_generate(bytearray(private_key))
    )
    point_le = public_key[:size][::-1] + public_key[size:][::-1]

    spki = GostPublicKeyInfo(
        {
            "algorithm": keys.PublicKeyAlgorithm(
                {
                    "algorithm": GOST_KEY_OIDS[key_size],
                    "parameters": core.ObjectIdentifier(curve_oid),
                }
            ),
            "public_key": b"\x04" + point_le,
        }
    )
    name_attributes: dict[str, str] = {"common_name": common_name, "country_name": "RU"}
    if organization:
        name_attributes["organization_name"] = organization
    subject = x509.Name.build(name_attributes)

    if issuer_cert_der is not None:
        issuer_cert = x509.Certificate.load(issuer_cert_der)
        issuer_name = issuer_cert.subject
        signing_key = issuer_private_key
        if signing_key is None:
            raise ValueError("issuer_private_key is required with issuer_cert_der")
    else:
        issuer_name = subject
        signing_key = private_key

    signature_oid = GOST_SIGNATURE_OIDS[key_size]
    signature_algorithm = algos.SignedDigestAlgorithm(
        {"algorithm": signature_oid, "parameters": core.ObjectIdentifier(curve_oid)}
    )
    not_before = not_before or datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
    not_after = not_after or datetime.datetime(2034, 1, 1, tzinfo=datetime.UTC)
    key_usage = {"digital_signature"}
    if is_ca:
        key_usage.add("key_cert_sign")
        key_usage.add("crl_sign")
    extensions = [
        x509.Extension(
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": x509.BasicConstraints({"ca": is_ca}),
            }
        ),
        x509.Extension(
            {
                "extn_id": "key_usage",
                "critical": True,
                "extn_value": x509.KeyUsage(key_usage),
            }
        ),
    ]
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial or int.from_bytes(os.urandom(8), "big") | (1 << 63),
            "signature": signature_algorithm,
            "issuer": issuer_name,
            "validity": {
                "not_before": core.UTCTime(not_before),
                "not_after": core.UTCTime(not_after),
            },
            "subject": subject,
            "subject_public_key_info": spki,
            "extensions": extensions,
        }
    )
    signature = gost_sign(
        signing_key, tbs.dump(), key_size=key_size, curve_oid=curve_oid
    )
    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": signature_algorithm,
            "signature_value": core.OctetBitString(signature),
        }
    )
    return parse_certificate(certificate.dump()), private_key


def make_gost_crl(
    *,
    issuer_cert_der: bytes,
    issuer_private_key: bytes,
    revoked_serials: tuple[int, ...] = (),
    this_update: datetime.datetime | None = None,
    next_update: datetime.datetime | None = None,
) -> bytes:
    """Собрать CRL, подписанный ключом издателя (конвенция КриптоПро)."""
    issuer = x509.Certificate.load(issuer_cert_der)
    issuer_info = parse_certificate(issuer_cert_der)
    key_size = issuer_info.key_size
    curve_oid = issuer_info.curve_oid or DEFAULT_GOST_CURVES[key_size]
    signature_oid = GOST_SIGNATURE_OIDS[key_size]
    signature_algorithm = algos.SignedDigestAlgorithm(
        {"algorithm": signature_oid, "parameters": core.ObjectIdentifier(curve_oid)}
    )
    this_update = this_update or datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    next_update = next_update or datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC)
    tbs = crl.TbsCertList(
        {
            "version": "v2",
            "signature": signature_algorithm,
            "issuer": issuer.subject,
            "this_update": core.UTCTime(this_update),
            "next_update": core.UTCTime(next_update),
            "revoked_certificates": [
                crl.RevokedCertificate(
                    {
                        "user_certificate": serial,
                        "revocation_date": core.UTCTime(
                            datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
                        ),
                    }
                )
                for serial in revoked_serials
            ],
        }
    )
    signature = gost_sign(
        issuer_private_key,
        tbs.dump(),
        key_size=key_size,
        curve_oid=curve_oid,
    )
    return crl.CertificateList(
        {
            "tbs_cert_list": tbs,
            "signature_algorithm": signature_algorithm,
            "signature": core.OctetBitString(signature),
        }
    ).dump()


SIGNING_TIME = datetime.datetime(2026, 11, 8, 12, 0, tzinfo=datetime.UTC)
SHA256_OID = "2.16.840.1.101.3.4.2.1"
STREEBOG256_OID = "1.2.643.7.1.1.2.2"
STREEBOG512_OID = "1.2.643.7.1.1.2.3"
GOST_SIGNATURE_256_OID = "1.2.643.7.1.1.3.2"
GOST_SIGNATURE_512_OID = "1.2.643.7.1.1.3.3"


def _cms_attributes(message_digest: bytes) -> cms.CMSAttributes:
    return cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [message_digest]}),
            cms.CMSAttribute(
                {
                    "type": "signing_time",
                    "values": [cms.Time({"utc_time": core.UTCTime(SIGNING_TIME)})],
                }
            ),
        ]
    )


def _signed_data(
    *, certificate_der: bytes, signer_info: cms.SignerInfo, digest_oid: str
) -> bytes:
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": digest_oid})],
            "encap_content_info": {"content_type": "data"},
            "certificates": [x509.Certificate.load(certificate_der)],
            "signer_infos": [signer_info],
        }
    )
    return cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    ).dump()


def make_rsa_cms(
    *,
    data: bytes = b"payload",
    signer: tuple[CertificateInfo, rsa.RSAPrivateKey] | None = None,
) -> tuple[bytes, CertificateInfo, bytes]:
    """Build a detached RSA CMS over ``data``."""
    info, key = signer if signer is not None else make_rsa_certificate()
    attributes = _cms_attributes(hashlib.sha256(data).digest())
    asn1_certificate = x509.Certificate.load(info.der)
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": asn1_certificate.issuer,
                            "serial_number": asn1_certificate.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": SHA256_OID}),
            "signed_attrs": attributes,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": "sha256_rsa"}
            ),
            "signature": key.sign(
                attributes.dump(), padding.PKCS1v15(), hashes.SHA256()
            ),
        }
    )
    return (
        _signed_data(
            certificate_der=info.der, signer_info=signer_info, digest_oid=SHA256_OID
        ),
        info,
        data,
    )


def make_gost_cms(
    *,
    data: bytes = b"payload",
    signer: tuple[CertificateInfo, bytes] | None = None,
) -> tuple[bytes, CertificateInfo, bytes]:
    """Собрать отсоединённую подпись CAdES-BES ГОСТ над ``data``."""
    info, private_key = signer if signer is not None else make_gost_certificate()
    key_size = info.key_size
    curve_oid = info.curve_oid or DEFAULT_GOST_CURVES[key_size]
    digest_name = "streebog256" if key_size == 256 else "streebog512"
    digest_oid = STREEBOG256_OID if key_size == 256 else STREEBOG512_OID
    signature_oid = (
        GOST_SIGNATURE_256_OID if key_size == 256 else GOST_SIGNATURE_512_OID
    )
    attributes = _cms_attributes(bytes(gosthash.new(digest_name, data=data).digest()))
    signature = gost_sign(
        private_key,
        attributes.dump(),
        key_size=key_size,
        curve_oid=curve_oid,
    )
    asn1_certificate = x509.Certificate.load(info.der)
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": asn1_certificate.issuer,
                            "serial_number": asn1_certificate.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": digest_oid}),
            "signed_attrs": attributes,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": signature_oid}
            ),
            "signature": signature,
        }
    )
    return (
        _signed_data(
            certificate_der=info.der,
            signer_info=signer_info,
            digest_oid=digest_oid,
        ),
        info,
        data,
    )


def _gost_hash(name: str, data: bytes) -> bytes:
    if name in ("streebog256", "streebog512"):
        return bytes(gosthash.new(name, data=data).digest())
    return hashlib.new(name, data).digest()


def make_gost_ocsp(
    *,
    issuer_cert_der: bytes,
    issuer_private_key: bytes,
    target_cert_der: bytes,
    status: str = "good",
    hash_name: str = "streebog256",
    this_update: datetime.datetime | None = None,
    next_update: datetime.datetime | None = None,
    produced_at: datetime.datetime | None = None,
) -> bytes:
    """Собрать ответ OCSP, подписанный ключом издателя."""
    issuer = x509.Certificate.load(issuer_cert_der)
    target = x509.Certificate.load(target_cert_der)
    issuer_info = parse_certificate(issuer_cert_der)
    key_size = issuer_info.key_size
    curve_oid = issuer_info.curve_oid or DEFAULT_GOST_CURVES[key_size]
    signature_oid = GOST_SIGNATURE_OIDS[key_size]

    hash_oid = {
        "streebog256": STREEBOG256_OID,
        "streebog512": STREEBOG512_OID,
        "sha1": "1.3.14.3.2.26",
        "sha256": "2.16.840.1.101.3.4.2.1",
    }[hash_name]
    spki_der = issuer["tbs_certificate"]["subject_public_key_info"].dump()
    spki_bits = bytes(GostPublicKeyInfo.load(spki_der)["public_key"].native)

    cert_id = ocsp.CertId(
        {
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_oid}),
            "issuer_name_hash": _gost_hash(hash_name, issuer.subject.dump()),
            "issuer_key_hash": _gost_hash(hash_name, spki_bits),
            "serial_number": target.serial_number,
        }
    )
    if status == "revoked":
        cert_status = ocsp.CertStatus(
            {
                "revoked": ocsp.RevokedInfo(
                    {
                        "revocation_time": core.GeneralizedTime(
                            datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
                        )
                    }
                )
            }
        )
    elif status == "unknown":
        cert_status = ocsp.CertStatus({"unknown": None})
    else:
        cert_status = ocsp.CertStatus({"good": None})

    this_update = this_update or datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    next_update = next_update or datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC)
    produced_at = produced_at or this_update

    tbs = ocsp.ResponseData(
        {
            "version": "v1",
            "responder_id": ocsp.ResponderId({"by_name": issuer.subject}),
            "produced_at": core.GeneralizedTime(produced_at),
            "responses": [
                ocsp.SingleResponse(
                    {
                        "cert_id": cert_id,
                        "cert_status": cert_status,
                        "this_update": core.GeneralizedTime(this_update),
                        "next_update": core.GeneralizedTime(next_update),
                    }
                )
            ],
        }
    )
    signature = gost_sign(
        issuer_private_key,
        tbs.dump(),
        key_size=key_size,
        curve_oid=curve_oid,
    )
    basic = ocsp.BasicOCSPResponse(
        {
            "tbs_response_data": tbs,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {
                    "algorithm": signature_oid,
                    "parameters": core.ObjectIdentifier(curve_oid),
                }
            ),
            "signature": core.OctetBitString(signature),
        }
    )
    response = ocsp.OCSPResponse(
        {
            "response_status": "successful",
            "response_bytes": ocsp.ResponseBytes(
                {
                    "response_type": "basic_ocsp_response",
                    "response": basic,
                }
            ),
        }
    )
    return response.dump()


TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"


def make_gost_timestamp(
    *,
    signature_value: bytes,
    tsa_cert_der: bytes,
    tsa_private_key: bytes,
    gen_time: datetime.datetime | None = None,
    hash_name: str = "streebog256",
) -> bytes:
    """??????? ????? ??????? CAdES-T ??? ????????? ???????."""
    tsa = x509.Certificate.load(tsa_cert_der)
    info = parse_certificate(tsa_cert_der)
    key_size = info.key_size
    curve_oid = info.curve_oid or DEFAULT_GOST_CURVES[key_size]
    signature_oid = GOST_SIGNATURE_OIDS[key_size]
    hash_oid = {
        "streebog256": STREEBOG256_OID,
        "streebog512": STREEBOG512_OID,
        "sha256": "2.16.840.1.101.3.4.2.1",
    }[hash_name]
    gen_time = gen_time or datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)

    tst_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.1",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_oid}),
                    "hashed_message": _gost_hash(hash_name, signature_value),
                }
            ),
            "serial_number": int.from_bytes(os.urandom(4), "big"),
            "gen_time": core.GeneralizedTime(gen_time),
        }
    )
    attributes = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": [TST_INFO_OID]}),
            cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [_gost_hash(hash_name, tst_info.dump())],
                }
            ),
            cms.CMSAttribute(
                {
                    "type": "signing_time",
                    "values": [cms.Time({"utc_time": core.UTCTime(gen_time)})],
                }
            ),
        ]
    )
    signature = gost_sign(
        tsa_private_key,
        attributes.dump(),
        key_size=key_size,
        curve_oid=curve_oid,
    )
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": tsa.issuer,
                            "serial_number": tsa.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": hash_oid}),
            "signed_attrs": attributes,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": signature_oid}
            ),
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": hash_oid})],
            "encap_content_info": cms.EncapsulatedContentInfo(
                {"content_type": TST_INFO_OID, "content": tst_info}
            ),
            "certificates": [tsa],
            "signer_infos": [signer_info],
        }
    )
    return cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    ).dump()


def add_cms_timestamp(cms_der: bytes, token_der: bytes) -> bytes:
    """???????? ????? ??????? ? unsigned-???????? ?????????? CMS."""
    content_info = cms.ContentInfo.load(cms_der)
    signer_info = content_info["content"]["signer_infos"][0]
    token = cms.ContentInfo.load(token_der)
    signer_info["unsigned_attrs"] = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {
                    "type": "signature_time_stamp_token",
                    "values": [token],
                }
            )
        ]
    )
    return content_info.dump()
