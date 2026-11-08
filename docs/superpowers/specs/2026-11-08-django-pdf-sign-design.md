# django-pdf-sign — design

Date: 2026-11-08
Status: approved for implementation

## 1. Intent

Django package for **client-side** electronic signatures of PDF documents.

The server never holds private keys. It prepares a PDF with a visible stamp,
hands the exact bytes to sign to the browser (CryptoPro Browser Plug-in),
verifies the returned detached CMS, and embeds it into the PDF.

Supported signature types:

- **GOST 34.10-2012 / CAdES-BES** — Russian qualified signatures
  (Streebog-256/512). Intended to be verifiable in Russian validators
  (Gosuslugi, CryptoPro) when the signer holds a qualified certificate.
- **PAdES / RSA-ECDSA** — Adobe-compatible signatures.

The package does **not** make a signature legally valid. Legal validity comes
from the signer's certified cryptographic provider (СКЗИ) and qualified
certificate. See `docs/legal.md`.

## 2. Goals

- A small, dependable server-side core that works with keys held on the client.
- Correct handling of the PDF `/ByteRange`, placeholder sizing, and embedding.
- Server-side verification that the CMS covers exactly the bytes that were
  handed to the client, and that the signer certificate matches the session.
- Configurable visible stamp following Russian practice (ГОСТ Р 7.0.97-2016
  and EDI operator conventions).
- A Django layer: models, admin, settings, cleanup command. No views, no DRF.
- Distribution on PyPI as `django-pdf-sign`, installable with plain `pip`
  (no CryptoPro on the server).

## 3. Non-goals (v1)

- Server-side signing (private keys on the server).
- Views, DRF serializers, URLs, templates.
- Trust chain validation, OCSP/CRL, RFC 3161 timestamps.
- PDF/A, multiple signatures in one user flow, mobile clients.
- Replacing the client's cryptographic provider.

## 4. Protocol

Three steps. Full HTTP-level contract in `docs/protocol.md`.

### Step 1 — certificate

The client exports its signing certificate (DER, base64) and sends it to the
server. The certificate is needed **before** hashing because the stamp shows
the signer's name, certificate serial and validity, and any change to the PDF
after hashing would invalidate the signature.

### Step 2 — prepare

`prepare_signing()`:

1. Parse the certificate (`asn1crypto`): subject, common name, organization,
   serial, validity, SHA-256 thumbprint, key algorithm OID, curve OID, public
   key.
2. Choose the digest: Streebog-256/512 for GOST keys, SHA-256 otherwise.
3. Create the signature field and stamp, write a placeholder, compute the
   `/ByteRange` (via pyHanko's `PdfCMSEmbedder`).
4. Recompute the digest over the exact `/ByteRange` bytes with our own digest
   implementation (pyHanko cannot hash Streebog).
5. Persist a `SigningSession` with the prepared PDF, offsets, certificate and
   expiry.
6. Return the bytes to sign, the digest algorithm, the session id and expiry.

### Step 3 — sign (client)

The browser signs the received bytes with the CryptoPro Browser Plug-in:
`CadesSignedData.SignCades(signer, CADESCOM_CADES_BES, true)` (detached CMS).
It sends the CMS (base64) back.

### Step 4 — complete

`complete_signing()`:

1. Lock the session row (`select_for_update`), check status, expiry and user.
2. Parse the CMS, extract the signer certificate, `messageDigest`, signature
   and signed attributes.
3. Check the certificate thumbprint equals the session's.
4. Check `messageDigest` equals our digest of the stored bytes to sign.
5. Verify the signature over the signed attributes with `gostcrypto` (GOST) or
   `cryptography` (RSA/ECDSA).
6. Embed the CMS into the placeholder, store the signed PDF, create an
   immutable `SignatureRecord`, mark the session completed.

## 5. Package layout

```
src/django_pdf_sign/
  __init__.py            version
  apps.py                AppConfig
  conf.py                settings namespace, defaults, accessor
  constants.py           enums, OIDs, algorithm names
  exceptions.py          exception hierarchy
  models.py              SigningSession, SignatureRecord
  admin.py               read-only admin
  migrations/
  services/
    prepare.py           prepare_signing()
    complete.py          complete_signing()
    verify.py            verify_cms_over_bytes(), verify_signed_pdf()
  pdf/
    embedder.py          prepare_document(), embed_cms()
    stamp.py             StampConfig, build_stamp_style(), text params
  crypto/
    certs.py             parse_certificate()
    cms.py               parse_cms()
    digest.py            digest_for(), algorithm_for_key()
    gost.py              verify_gost()
    pades.py             verify_pades()
    oids.py              GOST OIDs, curve OIDs
  fonts/
    DejaVuSans.ttf
    LICENSE.DejaVu
  management/commands/pdf_sign_cleanup.py
```

## 6. Public API

```python
from django_pdf_sign.services import (
    prepare_signing, complete_signing,
    verify_cms_over_bytes, verify_signed_pdf,
)

prepared = prepare_signing(
    document=invoice,
    file_field="file",
    user=request.user,
    certificate_der=cert_der,
    page=-1,
    box=(57, 57, 284, 170),
)
# prepared.session, prepared.bytes_to_sign, prepared.digest_algorithm,
# prepared.expires_at

result = complete_signing(
    session_id=prepared.session.pk,
    cms=cms_bytes,
    user=request.user,
)
# result.record, result.signed_pdf
```

Return types are frozen dataclasses so callers can rely on names.

## 7. Django layer

### Models

`SigningSession` (UUID primary key) holds one in-flight signing:

- generic relation to the document (`content_type`, `object_id`, `document`);
- `user` (nullable);
- certificate metadata (DER, subject, common name, organization, serial,
  thumbprint, validity);
- `digest_algorithm`, `subfilter`, `field_name`, `page`, `box`,
  `bytes_reserved`;
- `prepared_pdf` (`FileField`), `reserved_region_start`,
  `reserved_region_end`;
- `status` (`prepared` / `completed` / `failed` / `expired`), `created_at`,
  `expires_at`, `completed_at`, `error`, `metadata`.

`SignatureRecord` is the immutable audit row: one-to-one to the session,
certificate metadata, digest algorithm, subfilter, CMS size, verification
status and details, signed PDF.

### Admin

Read-only: list, filter by status/algorithm/date, search by subject/serial/
thumbprint. No add, no change of signed data. A manual "mark expired" action
is out of scope for v1.

### Settings

```python
DJANGO_PDF_SIGN = {
    "SESSION_TTL": 900,
    "BYTES_RESERVED": 16384,
    "MAX_DOCUMENT_BYTES": 25 * 1024 * 1024,
    "DEFAULT_PAGE": -1,
    "DEFAULT_BOX": (57, 57, 284, 170),
    "SUBFILTER": None,
    "STAMP": {
        "TEXT": DEFAULT_STAMP_TEXT,
        "FONT_PATH": None,
        "FONT_SIZE": 7,
        "BORDER_WIDTH": 1,
        "BACKGROUND_PATH": None,
    },
    "PREPARED_UPLOAD_TO": "django_pdf_sign/prepared/%Y/%m/%d",
    "SIGNED_UPLOAD_TO": "django_pdf_sign/signed/%Y/%m/%d",
}
```

Unknown keys raise `ImproperlyConfigured` on first access. `FONT_PATH=None`
means the bundled DejaVu Sans.

### Cleanup

`python manage.py pdf_sign_cleanup` marks expired `prepared` sessions as
`expired`, deletes their prepared files, and deletes expired sessions older
than a retention window. Supports `--dry-run`.

## 8. Cryptography

### Certificate parsing

`asn1crypto.x509.Certificate` for the certificate body. The GOST public key
lives in `SubjectPublicKeyInfo` as a BIT STRING wrapping a DER OCTET STRING of
`0x04 || X || Y`; `asn1crypto`'s default `PublicKeyInfo` rejects unknown
algorithm OIDs, so a small subclass with an explicit `public_key` spec is used
for the SPKI. Verified in the spike.

Detected algorithms:

- key OID `1.2.643.7.1.1.1.1` → GOST 2012-256, digest `streebog256`;
- key OID `1.2.643.7.1.1.1.2` → GOST 2012-512, digest `streebog512`;
- RSA/EC OIDs → `sha256`.

### Digest

- `streebog256` / `streebog512` → `gostcrypto.gosthash`.
- `sha256` → `hashlib`.

The `/ByteRange` bytes are `pdf[:start] + pdf[end:]`, matching pyHanko's
definition exactly.

### Verification

- GOST: `gostcrypto.gostsignature.new(MODE_256/512, curve)` with the curve
  selected by the certificate's parameter OID
  (`CURVES_R_1323565_1_024_2019`); public key = `X || Y` (the `0x04` point
  prefix stripped).
- PAdES: `cryptography` `public_key.verify(signature, signed_attrs_der, ...)`.
- Signed attributes are verified in their `SET OF` encoding: the CMS encodes
  them implicitly tagged (`0xA0`), the signature covers `0x31 || ...`.

### What is checked

- `messageDigest` equals our digest of the stored bytes to sign;
- certificate thumbprint equals the session's;
- the cryptographic signature over the signed attributes is valid;
- session is not expired, not reused, belongs to the caller.

### What is not checked

Trust chain, revocation, timestamp. Documented as an explicit non-goal; a
`Verifier` extension point is left for later.

## 9. Stamp

Default template:

```
ДОКУМЕНТ ПОДПИСАН
ЭЛЕКТРОННОЙ ПОДПИСЬЮ
Сертификат: %(serial)s
Владелец: %(signer)s
Действителен: с %(valid_from)s до %(valid_to)s
```

- `%(signer)s` — common name, or organization + common name when both exist.
- `%(serial)s` — uppercase hex serial.
- `%(valid_from)s`, `%(valid_to)s` — `DD.MM.YYYY`.
- Optional `%(ts)s` — signing time.
- Font: bundled DejaVu Sans (Cyrillic).
- Placement: last page (`page=-1`) by default, box `(57, 57, 284, 170)`
  (80×40 mm, 20 mm from the bottom-left corner).
- Background image and custom text via settings.

Rationale and standard references in `docs/stamp.md`.

## 10. Packaging and quality gates

- `pyproject.toml` (hatchling), Python ≥ 3.11, Django ≥ 4.2.
- Runtime dependencies: `django`, `pyhanko[opentype]`, `asn1crypto`,
  `cryptography`, `gostcrypto`.
- Optional: `qr` extra.
- ruff (lint + format), mypy strict, pytest + pytest-django.
- CI matrix: Python 3.11/3.12/3.13 × Django 4.2/5.2/6.1 (where compatible),
  Linux and Windows.
- Build with `uv build`, check with `twine check`.

## 11. Test strategy

- **PAdES end-to-end**: self-signed RSA certificate, prepare → sign → complete
  → validate with pyHanko. Proven in the spike.
- **GOST end-to-end**: generated GOST certificate and CMS, prepare → sign →
  complete → verify with our verifier. Proven in the spike.
- **Negative cases**: tampered bytes, wrong certificate, expired session,
  reused session, wrong user, oversized document, malformed CMS.
- **Fixtures**: generated deterministically per test run; CryptoPro's official
  test root certificate and CRL vendored for parsing/chain tests. Provenance in
  `docs/fixtures.md`.
- Real CryptoPro CMS interop is an integration test guarded by an environment
  variable; it cannot run in CI without the CSP.

## 12. Risks

| Risk | Mitigation |
|---|---|
| pyHanko internal API changes | isolate in `pdf/embedder.py`, pin `<0.39`, integration tests |
| GOST CMS differs from CryptoPro output | verify against a real CryptoPro fixture in an optional integration test; fail closed |
| Streebog slower than SHA | benchmark; document limits; `MAX_DOCUMENT_BYTES` |
| Large PDFs in memory | v1 limit plus documented limit; streaming later |
| SubFilter expectations differ between validators | configurable, default `adbe.pkcs7.detached` for GOST |
| Legal validity misunderstood | explicit `docs/legal.md` |

## 13. Decisions recorded

- Client-side keys only; no server signing in v1.
- Client returns a complete detached CMS; the server does not build CMS from a
  raw signature.
- Server verifies the CMS itself with `gostcrypto`, no CryptoPro on the server.
- Package ships services and models, not views.
- Package name `django-pdf-sign`.
- Stamp carries certificate data, therefore the certificate is sent in step 1.
