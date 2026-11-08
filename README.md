# django-pdf-sign

Client-side electronic signatures for PDF documents in Django.

The server never holds private keys. It prepares a PDF with a visible stamp,
hands the exact bytes to sign to the browser (CryptoPro Browser Plug-in),
verifies the returned detached CMS, and embeds it.

- **GOST 34.10-2012 / CAdES-BES** — Russian qualified signatures
  (Streebog-256/512), verifiable in Russian validators when the signer holds a
  qualified certificate.
- **PAdES / RSA-ECDSA** — Adobe-compatible signatures.

> Status: early development. The public API is not stable yet.

## Install

```bash
pip install django-pdf-sign
```

The server needs no CryptoPro installation: verification is done with
`gostcrypto` and `cryptography`.

## Quick start

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "django.contrib.contenttypes",
    "django_pdf_sign",
]
```

```python
from django_pdf_sign.services import prepare_signing, complete_signing

# Step 1: the browser sends its certificate; prepare the document.
prepared = prepare_signing(
    document=invoice,
    user=request.user,
    certificate_der=certificate_der,   # DER bytes from the browser
    page=-1,                            # last page
    box=(57, 57, 284, 170),             # 80x40 mm, 20 mm margins
)

# Step 2: send to the browser.
response = {
    "session_id": str(prepared.session.pk),
    "bytes_to_sign": base64.b64encode(prepared.bytes_to_sign).decode(),
    "digest_algorithm": prepared.digest_algorithm,
    "expires_at": prepared.expires_at.isoformat(),
}

# Step 3: the browser returns a detached CMS; verify and embed it.
result = complete_signing(
    session_id=prepared.session.pk,
    cms=cms_bytes,
    user=request.user,
)
result.signed_pdf      # bytes of the signed PDF
result.record          # immutable SignatureRecord
```

## What it does

- Adds a signature field and a Russian-style stamp to the PDF.
- Returns the exact `/ByteRange` bytes to sign.
- Verifies that the CMS covers those bytes, that the certificate matches the
  session and that the signature is cryptographically valid.
- Embeds the CMS, stores the signed PDF and writes an audit record.
- Expires abandoned sessions (`python manage.py pdf_sign_cleanup`).

## What it does not do

- Hold, receive or log private keys, PINs or key containers.
- Validate trust chains, OCSP/CRL or timestamps in version 1.
- Provide views or DRF endpoints; your application owns URLs and permissions.
- Make a signature legally valid. That requires a qualified certificate and a
  certified cryptographic provider on the signer's side.

## Settings

```python
DJANGO_PDF_SIGN = {
    "SESSION_TTL": 900,
    "BYTES_RESERVED": 16384,
    "MAX_DOCUMENT_BYTES": 25 * 1024 * 1024,
    "DEFAULT_PAGE": -1,
    "DEFAULT_BOX": (57, 57, 284, 170),
    "SUBFILTER": None,
    "STAMP": {
        "TEXT": "...",
        "FONT_PATH": None,
        "FONT_SIZE": 7,
        "BORDER_WIDTH": 1,
        "BACKGROUND_PATH": None,
    },
    "PREPARED_UPLOAD_TO": "django_pdf_sign/prepared/%Y/%m/%d",
    "SIGNED_UPLOAD_TO": "django_pdf_sign/signed/%Y/%m/%d",
}
```

## Documentation

- [Protocol](docs/protocol.md) — server/client contract and browser example.
- [Stamp](docs/stamp.md) — default template, placement, configuration.
- [Legal validity](docs/legal.md) — what makes a signature valid, and what this
  package does not do.
- [Fixtures](docs/fixtures.md) — test certificate provenance.

## Requirements

- Python 3.11+
- Django 4.2+
- `pyhanko[opentype]`, `asn1crypto`, `cryptography`, `gostcrypto`

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python -m mypy
uv build
```

## License

MIT. The bundled DejaVu Sans font is distributed under the Bitstream Vera
license; see `src/django_pdf_sign/fonts/LICENSE.DejaVu`.
