# django-pdf-sign

Client-side electronic signatures for PDF documents in Django.

The server never holds private keys. It prepares a PDF with a visible stamp,
hands the exact bytes to sign to the browser (CryptoPro Browser Plug-in),
verifies the returned detached CMS, and embeds it.

- **GOST 34.10-2012 / CAdES-BES** — Russian qualified signatures.
- **PAdES / RSA-ECDSA** — Adobe-compatible signatures.

> Status: early development. The public API is not stable yet.

## Documentation

- `docs/protocol.md` — server/client contract.
- `docs/legal.md` — what makes a signature legally valid.
- `docs/fixtures.md` — test certificate provenance.
