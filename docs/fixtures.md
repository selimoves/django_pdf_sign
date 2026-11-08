# Test fixtures

## Generated fixtures

Most tests build their own material in `tests/helpers.py`:

- `make_rsa_certificate()` — a self-signed RSA-2048 certificate and key.
- `make_gost_certificate(key_size=256|512, curve_oid=...)` — a self-signed
  GOST 34.10-2012 certificate and private key, built with `asn1crypto` and
  signed with `gostcrypto`.
- `make_rsa_cms()` / `make_gost_cms()` — detached CAdES-BES containers over
  arbitrary bytes.
- `minimal_pdf(pages=1)` — a valid, minimal PDF.

They are deterministic in shape, random in key material, and regenerated on
every test run. No private key is ever committed.

## CryptoPro official fixtures

`tests/fixtures/crypto/` contains the official CryptoPro test material from
`https://github.com/CryptoPro/pycades/tree/main/tests/fixtures`:

- `pycades-root.cer` — root CA certificate for GOST R 34.10-2012 test signing;
- `pycades-root.crl` — the matching revocation list.

They are used only to prove that the parser handles a real CryptoPro-issued
certificate: a `SEQUENCE` of curve parameters and a public key point encoded
without the `0x04` prefix. They are **not** trust anchors and must never be
trusted in production.

Copyright (c) 2026, CryptoPro LLC. Distributed under the BSD 3-Clause license
of the pycades repository.

The upstream repository also ships `pycades-test.pfx`, a password-protected
container with a private key. It is deliberately **not** vendored here. If you
need a real CryptoPro CMS for an interoperability test, generate one locally:

1. run a container with CryptoPro CSP (the `php-pdf-cryptopro` repository has a
   working Docker recipe);
2. install `pycades-test.pfx` with `certmgr -install -pfx`;
3. sign a PDF with `pycades` or `cryptcp`;
4. commit only the resulting **signed PDF**, never the container or the key.

Such an integration test must be guarded by an environment variable and skipped
in CI, because CI has no CryptoPro CSP.

## Regenerating

Generated fixtures need no regeneration. Official fixtures are copied verbatim
from the upstream repository; update them by replacing the two files and
re-running `uv run pytest tests/test_fixtures.py`.
