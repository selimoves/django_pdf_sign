The files in this directory are the official test fixtures published by
CryptoPro in the pycades repository:

  https://github.com/CryptoPro/pycades/tree/main/tests/fixtures

- `pycades-root.cer` — root CA certificate for GOST R 34.10-2012 test signing.
- `pycades-root.crl` — the matching certificate revocation list.

They are used only to verify that django-pdf-sign parses real GOST
certificates. They are not trust anchors and must never be trusted in
production.

Copyright (c) 2026, CryptoPro LLC. Distributed under the BSD 3-Clause license
of the pycades repository. See the upstream repository for the full license
text.
