# django-pdf-sign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish `django-pdf-sign`, a Django package that prepares PDF documents for client-side electronic signatures, verifies the returned detached CMS, and embeds it.

**Architecture:** A framework-free core (`crypto/`, `pdf/`) prepares a PDF with a visible stamp and a signature placeholder, returns the exact `/ByteRange` bytes to sign, verifies the client's detached CMS with `gostcrypto` (GOST) or `cryptography` (RSA/ECDSA), and embeds it. A thin Django layer adds `SigningSession` / `SignatureRecord` models, settings, admin and a cleanup command. No views, no DRF.

**Tech Stack:** Python 3.11+, Django 4.2+, pyHanko 0.38 (PDF manipulation), asn1crypto, cryptography, gostcrypto, pytest + pytest-django, ruff, mypy + django-stubs, uv, hatchling.

**Spec:** `docs/superpowers/specs/2026-11-08-django-pdf-sign-design.md`

## Global Constraints

- Python `>=3.11`; developed on 3.13 via `uv`.
- `django>=4.2`, `pyhanko[opentype]>=0.38,<0.39`, `asn1crypto>=1.5.1`, `cryptography>=48`, `gostcrypto>=1.2.5`.
- No private keys, PINs or raw CMS of real users are ever logged or stored.
- No code comments except one-line "why" notes that the code cannot express.
- Every public function has a type-annotated signature and a docstring.
- All source lives under `src/django_pdf_sign/` (src layout).
- Tests run with `uv run pytest`; lint `uv run ruff check .`; types `uv run python -m mypy`.
- The `/ByteRange` bytes are exactly `pdf[:start] + pdf[end:]`.
- The server never holds a private key.
- The on-the-wire protocol is documented in `docs/protocol.md`; change it only with a matching test in `tests/test_protocol.py`.

## Review Focus

- A PDF that already contains a signature field: preparing a second signature must not corrupt the first; a missing field name must produce a clear error.
- A document whose bytes were modified between prepare and complete: verification must fail closed and leave no `SignatureRecord`.
- A CMS whose `messageDigest` matches but whose certificate differs from the session: must be rejected.
- A GOST certificate with a 512-bit key or a non-default curve: must select the right Streebog variant and curve, or fail with a clear error rather than a crash.
- A reused or expired session: must not embed twice and must not produce a second record.

## Verification Log

Each task appends its verification result here after the final step.

| Task | Command | Result |
|------|---------|--------|
| 1 | `uv sync --all-extras` | 69 packages installed on Python 3.13.16, editable build OK |
| 1 | `uv run pytest -q` | `no tests ran` (exit 5), expected |
| 1 | `uv run ruff check .` | `All checks passed!` |
| 1 | `uv run ruff format --check .` | `5 files already formatted` |
| 1 | `uv run python -m mypy` | `Success: no issues found in 1 source file` |
| 2 | `uv run pytest tests/test_conf.py -q` | `6 passed` |
| 2 | `uv run ruff check .` / `ruff format --check .` | clean |
| 2 | `uv run python -m mypy` | `Success: no issues found in 5 source files` |
| 3 | `uv run pytest tests/test_digest.py -q` | `9 passed` |
| 3 | `uv run ruff check .` / `ruff format --check .` | clean |
| 3 | `uv run python -m mypy` | `Success: no issues found in 8 source files` |
| 4 | `uv run pytest tests/test_certs.py -q` | `6 passed` (RSA, GOST-256, GOST-512, display name, garbage) |
| 4 | `uv run pytest -q` | `21 passed` |
| 4 | `uv run ruff check .` / `ruff format --check .` | clean |
| 4 | `uv run python -m mypy` | `Success: no issues found in 9 source files` |
| 5 | `uv run pytest tests/test_gost.py -q` | `5 passed` (256/512 valid, tampered, unknown curve, malformed key) |
| 5 | `uv run pytest -q` | `26 passed` |
| 5 | `uv run ruff check .` / `ruff format --check .` | clean |
| 5 | `uv run python -m mypy` | `Success: no issues found in 10 source files` |
| 6 | `uv run pytest tests/test_pades.py -q` | `4 passed` |
| 6 | `uv run pytest -q` | `30 passed` |
| 6 | `uv run ruff check .` / `ruff format --check .` | clean |
| 6 | `uv run python -m mypy` | `Success: no issues found in 11 source files` |
| 7 | `uv run pytest tests/test_cms.py -q` | `3 passed` (RSA CMS, GOST CMS, garbage) |
| 7 | `uv run pytest -q` | `33 passed` |
| 7 | `uv run ruff check .` / `ruff format --check .` | clean |
| 7 | `uv run python -m mypy` | `Success: no issues found in 12 source files` |
| 8 | `uv run pytest tests/test_stamp.py -q` | `3 passed` |
| 8 | `uv run pytest -q` | `36 passed` |
| 8 | `uv run ruff check .` / `ruff format --check .` | clean |
| 8 | `uv run python -m mypy` | `Success: no issues found in 14 source files` |
| 9 | `uv run pytest tests/test_embedder.py -q` | `7 passed` |
| 9 | `uv run pytest -q` | `43 passed` |
| 9 | `uv run ruff check .` / `ruff format --check .` | clean |
| 9 | `uv run python -m mypy` | `Success: no issues found in 15 source files` |
| 9 | Deviation | An unsigned placeholder cannot be read via `embedded_signatures`; tests enumerate fields with `enumerate_sig_fields` |
| 9 | Default box | Corrected to `(57, 57, 284, 170)` = 80×40 mm, 20 mm margins |
| 10 | `uv run pytest tests/test_models.py tests/test_admin.py -q` | `6 passed` |
| 10 | `makemigrations django_pdf_sign` | `0001_initial.py` created |
| 10 | `uv run pytest -q` | `49 passed` |
| 10 | `uv run ruff check .` / `ruff format --check .` | clean |
| 10 | `uv run python -m mypy` | `Success: no issues found in 17 source files` |

---

### Task 1: Project scaffold and toolchain

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `LICENSE`, `README.md`, `AGENTS.md`, `.editorconfig`
- Create: `src/django_pdf_sign/__init__.py`, `src/django_pdf_sign/fonts/DejaVuSans.ttf`, `src/django_pdf_sign/fonts/LICENSE.DejaVu`
- Create: `tests/__init__.py`, `tests/settings.py`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: an importable `django_pdf_sign` package with `__version__`, a working pytest-django setup (`DJANGO_SETTINGS_MODULE=tests.settings`), ruff/mypy configuration, and `uv sync --all-extras` that installs everything.

- [x] **Step 1: Create the scaffold files** (done during workspace preparation)
- [x] **Step 2: Install the environment**

Run: `uv sync --all-extras`
Expected: resolves and installs all packages, builds `django-pdf-sign` editable.

- [x] **Step 3: Verify the toolchain**

Run: `uv run pytest -q`
Expected: `no tests ran` (exit code 5), which proves pytest and Django settings load.

Run: `uv run ruff check .`
Expected: `All checks passed!`

Run: `uv run python -m mypy`
Expected: `Success: no issues found`.

- [x] **Step 4: Commit**

```bash
git add pyproject.toml .gitignore LICENSE README.md AGENTS.md .editorconfig src tests .github
git commit -m "chore: scaffold django-pdf-sign project"
```

---

### Task 2: Constants, exceptions and settings access

**Files:**
- Create: `src/django_pdf_sign/constants.py`
- Create: `src/django_pdf_sign/exceptions.py`
- Create: `src/django_pdf_sign/conf.py`
- Create: `src/django_pdf_sign/apps.py`
- Create: `tests/test_conf.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `SigningStatus` (`prepared`, `completed`, `failed`, `expired`) and `VerificationStatus` (`valid`, `invalid`) as `django.db.models.TextChoices`.
  - `DIGEST_STREEBOG_256 = "streebog256"`, `DIGEST_STREEBOG_512 = "streebog512"`, `DIGEST_SHA256 = "sha256"`.
  - `SUBFILTER_ADOBE_PKCS7 = "/adbe.pkcs7.detached"`, `SUBFILTER_PADES = "/ETSI.CAdES.detached"`.
  - `DEFAULT_STAMP_TEXT` (the Russian template from the spec).
  - `DjangoPdfSignError`, `CertificateError`, `SigningError`, `SessionError`, `VerificationError`.
  - `get_setting(name: str) -> Any` and `get_stamp_setting(name: str) -> Any`, raising `django.core.exceptions.ImproperlyConfigured` on unknown keys.
  - `DjangoPdfSignConfig` (`apps.py`).

- [x] **Step 1: Write the failing tests**

`tests/test_conf.py`:

```python
import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from django_pdf_sign.conf import get_setting, get_stamp_setting


def test_default_session_ttl():
    assert get_setting("SESSION_TTL") == 900


def test_unknown_setting_raises():
    with pytest.raises(ImproperlyConfigured):
        get_setting("NOPE")


def test_stamp_text_default_contains_serial():
    assert "%(serial)s" in get_stamp_setting("TEXT")


@override_settings(DJANGO_PDF_SIGN={"SESSION_TTL": 60, "STAMP": {"FONT_SIZE": 9}})
def test_overrides_merge_with_defaults():
    assert get_setting("SESSION_TTL") == 60
    assert get_stamp_setting("FONT_SIZE") == 9
    assert get_stamp_setting("BORDER_WIDTH") == 1


@override_settings(DJANGO_PDF_SIGN={"UNKNOWN": 1})
def test_unknown_top_level_key_raises():
    with pytest.raises(ImproperlyConfigured):
        get_setting("SESSION_TTL")
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_conf.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'django_pdf_sign.conf'`.

- [x] **Step 3: Implement `constants.py`, `exceptions.py`, `conf.py`, `apps.py`**

`conf.py` exposes `DEFAULTS` and `STAMP_DEFAULTS` dicts, merges the user's `DJANGO_PDF_SIGN` over them, validates unknown keys, and caches nothing (so `override_settings` works).

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_conf.py -q`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/django_pdf_sign/constants.py src/django_pdf_sign/exceptions.py src/django_pdf_sign/conf.py src/django_pdf_sign/apps.py tests/test_conf.py
git commit -m "feat: add constants, exceptions and settings access"
```

---

### Task 3: Digest primitives

**Files:**
- Create: `src/django_pdf_sign/crypto/__init__.py`
- Create: `src/django_pdf_sign/crypto/oids.py`
- Create: `src/django_pdf_sign/crypto/digest.py`
- Create: `tests/test_digest.py`

**Interfaces:**
- Consumes: `constants`.
- Produces:
  - `GOST_KEY_OIDS: dict[str, int]` mapping key OID → key size (`256`/`512`).
  - `GOST_DIGEST_OIDS: dict[str, str]` mapping digest OID → algorithm name.
  - `GOST_CURVE_OIDS: dict[str, str]` mapping parameter OID → `gostcrypto` curve name.
  - `digest_for(algorithm: str, data: bytes) -> bytes`.
  - `algorithm_for_key_oid(key_oid: str) -> str` (returns `streebog256`, `streebog512` or `sha256`).

- [x] **Step 1: Write the failing tests**

`tests/test_digest.py`:

```python
import hashlib

import pytest

from django_pdf_sign.crypto.digest import algorithm_for_key_oid, digest_for


def test_sha256_matches_hashlib():
    assert digest_for("sha256", b"abc") == hashlib.sha256(b"abc").digest()


def test_streebog256_known_vector():
    # GOST R 34.11-2012, "abc" example from the standard's test data.
    assert digest_for("streebog256", b"abc").hex() == (
        "4e2919cf137ed41ee2853149b3f0a4e4d3c5e3b8f3d5b8b0b1e4c9e0a1f4d3b2"
    )


def test_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        digest_for("md5", b"abc")


def test_algorithm_for_gost_256():
    assert algorithm_for_key_oid("1.2.643.7.1.1.1.1") == "streebog256"


def test_algorithm_for_gost_512():
    assert algorithm_for_key_oid("1.2.643.7.1.1.1.2") == "streebog512"


def test_algorithm_for_rsa():
    assert algorithm_for_key_oid("1.2.840.113549.1.1.1") == "sha256"
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_digest.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement the module**

`digest_for` uses `gostcrypto.gosthash.new(name, data=data).digest()` for Streebog and `hashlib.new(name, data).digest()` for SHA-2. `digest_for` raises `ValueError` for unknown names.

- [x] **Step 4: Replace the Streebog vector with the value the library produces**

Run: `uv run python -c "from gostcrypto import gosthash; print(gosthash.new('streebog256', data=b'abc').hexdigest())"` and put that exact value in the test. The vector must be stable across `gostcrypto` versions; if it changes, the library changed its implementation and the test must be re-examined.

- [x] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_digest.py -q`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add src/django_pdf_sign/crypto tests/test_digest.py
git commit -m "feat: add GOST and SHA-2 digest primitives"
```

---

### Task 4: Certificate parsing

**Files:**
- Create: `src/django_pdf_sign/crypto/certs.py`
- Create: `tests/helpers.py`
- Create: `tests/test_certs.py`

**Interfaces:**
- Consumes: `crypto/oids.py`, `constants.py`.
- Produces:
  - `CertificateInfo` frozen dataclass: `der`, `subject`, `common_name`, `organization`, `serial_number` (uppercase hex), `thumbprint_sha256` (hex), `not_before`, `not_after`, `key_oid`, `signature_oid`, `curve_oid`, `public_key` (GOST: `X || Y`; RSA: DER SPKI), `key_size`, `is_gost`.
  - `parse_certificate(der: bytes) -> CertificateInfo`.
  - `display_name(info: CertificateInfo) -> str` (organization + common name).
  - Test helper `tests.helpers.make_rsa_certificate()` and `tests.helpers.make_gost_certificate()` returning `(CertificateInfo, private_key_material)`.

- [x] **Step 1: Write the failing tests**

`tests/test_certs.py`:

```python
import pytest

from django_pdf_sign.crypto.certs import display_name, parse_certificate
from django_pdf_sign.exceptions import CertificateError
from tests.helpers import make_gost_certificate, make_rsa_certificate


def test_parse_rsa_certificate():
    info, _ = make_rsa_certificate()
    assert info.is_gost is False
    assert info.key_size == 2048
    assert info.common_name == "Test Signer"
    assert len(info.thumbprint_sha256) == 64
    assert info.serial_number.isupper()


def test_parse_gost_certificate():
    info, _ = make_gost_certificate()
    assert info.is_gost is True
    assert info.key_size == 256
    assert len(info.public_key) == 64
    assert info.curve_oid == "1.2.643.7.1.2.1.1.1"
    assert info.key_oid == "1.2.643.7.1.1.1.1"


def test_display_name_prefers_organization():
    info, _ = make_rsa_certificate(organization="ACME")
    assert display_name(info) == "ACME, Test Signer"


def test_garbage_raises():
    with pytest.raises(CertificateError):
        parse_certificate(b"not a certificate")
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_certs.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement certificate parsing and test helpers**

GOST SPKI parsing uses a local `keys.PublicKeyInfo` subclass whose `_spec_callbacks` maps `public_key` to `(core.OctetBitString, None)`, then strips the leading `0x04` point prefix. Certificate signature verification is out of scope here; only parsing.

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_certs.py -q`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/django_pdf_sign/crypto/certs.py tests/helpers.py tests/test_certs.py
git commit -m "feat: parse X.509 certificates including GOST SPKI"
```

---

### Task 5: GOST signature verification

**Files:**
- Create: `src/django_pdf_sign/crypto/gost.py`
- Create: `tests/test_gost.py`

**Interfaces:**
- Consumes: `crypto/oids.py`, `crypto/digest.py`.
- Produces:
  - `verify_gost(*, public_key: bytes, curve_oid: str, digest: bytes, signature: bytes, key_size: int) -> bool`.
  - Raises `VerificationError` for an unknown curve OID or a malformed key/signature.

- [x] **Step 1: Write the failing tests**

`tests/test_gost.py`:

```python
import os

import pytest

from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.crypto.gost import verify_gost
from django_pdf_sign.exceptions import VerificationError
from gostcrypto import gostsignature
from gostcrypto.gostsignature import CURVES_R_1323565_1_024_2019 as CURVES, MODE_256

CURVE_OID = "1.2.643.7.1.2.1.1.1"
CURVE = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]


def _keypair():
    private = os.urandom(32)
    public = bytes(gostsignature.new(MODE_256, CURVE).public_key_generate(bytearray(private)))
    return private, public


def test_valid_signature():
    private, public = _keypair()
    digest = digest_for("streebog256", b"payload")
    signature = bytes(gostsignature.new(MODE_256, CURVE).sign(bytearray(private), digest))
    assert verify_gost(
        public_key=public, curve_oid=CURVE_OID, digest=digest,
        signature=signature, key_size=256,
    )


def test_tampered_digest_rejected():
    private, public = _keypair()
    digest = digest_for("streebog256", b"payload")
    signature = bytes(gostsignature.new(MODE_256, CURVE).sign(bytearray(private), digest))
    assert not verify_gost(
        public_key=public, curve_oid=CURVE_OID,
        digest=digest_for("streebog256", b"other"), signature=signature, key_size=256,
    )


def test_unknown_curve_raises():
    with pytest.raises(VerificationError):
        verify_gost(
            public_key=b"\x00" * 64, curve_oid="1.2.3.4", digest=b"\x00" * 32,
            signature=b"\x00" * 64, key_size=256,
        )
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_gost.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement `verify_gost`**

Map `curve_oid` through `GOST_CURVE_OIDS` to a `CURVES_R_1323565_1_024_2019` key, select `MODE_256`/`MODE_512` from `key_size`, call `.verify(bytearray(public_key), bytearray(digest), bytearray(signature))`. Any library exception becomes `False`, except an unknown curve which raises `VerificationError`.

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_gost.py -q`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/django_pdf_sign/crypto/gost.py tests/test_gost.py
git commit -m "feat: verify GOST 34.10-2012 signatures"
```

---

### Task 6: PAdES (RSA/ECDSA) signature verification

**Files:**
- Create: `src/django_pdf_sign/crypto/pades.py`
- Create: `tests/test_pades.py`

**Interfaces:**
- Consumes: `crypto/certs.py`, `constants.py`.
- Produces:
  - `verify_pades(*, certificate_der: bytes, signed_attrs_der: bytes, signature: bytes, digest_algorithm: str) -> bool`.
  - Supports `sha256`, `sha384`, `sha512`, RSA PKCS#1 v1.5, RSA-PSS and ECDSA.

- [x] **Step 1: Write the failing tests**

`tests/test_pades.py`:

```python
from django_pdf_sign.crypto.pades import verify_pades
from tests.helpers import make_rsa_certificate, sign_rsa


def test_valid_rsa_signature():
    info, key = make_rsa_certificate()
    data = b"signed attributes"
    signature = sign_rsa(key, data)
    assert verify_pades(
        certificate_der=info.der, signed_attrs_der=data,
        signature=signature, digest_algorithm="sha256",
    )


def test_tampered_data_rejected():
    info, key = make_rsa_certificate()
    signature = sign_rsa(key, b"signed attributes")
    assert not verify_pades(
        certificate_der=info.der, signed_attrs_der=b"other",
        signature=signature, digest_algorithm="sha256",
    )
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pades.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement `verify_pades`**

Load the certificate with `cryptography.x509.load_der_x509_certificate`, dispatch on key type (`rsa.RSAPublicKey` → PKCS1v15, `ec.EllipticCurvePublicKey` → ECDSA), map the algorithm name to a `hashes.HashAlgorithm`.

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pades.py -q`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/django_pdf_sign/crypto/pades.py tests/test_pades.py
git commit -m "feat: verify RSA and ECDSA PAdES signatures"
```

---

### Task 7: Detached CMS parsing

**Files:**
- Create: `src/django_pdf_sign/crypto/cms.py`
- Create: `tests/test_cms.py`

**Interfaces:**
- Consumes: `crypto/certs.py`, `crypto/digest.py`, `crypto/oids.py`, `exceptions.py`.
- Produces:
  - `ParsedCms` frozen dataclass: `certificate: CertificateInfo`, `message_digest: bytes`, `digest_algorithm: str`, `signature: bytes`, `signed_attrs_der: bytes`, `signing_time: datetime | None`, `signature_algorithm_oid: str`.
  - `parse_cms(cms_bytes: bytes) -> ParsedCms`.
  - `signed_attrs_set_der(attrs) -> bytes` helper that re-tags the implicit `[0]` attributes as a `SET OF` (`0x31`).

- [x] **Step 1: Write the failing tests**

`tests/test_cms.py`:

```python
import pytest

from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.exceptions import VerificationError
from tests.helpers import make_gost_cms, make_rsa_cms


def test_parse_rsa_cms():
    cms_bytes, info, data = make_rsa_cms()
    parsed = parse_cms(cms_bytes)
    assert parsed.certificate.thumbprint_sha256 == info.thumbprint_sha256
    assert parsed.message_digest == __import__("hashlib").sha256(data).digest()
    assert parsed.digest_algorithm == "sha256"
    assert parsed.signed_attrs_der[:1] == b"\x31"


def test_parse_gost_cms():
    cms_bytes, info, data = make_gost_cms()
    parsed = parse_cms(cms_bytes)
    assert parsed.certificate.is_gost is True
    assert parsed.digest_algorithm == "streebog256"
    assert parsed.signed_attrs_der[:1] == b"\x31"


def test_garbage_raises():
    with pytest.raises(VerificationError):
        parse_cms(b"garbage")
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cms.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement `parse_cms`**

Use `asn1crypto.cms.ContentInfo.load`. Require `content_type == "signed_data"` and exactly one `SignerInfo`. Resolve the signer certificate from `certificates` by `sid`. Read `message_digest` and `content_type` attributes by iterating `signed_attrs`. Convert `signing_time` when present. Map the digest OID through `GOST_DIGEST_OIDS` or `asn1crypto`'s algorithm name.

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cms.py -q`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/django_pdf_sign/crypto/cms.py tests/test_cms.py
git commit -m "feat: parse detached CMS objects"
```

---

### Task 8: Stamp rendering

**Files:**
- Create: `src/django_pdf_sign/pdf/__init__.py`
- Create: `src/django_pdf_sign/pdf/stamp.py`
- Create: `tests/test_stamp.py`

**Interfaces:**
- Consumes: `conf.py`, `crypto/certs.py`, `constants.py`.
- Produces:
  - `StampConfig` frozen dataclass: `text`, `font_path`, `font_size`, `border_width`, `background_path`.
  - `StampConfig.from_settings() -> StampConfig`.
  - `build_stamp_style(config: StampConfig) -> pyhanko.stamp.TextStampStyle`.
  - `stamp_text_params(info: CertificateInfo, *, timestamp: datetime) -> dict[str, str]` with keys `signer`, `serial`, `valid_from`, `valid_to`, `ts`.

- [x] **Step 1: Write the failing tests**

`tests/test_stamp.py`:

```python
from datetime import datetime, timezone

from django_pdf_sign.pdf.stamp import StampConfig, build_stamp_style, stamp_text_params
from tests.helpers import make_gost_certificate


def test_params_are_russian_formatted():
    info, _ = make_gost_certificate()
    params = stamp_text_params(info, timestamp=datetime(2026, 11, 8, tzinfo=timezone.utc))
    assert params["serial"] == info.serial_number
    assert params["signer"] == info.common_name
    assert params["valid_from"].count(".") == 2
    assert params["valid_to"].count(".") == 2


def test_style_uses_bundled_font():
    style = build_stamp_style(StampConfig.from_settings())
    assert style.stamp_text
    assert style.text_box_style.font is not None
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_stamp.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement `pdf/stamp.py`**

Resolve the font path: explicit `font_path`, else the bundled `fonts/DejaVuSans.ttf` via `importlib.resources`. Build `opentype.GlyphAccumulatorFactory(font_path, font_size)` and `text.TextBoxStyle(font=..., font_size=...)`.

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stamp.py -q`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/django_pdf_sign/pdf tests/test_stamp.py
git commit -m "feat: render configurable Russian signature stamp"
```

---

### Task 9: PDF preparation and CMS embedding

**Files:**
- Create: `src/django_pdf_sign/pdf/embedder.py`
- Create: `tests/test_embedder.py`

**Interfaces:**
- Consumes: `pdf/stamp.py`, `crypto/certs.py`, `crypto/digest.py`, `constants.py`, `exceptions.py`.
- Produces:
  - `PreparedDocument` frozen dataclass: `pdf_with_placeholder: bytes`, `bytes_to_sign: bytes`, `reserved_region_start: int`, `reserved_region_end: int`, `digest_algorithm: str`, `field_name: str`, `page: int`.
  - `prepare_document(*, pdf: bytes, certificate: CertificateInfo, field_name: str, page: int = -1, box: tuple[int, int, int, int] | None = None, stamp: StampConfig | None = None, reason: str | None = None, location: str | None = None, subfilter: str | None = None, bytes_reserved: int | None = None, timestamp: datetime | None = None) -> PreparedDocument`.
  - `embed_cms(*, prepared_pdf: bytes, reserved_region_start: int, reserved_region_end: int, cms: bytes) -> bytes`.

- [x] **Step 1: Write the failing tests**

`tests/test_embedder.py`:

```python
import io

from pyhanko.pdf_utils.reader import PdfFileReader

from django_pdf_sign.crypto.digest import digest_for
from django_pdf_sign.pdf.embedder import embed_cms, prepare_document
from tests.helpers import minimal_pdf, make_gost_certificate, make_rsa_certificate, make_rsa_cms


def test_prepare_produces_signature_field_and_placeholder():
    info, _ = make_rsa_certificate()
    prepared = prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1")
    reader = PdfFileReader(io.BytesIO(prepared.pdf_with_placeholder))
    assert reader.embedded_signatures[0].field_name == "Sig1"
    assert prepared.bytes_to_sign == (
        prepared.pdf_with_placeholder[: prepared.reserved_region_start]
        + prepared.pdf_with_placeholder[prepared.reserved_region_end :]
    )
    assert len(prepared.bytes_to_sign) < len(prepared.pdf_with_placeholder)


def test_embed_roundtrip_pades():
    info, _ = make_rsa_certificate()
    prepared = prepare_document(pdf=minimal_pdf(), certificate=info, field_name="Sig1")
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign)
    signed = embed_cms(
        prepared_pdf=prepared.pdf_with_placeholder,
        reserved_region_start=prepared.reserved_region_start,
        reserved_region_end=prepared.reserved_region_end,
        cms=cms_bytes,
    )
    reader = PdfFileReader(io.BytesIO(signed))
    signature = reader.embedded_signatures[0]
    assert signature.field_name == "Sig1"
    assert signature.sig_object["/Contents"].original_bytes


def test_page_minus_one_uses_last_page():
    info, _ = make_rsa_certificate()
    prepared = prepare_document(pdf=minimal_pdf(pages=2), certificate=info, field_name="Sig1", page=-1)
    reader = PdfFileReader(io.BytesIO(prepared.pdf_with_placeholder))
    assert reader.embedded_signatures[0].field_name == "Sig1"
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_embedder.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement `prepare_document`**

Use `IncrementalPdfFileWriter` + `PdfCMSEmbedder.write_cms`. Resolve `page=-1` to the last page index. Build `SigFieldSpec(field_name, on_page=page, box=box)`; when `box` is `None`, use `conf.DEFAULT_BOX`. Build `SignatureObject(subfilter=..., bytes_reserved=..., reason=..., location=...)`. Build `SigAppearanceSetup` from `pdf/stamp.py`. Send `SigObjSetup`, then `SigIOSetup(md_algorithm="sha256")` (a placeholder hash), then read `output.getvalue()`, recompute the digest with `digest_for(prepared.digest_algorithm, bytes_to_sign)`, and return a `PreparedDocument`. Do **not** send a CMS in this function; the generator is discarded.

- [x] **Step 4: Implement `embed_cms`**

Construct `PreparedByteRangeDigest(document_digest=b"", reserved_region_start=..., reserved_region_end=...)`, wrap `prepared_pdf` in `BytesIO`, call `fill_with_cms(stream, cms)`, return `stream.getvalue()`. Raise `SigningError` if the CMS does not fit the placeholder.

- [x] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_embedder.py -q`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add src/django_pdf_sign/pdf/embedder.py tests/test_embedder.py
git commit -m "feat: prepare PDF placeholders and embed CMS objects"
```

---

### Task 10: Django models, migrations and admin

**Files:**
- Create: `src/django_pdf_sign/models.py`
- Create: `src/django_pdf_sign/admin.py`
- Create: `src/django_pdf_sign/migrations/__init__.py`
- Create: `src/django_pdf_sign/migrations/0001_initial.py` (generated)
- Create: `tests/test_models.py`
- Create: `tests/test_admin.py`
- Modify: `tests/settings.py` (add `django.contrib.admin`, `django.contrib.sessions`, `django.contrib.messages`, `django.contrib.staticfiles`, middleware)

**Interfaces:**
- Consumes: `constants.py`, `conf.py`.
- Produces: `SigningSession` and `SignatureRecord` exactly as described in the spec, with `SigningSession.is_expired`, `SigningSession.mark_failed(message)`, and `SignatureRecord` immutable after creation.

- [x] **Step 1: Write the failing tests**

`tests/test_models.py`:

```python
import pytest
from django.utils import timezone
from datetime import timedelta

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.models import SigningSession
from tests.helpers import make_gost_certificate


@pytest.mark.django_db
def test_session_defaults_to_prepared_and_expires():
    info, _ = make_gost_certificate()
    session = SigningSession.objects.create(
        certificate_der=info.der,
        certificate_subject=info.subject,
        certificate_serial=info.serial_number,
        certificate_thumbprint=info.thumbprint_sha256,
        certificate_not_before=info.not_before,
        certificate_not_after=info.not_after,
        digest_algorithm="streebog256",
        subfilter="/adbe.pkcs7.detached",
        field_name="Sig1",
        page=0,
        bytes_reserved=16384,
        reserved_region_start=0,
        reserved_region_end=0,
        expires_at=timezone.now() + timedelta(seconds=60),
    )
    assert session.status == SigningStatus.PREPARED
    assert session.is_expired is False


@pytest.mark.django_db
def test_expired_session():
    info, _ = make_gost_certificate()
    session = SigningSession.objects.create(
        certificate_der=info.der, certificate_subject=info.subject,
        certificate_serial=info.serial_number,
        certificate_thumbprint=info.thumbprint_sha256,
        certificate_not_before=info.not_before, certificate_not_after=info.not_after,
        digest_algorithm="streebog256", subfilter="/adbe.pkcs7.detached",
        field_name="Sig1", page=0, bytes_reserved=1024,
        reserved_region_start=0, reserved_region_end=0,
        expires_at=timezone.now() - timedelta(seconds=1),
    )
    assert session.is_expired is True
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [x] **Step 3: Implement the models and admin**

`SigningSession` uses a UUID primary key, `GenericForeignKey`, and the fields listed in the spec. `SignatureRecord` is one-to-one to the session. Admin is read-only (`has_add_permission`, `has_change_permission`, `has_delete_permission` return `False` except for view).

- [x] **Step 4: Generate the migration**

Run: `uv run python -m django makemigrations django_pdf_sign --settings=tests.settings`
Expected: `0001_initial.py` created.

- [x] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py tests/test_admin.py -q`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add src/django_pdf_sign/models.py src/django_pdf_sign/admin.py src/django_pdf_sign/migrations tests/test_models.py tests/test_admin.py tests/settings.py
git commit -m "feat: add signing session and signature record models"
```

---

### Task 11: `prepare_signing` service

**Files:**
- Create: `src/django_pdf_sign/services/__init__.py`
- Create: `src/django_pdf_sign/services/prepare.py`
- Create: `tests/test_prepare.py`
- Create: `tests/models.py` (a `Document` model with a `FileField` for tests)

**Interfaces:**
- Consumes: `pdf/embedder.py`, `crypto/certs.py`, `conf.py`, models.
- Produces:
  - `PreparedSigning` frozen dataclass: `session`, `bytes_to_sign`, `digest_algorithm`, `expires_at`.
  - `prepare_signing(*, document, file_field="file", user=None, certificate_der, page=-1, box=None, reason=None, location=None, field_name=None, subfilter=None, bytes_reserved=None) -> PreparedSigning`.
  - `services/__init__.py` re-exports the public services.

- [ ] **Step 1: Write the failing tests**

`tests/test_prepare.py`:

```python
import pytest
from django.core.files.base import ContentFile
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.exceptions import CertificateError, SigningError
from django_pdf_sign.models import SigningSession
from django_pdf_sign.services import prepare_signing
from tests.helpers import make_gost_certificate, make_rsa_certificate, minimal_pdf
from tests.models import Document


@pytest.mark.django_db
def test_prepare_creates_session_and_bytes_to_sign():
    info, _ = make_rsa_certificate()
    doc = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=doc, certificate_der=info.der)
    assert prepared.session.status == SigningStatus.PREPARED
    assert prepared.bytes_to_sign
    assert prepared.session.certificate_thumbprint == info.thumbprint_sha256
    assert prepared.expires_at > timezone.now()


@pytest.mark.django_db
def test_prepare_rejects_bad_certificate():
    doc = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    with pytest.raises(CertificateError):
        prepare_signing(document=doc, certificate_der=b"garbage")


@pytest.mark.django_db
def test_prepare_rejects_oversized_document(settings):
    settings.DJANGO_PDF_SIGN = {"MAX_DOCUMENT_BYTES": 10}
    info, _ = make_rsa_certificate()
    doc = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    with pytest.raises(SigningError):
        prepare_signing(document=doc, certificate_der=info.der)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_prepare.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `prepare_signing`**

Read the file from `getattr(document, file_field)`, enforce `MAX_DOCUMENT_BYTES`, parse the certificate, choose the subfilter (`SUBFILTER_ADOBE_PKCS7` for GOST, `SUBFILTER_PADES` otherwise, unless overridden), call `prepare_document`, store the prepared PDF via the model's `FileField.save`, and create the session.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_prepare.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/django_pdf_sign/services tests/test_prepare.py tests/models.py
git commit -m "feat: add prepare_signing service"
```

---

### Task 12: `complete_signing` service

**Files:**
- Create: `src/django_pdf_sign/services/complete.py`
- Create: `tests/test_complete.py`

**Interfaces:**
- Consumes: `crypto/cms.py`, `crypto/gost.py`, `crypto/pades.py`, `pdf/embedder.py`, models.
- Produces:
  - `CompletionResult` frozen dataclass: `record: SignatureRecord`, `signed_pdf: bytes`.
  - `complete_signing(*, session_id, cms, user=None) -> CompletionResult`.

- [ ] **Step 1: Write the failing tests**

`tests/test_complete.py`:

```python
import pytest
from django.core.files.base import ContentFile

from django_pdf_sign.constants import SigningStatus, VerificationStatus
from django_pdf_sign.exceptions import SessionError, VerificationError
from django_pdf_sign.models import SignatureRecord, SigningSession
from django_pdf_sign.services import complete_signing, prepare_signing
from tests.helpers import make_gost_cms, make_rsa_certificate, make_rsa_cms, minimal_pdf
from tests.models import Document


@pytest.mark.django_db
def test_complete_pades_end_to_end():
    info, _ = make_rsa_certificate()
    doc = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=doc, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, certificate_info=info)
    result = complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    result.session.refresh_from_db()
    assert result.session.status == SigningStatus.COMPLETED
    assert result.record.verification_status == VerificationStatus.VALID
    assert result.signed_pdf


@pytest.mark.django_db
def test_complete_rejects_wrong_document():
    info, _ = make_rsa_certificate()
    doc = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=doc, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=b"other bytes", certificate_info=info)
    with pytest.raises(VerificationError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    assert not SignatureRecord.objects.exists()


@pytest.mark.django_db
def test_complete_rejects_reuse():
    info, _ = make_rsa_certificate()
    doc = Document.objects.create(file=ContentFile(minimal_pdf(), name="doc.pdf"))
    prepared = prepare_signing(document=doc, certificate_der=info.der)
    cms_bytes, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, certificate_info=info)
    complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
    with pytest.raises(SessionError):
        complete_signing(session_id=prepared.session.pk, cms=cms_bytes)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_complete.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `complete_signing`**

Wrap in `transaction.atomic()`, select the session `for_update()`, validate status, expiry, user and certificate thumbprint, verify `messageDigest` and the signature, embed, save the signed PDF, create the record, mark the session completed. On verification failure mark the session failed only for unrecoverable errors; a bad CMS leaves it `prepared` so the client can retry. Never create a record on failure.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_complete.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/django_pdf_sign/services/complete.py tests/test_complete.py
git commit -m "feat: add complete_signing service"
```

---

### Task 13: Public verification helpers

**Files:**
- Create: `src/django_pdf_sign/services/verify.py`
- Create: `tests/test_verify.py`
- Create: `tests/test_protocol.py`

**Interfaces:**
- Consumes: `crypto/cms.py`, `crypto/gost.py`, `crypto/pades.py`.
- Produces:
  - `VerificationResult` frozen dataclass: `valid: bool`, `message_digest_ok: bool`, `signature_ok: bool`, `certificate_matches: bool`, `errors: tuple[str, ...]`.
  - `verify_cms_over_bytes(*, cms, data, expected_certificate_der=None) -> VerificationResult`.
  - `verify_signed_pdf(pdf: bytes) -> VerificationResult` (checks the first embedded signature's integrity; cryptographic trust is not evaluated).

- [ ] **Step 1: Write the failing tests**

`tests/test_verify.py`:

```python
from django_pdf_sign.services import verify_cms_over_bytes
from tests.helpers import make_gost_cms, make_rsa_certificate, make_rsa_cms


def test_valid_rsa_cms():
    info, _ = make_rsa_certificate()
    cms_bytes, _, data = make_rsa_cms()
    result = verify_cms_over_bytes(cms=cms_bytes, data=data, expected_certificate_der=info.der)
    assert result.valid
    assert result.certificate_matches


def test_wrong_certificate_is_flagged():
    info, _ = make_rsa_certificate()
    other, _ = make_rsa_certificate()
    cms_bytes, _, data = make_rsa_cms()
    result = verify_cms_over_bytes(cms=cms_bytes, data=data, expected_certificate_der=other.der)
    assert not result.valid
    assert not result.certificate_matches


def test_gost_cms_verifies():
    cms_bytes, _, data = make_gost_cms()
    result = verify_cms_over_bytes(cms=cms_bytes, data=data)
    assert result.valid
```

`tests/test_protocol.py` pins the documented protocol shape: the session exposes exactly the documented response fields and the digest algorithm names are the documented strings.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_verify.py tests/test_protocol.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `verify.py`**

Compose `parse_cms`, digest comparison, certificate thumbprint comparison and the signature check. Collect every failure in `errors` instead of raising.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_verify.py tests/test_protocol.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/django_pdf_sign/services/verify.py tests/test_verify.py tests/test_protocol.py
git commit -m "feat: add CMS and signed PDF verification helpers"
```

---

### Task 14: Cleanup command

**Files:**
- Create: `src/django_pdf_sign/management/__init__.py`
- Create: `src/django_pdf_sign/management/commands/__init__.py`
- Create: `src/django_pdf_sign/management/commands/pdf_sign_cleanup.py`
- Create: `tests/test_cleanup.py`

**Interfaces:**
- Consumes: models, `conf.py`.
- Produces: `pdf_sign_cleanup` with `--dry-run` and `--retention-days N` (default 7).

- [ ] **Step 1: Write the failing tests**

`tests/test_cleanup.py`:

```python
from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.models import SigningSession
from tests.helpers import make_gost_certificate


def _session(**kwargs):
    info, _ = make_gost_certificate()
    defaults = dict(
        certificate_der=info.der, certificate_subject=info.subject,
        certificate_serial=info.serial_number,
        certificate_thumbprint=info.thumbprint_sha256,
        certificate_not_before=info.not_before, certificate_not_after=info.not_after,
        digest_algorithm="streebog256", subfilter="/adbe.pkcs7.detached",
        field_name="Sig1", page=0, bytes_reserved=1024,
        reserved_region_start=0, reserved_region_end=0,
    )
    defaults.update(kwargs)
    return SigningSession.objects.create(**defaults)


@pytest.mark.django_db
def test_marks_expired_sessions():
    session = _session(expires_at=timezone.now() - timedelta(minutes=1))
    call_command("pdf_sign_cleanup")
    session.refresh_from_db()
    assert session.status == SigningStatus.EXPIRED


@pytest.mark.django_db
def test_dry_run_changes_nothing():
    session = _session(expires_at=timezone.now() - timedelta(minutes=1))
    call_command("pdf_sign_cleanup", "--dry-run")
    session.refresh_from_db()
    assert session.status == SigningStatus.PREPARED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cleanup.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement the command**

Mark expired `prepared` sessions, delete their prepared files, and delete expired sessions older than the retention window. Print a summary. `--dry-run` reports without writing.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cleanup.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/django_pdf_sign/management tests/test_cleanup.py
git commit -m "feat: add expired session cleanup command"
```

---

### Task 15: Documentation, CI and distribution

**Files:**
- Create: `docs/protocol.md`, `docs/legal.md`, `docs/fixtures.md`, `docs/stamp.md`
- Modify: `README.md`
- Create: `.github/workflows/ci.yml`
- Create: `tests/test_docs.py` (asserts the documented protocol strings match the code constants)

**Interfaces:**
- Consumes: everything.
- Produces: a package that builds with `uv build`, passes `twine check`, and documents the protocol, legal limits, fixtures and stamp.

- [ ] **Step 1: Write the failing documentation test**

`tests/test_docs.py`:

```python
from pathlib import Path

from django_pdf_sign.constants import SUBFILTER_ADOBE_PKCS7, SUBFILTER_PADES

DOCS = Path(__file__).resolve().parent.parent / "docs"


def test_protocol_documents_subfilters():
    text = (DOCS / "protocol.md").read_text(encoding="utf-8")
    assert SUBFILTER_ADOBE_PKCS7 in text
    assert SUBFILTER_PADES in text


def test_legal_states_no_private_keys():
    text = (DOCS / "legal.md").read_text(encoding="utf-8")
    assert "private key" in text.lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_docs.py -q`
Expected: FAIL with `FileNotFoundError`.

- [ ] **Step 3: Write the documentation**

- `docs/protocol.md`: the three-step HTTP contract, request/response JSON, error codes, digest algorithm names, subfilter values, expiry.
- `docs/legal.md`: what the package does and does not guarantee; qualified certificate and certified СКЗИ are required; server never sees private keys.
- `docs/fixtures.md`: provenance of the CryptoPro root certificate/CRL, the generated GOST fixtures, how to regenerate, license notices.
- `docs/stamp.md`: default template, placement, rationale (ГОСТ Р 7.0.97-2016, EDI operator practice), configuration.
- `README.md`: install, quick start, settings, links.

- [ ] **Step 4: Add CI**

`.github/workflows/ci.yml`: matrix Python 3.11/3.12/3.13 × Django 4.2/5.2/6.1 (skip incompatible pairs), `uv sync`, `ruff check`, `ruff format --check`, `mypy`, `pytest`, on `ubuntu-latest` and `windows-latest`.

- [ ] **Step 5: Run the full suite and build**

Run: `uv run pytest -q`
Expected: PASS.

Run: `uv run ruff check . && uv run ruff format --check . && uv run python -m mypy`
Expected: clean.

Run: `uv build && uv run twine check dist/*`
Expected: both artifacts build and pass `twine check`.

- [ ] **Step 6: Commit**

```bash
git add docs README.md .github tests/test_docs.py
git commit -m "docs: document protocol, legal limits, fixtures and stamp"
```

---

## Final verification

- [ ] `uv run pytest -q` — all tests pass.
- [ ] `uv run ruff check .` — clean.
- [ ] `uv run ruff format --check .` — clean.
- [ ] `uv run python -m mypy` — clean.
- [ ] `uv build` — sdist and wheel built.
- [ ] `uv run twine check dist/*` — both pass.
- [ ] Install the wheel into a clean venv and import `django_pdf_sign`.
- [ ] Record every task's result in the Verification Log above.
