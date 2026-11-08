# AGENTS.md

Working notes for AI agents and humans contributing to this repository.

## What this project is

`django-pdf-sign` is a Django package for **client-side** electronic signatures
of PDF documents. The server never holds private keys. It prepares a PDF with a
visible stamp, hands the exact bytes to sign to the browser (CryptoPro Browser
Plug-in), verifies the returned detached CMS, and embeds it.

Supported signature types:

- **GOST 34.10-2012 / CAdES-BES** — Russian qualified signatures (Streebog-256/512).
- **PAdES / RSA-ECDSA** — Adobe-compatible signatures.

## Repository layout

```
src/django_pdf_sign/   package source (src layout)
tests/                 pytest + pytest-django suite
docs/                  design spec, implementation plan, protocol, fixtures
```

## Toolchain

- Python **3.11+** (developed on 3.13 via `uv`).
- Package manager: **uv**. Do not use plain `pip` for local development.
- Lint/format: **ruff**. Types: **mypy** + `django-stubs`.

## Commands

```powershell
# create/refresh the environment
uv sync --all-extras

# run the test suite
uv run pytest

# lint, format check, type check
uv run ruff check .
uv run ruff format --check .
uv run python -m mypy

# build the distribution
uv build
```

## Rules

- **TDD**: write the failing test first, then the minimal implementation.
- **No comments** except one-line "why" notes that code cannot express.
- Every public function has a type-annotated signature and a docstring.
- Never log or store private keys, PINs or raw CMS from real users.
- Do not change the on-the-wire protocol in `docs/protocol.md` without a
  matching test in `tests/test_protocol.py`.
- Verify every step of `docs/superpowers/plans/` and record the result.

## Documentation

- `docs/superpowers/specs/` — design documents.
- `docs/superpowers/plans/` — implementation plans with step checklists.
- `docs/protocol.md` — HTTP contract between server and browser client.
- `docs/legal.md` — what makes a signature legally valid (and what this package
  does not do).
- `docs/fixtures.md` — provenance and regeneration of test certificates.
