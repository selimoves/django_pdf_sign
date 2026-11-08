import pytest
from django.test import override_settings

from django_pdf_sign.checks import check_settings


def _errors(config: dict) -> list:
    with override_settings(DJANGO_PDF_SIGN=config):
        return check_settings(None)


@pytest.mark.parametrize(
    "config",
    [
        {"SESSION_TTL": 0},
        {"BYTES_RESERVED": -1},
        {"MAX_DOCUMENT_BYTES": 0},
        {"DEFAULT_BOX": (10, 10, 5, 20)},
        {"SUBFILTER": "/bogus"},
        {"VERIFY": {"REVOCATION_MODE": "sometimes"}},
        {"VERIFY": {"ALLOW_FETCHING": True, "FETCH_ALLOWED_HOSTS": ()}},
        {"VERIFY": {"TRUST_ROOTS": ("/nonexistent/ca.cer",)}},
    ],
)
def test_invalid_settings_report_errors(config: dict) -> None:
    errors = _errors(config)
    assert errors
    assert all(error.id.startswith("django_pdf_sign.") for error in errors)


def test_valid_settings_have_no_errors() -> None:
    assert (
        _errors({"SESSION_TTL": 900, "VERIFY": {"REVOCATION_MODE": "soft-fail"}}) == []
    )
