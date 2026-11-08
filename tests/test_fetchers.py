import asyncio

import pytest
from pyhanko_certvalidator.errors import CRLFetchError

from django_pdf_sign.crypto.fetchers import AllowlistFetcherBackend
from django_pdf_sign.crypto.policy import VerificationPolicy
from django_pdf_sign.exceptions import VerificationError


def test_empty_allowlist_rejected() -> None:
    with pytest.raises(VerificationError):
        AllowlistFetcherBackend(())


def test_host_outside_allowlist_rejected() -> None:
    backend = AllowlistFetcherBackend(("allowed.example",))
    fetcher = backend.get_fetchers().crl_fetcher
    with pytest.raises(CRLFetchError):
        asyncio.run(fetcher._fetch_single("https://evil.example/crl"))


def test_allowed_host_is_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def fake_fetch(self: object, url: str) -> bytes:
        calls.append(url)
        return b"crl"

    monkeypatch.setattr(
        "pyhanko_certvalidator.fetchers.requests_fetchers.RequestsCRLFetcher._fetch_single",
        fake_fetch,
    )
    backend = AllowlistFetcherBackend(("allowed.example",))
    fetcher = backend.get_fetchers().crl_fetcher
    assert asyncio.run(fetcher._fetch_single("https://allowed.example/crl")) == b"crl"
    assert calls == ["https://allowed.example/crl"]


@pytest.mark.django_db
def test_policy_reads_fetch_allowlist(settings) -> None:
    settings.DJANGO_PDF_SIGN = {
        "VERIFY": {
            "ALLOW_FETCHING": True,
            "FETCH_ALLOWED_HOSTS": ("allowed.example",),
        }
    }
    policy = VerificationPolicy.from_settings()
    assert policy.fetch_allowed_hosts == ("allowed.example",)
