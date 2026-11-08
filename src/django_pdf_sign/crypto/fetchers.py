"""Сетевые fetcher-ы с allowlist хостов для CRL, OCSP и AIA."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from urllib.parse import urlsplit

import requests
from pyhanko_certvalidator.errors import (
    CertificateFetchError,
    CRLFetchError,
    OCSPFetchError,
)
from pyhanko_certvalidator.fetchers.api import Fetchers
from pyhanko_certvalidator.fetchers.requests_fetchers import (  # type: ignore[attr-defined]
    FetchBudget,
    RequestsCertificateFetcher,
    RequestsCRLFetcher,
    RequestsFetcherBackend,
    RequestsOCSPFetcher,
)

from django_pdf_sign.exceptions import VerificationError


class _AllowlistMixin:
    def __init__(
        self, allowed_hosts: frozenset[str], *args: Any, **kwargs: Any
    ) -> None:
        self._allowed_hosts = allowed_hosts
        super().__init__(*args, **kwargs)

    def _ensure_allowed(self, url: str | None, error: type[Exception]) -> None:
        host = (urlsplit(url or "").hostname or "").lower()
        if host not in self._allowed_hosts:
            raise error(f"Хост {host or '<пусто>'!r} не разрешён для загрузки отзыва")

    async def _get(self, url: str, *, acceptable_content_types: tuple[str, ...]) -> Any:
        owner = cast(Any, self)

        def task() -> Any:
            headers = {
                "Accept": ",".join(acceptable_content_types),
                "User-Agent": owner.user_agent,
            }
            response = requests.get(
                url=url,
                timeout=owner.per_request_timeout,
                headers=headers,
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise requests.RequestException(f"status code {response.status_code}")
            return response

        return await asyncio.to_thread(task)

    async def _post(
        self,
        url: str,
        data: bytes,
        *,
        content_type: str,
        acceptable_content_types: tuple[str, ...],
    ) -> Any:
        owner = cast(Any, self)

        def task() -> Any:
            headers = {
                "Accept": ",".join(acceptable_content_types),
                "User-Agent": owner.user_agent,
                "Content-Type": content_type,
            }
            response = requests.post(
                url=url,
                timeout=owner.per_request_timeout,
                headers=headers,
                data=data,
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise requests.RequestException(f"status code {response.status_code}")
            return response

        return await asyncio.to_thread(task)


class _AllowlistCRLFetcher(_AllowlistMixin, RequestsCRLFetcher):
    async def _fetch_single(self, url: str) -> Any:
        self._ensure_allowed(url, CRLFetchError)
        return await super()._fetch_single(url)  # type: ignore[no-untyped-call]


class _AllowlistOCSPFetcher(_AllowlistMixin, RequestsOCSPFetcher):
    async def _fetch_single(self, ocsp_url: str, ocsp_request: Any) -> Any:
        self._ensure_allowed(ocsp_url, OCSPFetchError)
        return await super()._fetch_single(ocsp_url, ocsp_request)  # type: ignore[no-untyped-call]


class _AllowlistCertificateFetcher(_AllowlistMixin, RequestsCertificateFetcher):
    async def fetch_certs(self, url: str, url_origin_type: str) -> Any:
        self._ensure_allowed(url, CertificateFetchError)
        return await super().fetch_certs(url, url_origin_type)  # type: ignore[no-untyped-call]


class AllowlistFetcherBackend(RequestsFetcherBackend):
    """Fetcher backend, разрешающий сетевые запросы только кlisted хостам."""

    def __init__(self, allowed_hosts: tuple[str, ...], **kwargs: Any) -> None:
        if not allowed_hosts:
            raise VerificationError(
                "ALLOW_FETCHING=True требует непустой FETCH_ALLOWED_HOSTS"
            )
        super().__init__(**kwargs)
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)

    def get_fetchers(self) -> Fetchers:
        budget = FetchBudget(self.limits)
        timeout = self.per_request_timeout
        return Fetchers(
            ocsp_fetcher=_AllowlistOCSPFetcher(
                self.allowed_hosts, per_request_timeout=timeout, budget=budget
            ),
            crl_fetcher=_AllowlistCRLFetcher(
                self.allowed_hosts, per_request_timeout=timeout, budget=budget
            ),
            cert_fetcher=_AllowlistCertificateFetcher(
                self.allowed_hosts, per_request_timeout=timeout, budget=budget
            ),
        )
