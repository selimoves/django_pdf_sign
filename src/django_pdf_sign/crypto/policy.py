"""Политика проверки подписей: цепочка, отзыв, метки времени."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from django_pdf_sign.conf import get_setting


def _read_many(paths: tuple[str, ...]) -> tuple[bytes, ...]:
    result = []
    for item in paths:
        result.append(Path(item).read_bytes())
    return tuple(result)


@dataclass(frozen=True)
class VerificationPolicy:
    """Параметры проверки цепочки, отзыва и меток времени.

    ``check_chain=False`` оставляет только криптографическую проверку подписи.
    ``revocation_mode`` принимает значения ``none``, ``soft-fail`` и
    ``require`` (как в pyhanko-certvalidator).
    """

    check_chain: bool = False
    trust_roots: tuple[bytes, ...] = ()
    intermediate_certs: tuple[bytes, ...] = ()
    crls: tuple[bytes, ...] = ()
    ocsps: tuple[bytes, ...] = ()
    revocation_mode: str = "soft-fail"
    allow_fetching: bool = False
    fetch_allowed_hosts: tuple[str, ...] = ()
    moment: datetime | None = None
    check_timestamps: bool = False
    require_timestamp: bool = False

    @classmethod
    def from_settings(cls) -> VerificationPolicy:
        """Собрать политику из ``DJANGO_PDF_SIGN['VERIFY']``."""
        config = get_setting("VERIFY")
        return cls(
            check_chain=bool(config["CHECK_CHAIN"]),
            trust_roots=_read_many(tuple(config["TRUST_ROOTS"])),
            intermediate_certs=_read_many(tuple(config["INTERMEDIATE_CERTS"])),
            crls=_read_many(tuple(config["CRLS"])),
            ocsps=_read_many(tuple(config["OCSPS"])),
            revocation_mode=str(config["REVOCATION_MODE"]),
            allow_fetching=bool(config["ALLOW_FETCHING"]),
            fetch_allowed_hosts=tuple(config["FETCH_ALLOWED_HOSTS"]),
            moment=None,
            check_timestamps=bool(config["CHECK_TIMESTAMPS"]),
            require_timestamp=bool(config["REQUIRE_TIMESTAMP"]),
        )


def resolve_moment(policy: VerificationPolicy) -> datetime:
    """Момент проверки: из политики или текущее время в UTC."""
    return policy.moment or datetime.now(UTC)
