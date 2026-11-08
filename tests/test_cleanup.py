"""Tests for the pdf_sign_cleanup command."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.models import SigningSession
from tests.helpers import make_gost_certificate


def _session(**overrides: object) -> SigningSession:
    info, _ = make_gost_certificate()
    values: dict[str, object] = {
        "certificate_der": info.der,
        "certificate_subject": info.subject,
        "certificate_serial": info.serial_number,
        "certificate_thumbprint": info.thumbprint_sha256,
        "certificate_not_before": info.not_before,
        "certificate_not_after": info.not_after,
        "digest_algorithm": "streebog256",
        "subfilter": "/adbe.pkcs7.detached",
        "field_name": "Sig1",
        "page": 0,
        "bytes_reserved": 1024,
        "reserved_region_start": 0,
        "reserved_region_end": 0,
        "expires_at": timezone.now() + timedelta(seconds=60),
    }
    values.update(overrides)
    return SigningSession.objects.create(**values)


@pytest.mark.django_db
def test_marks_expired_sessions() -> None:
    session = _session(expires_at=timezone.now() - timedelta(minutes=1))
    call_command("pdf_sign_cleanup")
    session.refresh_from_db()
    assert session.status == SigningStatus.EXPIRED


@pytest.mark.django_db
def test_dry_run_changes_nothing() -> None:
    session = _session(expires_at=timezone.now() - timedelta(minutes=1))
    call_command("pdf_sign_cleanup", "--dry-run")
    session.refresh_from_db()
    assert session.status == SigningStatus.PREPARED


@pytest.mark.django_db
def test_keeps_live_sessions() -> None:
    session = _session()
    call_command("pdf_sign_cleanup")
    session.refresh_from_db()
    assert session.status == SigningStatus.PREPARED


@pytest.mark.django_db
def test_deletes_stale_expired_sessions() -> None:
    session = _session(
        status=SigningStatus.EXPIRED,
        expires_at=timezone.now() - timedelta(days=30),
    )
    SigningSession.objects.filter(pk=session.pk).update(
        created_at=timezone.now() - timedelta(days=30)
    )
    call_command("pdf_sign_cleanup", "--retention-days", "7")
    assert not SigningSession.objects.filter(pk=session.pk).exists()


@pytest.mark.django_db
def test_keeps_recent_expired_sessions() -> None:
    session = _session(
        status=SigningStatus.EXPIRED,
        expires_at=timezone.now() - timedelta(minutes=1),
    )
    call_command("pdf_sign_cleanup", "--retention-days", "7")
    assert SigningSession.objects.filter(pk=session.pk).exists()
