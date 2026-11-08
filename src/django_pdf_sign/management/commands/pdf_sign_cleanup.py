"""Expire stale signing sessions and delete their prepared files."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandParser
from django.utils import timezone

from django_pdf_sign.constants import SigningStatus
from django_pdf_sign.models import SigningSession


class Command(BaseCommand):
    """Mark expired sessions and remove stale ones."""

    help = (
        "Mark expired signing sessions as expired, delete their prepared "
        "files, and remove stale sessions older than the retention window."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change without writing anything.",
        )
        parser.add_argument(
            "--retention-days",
            type=int,
            default=7,
            help="Delete expired or failed sessions older than this many days.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run: bool = options["dry_run"]
        retention_days: int = options["retention_days"]
        now = timezone.now()

        expired = SigningSession.objects.filter(
            status=SigningStatus.PREPARED, expires_at__lt=now
        )
        expired_count = expired.count()
        if not dry_run:
            for session in expired:
                session.prepared_pdf.delete(save=False)
                session.status = SigningStatus.EXPIRED
                session.save(update_fields=["status"])

        cutoff = now - timedelta(days=retention_days)
        stale = SigningSession.objects.filter(
            status__in=[SigningStatus.EXPIRED, SigningStatus.FAILED],
            created_at__lt=cutoff,
        )
        stale_count = stale.count()
        if not dry_run:
            for session in stale:
                session.prepared_pdf.delete(save=False)
            stale.delete()

        prefix = "Would expire" if dry_run else "Expired"
        self.stdout.write(
            f"{prefix} {expired_count} session(s); "
            f"{'would delete' if dry_run else 'deleted'} "
            f"{stale_count} stale session(s)."
        )
