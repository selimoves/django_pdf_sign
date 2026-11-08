"""Tests for the read-only admin."""

from __future__ import annotations

from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory

from django_pdf_sign.admin import SignatureRecordAdmin, SigningSessionAdmin
from django_pdf_sign.models import SignatureRecord, SigningSession


def test_signing_session_admin_is_read_only() -> None:
    model_admin = SigningSessionAdmin(SigningSession, AdminSite())
    request = RequestFactory().get("/admin/")
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert model_admin.has_delete_permission(request) is False


def test_signature_record_admin_is_read_only() -> None:
    model_admin = SignatureRecordAdmin(SignatureRecord, AdminSite())
    request = RequestFactory().get("/admin/")
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert model_admin.has_delete_permission(request) is False
