"""Публичные сервисы django-pdf-sign."""

from __future__ import annotations

from django_pdf_sign.crypto.policy import VerificationPolicy
from django_pdf_sign.crypto.validation import ChainResult
from django_pdf_sign.services.complete import CompletionResult, complete_signing
from django_pdf_sign.services.prepare import PreparedSigning, prepare_signing
from django_pdf_sign.services.verify import (
    VerificationResult,
    verify_cms_over_bytes,
    verify_signed_pdf,
)

__all__ = [
    "ChainResult",
    "CompletionResult",
    "PreparedSigning",
    "VerificationPolicy",
    "VerificationResult",
    "complete_signing",
    "prepare_signing",
    "verify_cms_over_bytes",
    "verify_signed_pdf",
]
