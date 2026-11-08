"""Exception hierarchy for django-pdf-sign."""

from __future__ import annotations


class DjangoPdfSignError(Exception):
    """Base class for every package error."""


class CertificateError(DjangoPdfSignError):
    """A certificate could not be parsed or is unusable."""


class SigningError(DjangoPdfSignError):
    """A document could not be prepared or a CMS could not be embedded."""


class SessionError(DjangoPdfSignError):
    """A signing session is missing, expired, reused or owned by someone else."""


class VerificationError(DjangoPdfSignError):
    """A CMS or a signed PDF failed verification."""
