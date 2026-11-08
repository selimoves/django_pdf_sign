import importlib.metadata

import django_pdf_sign


def test_version_is_pep440():
    version = django_pdf_sign.__version__
    assert version and version[0].isdigit()


def test_version_matches_distribution():
    assert django_pdf_sign.__version__ == importlib.metadata.version("django-pdf-sign")
