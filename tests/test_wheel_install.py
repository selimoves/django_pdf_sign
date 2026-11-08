import os
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.wheel


@pytest.fixture(scope="module")
def wheel_path() -> Path:
    value = os.environ.get("WHEEL_PATH")
    if not value:
        pytest.skip("WHEEL_PATH не задан")
    return Path(value)


def test_wheel_contains_runtime_files(wheel_path: Path) -> None:
    with zipfile.ZipFile(wheel_path) as archive:
        names = set(archive.namelist())
    assert "django_pdf_sign/py.typed" in names
    assert "django_pdf_sign/fonts/DejaVuSans.ttf" in names
    assert any(n.endswith("migrations/0001_initial.py") for n in names)
