"""Интероп-проверка с реальным КриптоПро CSP через Docker.

Скрипт собирает образ из ``docker/cryptopro`` (архив CSP кладётся в
``docker/cryptopro/dist``), экспортирует тестовый сертификат и подписывает
переданные байты. Используется тестом ``tests/test_cryptopro_interop.py``.

Пример:
    uv run python tools/cryptopro_interop.py --bytes-to-sign bytes.bin --out cms.der
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKER_DIR = ROOT / "docker" / "cryptopro"
DIST_DIR = DOCKER_DIR / "dist"
ARCHIVE = DIST_DIR / "linux-amd64_deb.tgz"
IMAGE = "django-pdf-sign-cryptopro:latest"


def docker_available() -> bool:
    """Есть ли Docker и запущен ли демон."""
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, check=False
    )
    return result.returncode == 0


def archive_available() -> bool:
    """Скачан ли архив КриптоПро CSP."""
    return ARCHIVE.exists()


def build_image(*, force: bool = False) -> None:
    """Собрать образ с КриптоПро CSP и pycades."""
    if not archive_available():
        raise FileNotFoundError(
            f"Нет архива CSP: положите linux-amd64_deb.tgz в {DIST_DIR}"
        )
    if not force and _image_exists():
        return
    subprocess.run(
        ["docker", "build", "-t", IMAGE, str(DOCKER_DIR)],
        check=True,
    )


def _image_exists() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def export_certificate() -> bytes:
    """Экспортировать сертификат тестового ключа КриптоПро (DER)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "cert.der"
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp}:/work",
                IMAGE,
                "export-cert",
                "/work/cert.der",
            ],
            check=True,
        )
        return out.read_bytes()


def sign_bytes(payload: bytes) -> bytes:
    """Подписать байты тестовым ключом КриптоПро и вернуть CMS (DER)."""
    with tempfile.TemporaryDirectory() as tmp:
        bytes_path = Path(tmp) / "bytes.bin"
        cms_path = Path(tmp) / "cms.der"
        bytes_path.write_bytes(payload)
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp}:/work",
                IMAGE,
                "sign",
                "/work/bytes.bin",
                "/work/cms.der",
            ],
            check=True,
        )
        return cms_path.read_bytes()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytes-to-sign", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args(argv)

    if not docker_available():
        print("Docker недоступен", file=sys.stderr)
        return 1
    if args.build:
        build_image(force=True)

    if args.cert is not None:
        args.cert.write_bytes(export_certificate())
        print(f"сертификат записан: {args.cert}")
    if args.bytes_to_sign is not None and args.out is not None:
        args.out.write_bytes(sign_bytes(args.bytes_to_sign.read_bytes()))
        print(f"CMS записана: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
