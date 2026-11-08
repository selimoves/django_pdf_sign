"""Создать офлайн-фикстуру реальной подписи КриптоПро.

Скрипт прогоняет полный цикл через сервисы пакета и Docker-образ с
КриптоПро CSP, затем сохраняет в ``tests/fixtures/cryptopro/`` только
публичные артефакты: сертификат, байты для подписи, CMS и подписанный PDF.
Закрытый ключ остаётся в контейнере и в репозиторий не попадает.

Запуск:
    uv run python tools/make_cryptopro_fixture.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django  # noqa: E402

django.setup()

import cryptopro_interop  # noqa: E402
from django.core.files.base import ContentFile  # noqa: E402
from django.core.management import call_command  # noqa: E402

from django_pdf_sign.services import (  # noqa: E402
    VerificationPolicy,
    complete_signing,
    prepare_signing,
)
from tests.helpers import minimal_pdf  # noqa: E402
from tests.models import Document  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "cryptopro"


def main() -> int:
    if not cryptopro_interop.docker_available():
        print("Docker недоступен", file=sys.stderr)
        return 1
    if not cryptopro_interop.archive_available():
        print("Нет архива CSP в docker/cryptopro/dist", file=sys.stderr)
        return 1

    cryptopro_interop.build_image()
    call_command("migrate", verbosity=0, run_syncdb=True)
    certificate_der = cryptopro_interop.export_certificate()

    document = Document.objects.create(
        file=ContentFile(minimal_pdf(), name="fixture.pdf")
    )
    prepared = prepare_signing(document=document, certificate_der=certificate_der)
    cms = cryptopro_interop.sign_bytes(prepared.bytes_to_sign)

    root = (ROOT / "tests/fixtures/crypto/pycades-root.cer").read_bytes()
    crl = (ROOT / "tests/fixtures/crypto/pycades-root.crl").read_bytes()
    policy = VerificationPolicy(
        check_chain=True,
        trust_roots=(root,),
        crls=(crl,),
        revocation_mode="require",
    )
    result = complete_signing(session_id=prepared.session.pk, cms=cms, policy=policy)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "pycades-test.cer").write_bytes(certificate_der)
    (OUT / "pycades-test.bytes").write_bytes(prepared.bytes_to_sign)
    (OUT / "pycades-test.cms").write_bytes(cms)
    (OUT / "pycades-test-signed.pdf").write_bytes(result.signed_pdf)

    print(f"сертификат: {len(certificate_der)} байт")
    print(f"байты для подписи: {len(prepared.bytes_to_sign)} байт")
    print(f"CMS: {len(cms)} байт")
    print(f"подписанный PDF: {len(result.signed_pdf)} байт")
    print(f"статус проверки: {result.record.verification_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
