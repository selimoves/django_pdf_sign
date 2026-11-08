# План подготовки django-pdf-sign к версии 1.0

> **Для агентов:** обязательный навык — `superpowers:executing-plans` (исполнение в этой сессии) или `superpowers:subagent-driven-development` (по задаче на субагента). Шаги помечены чекбоксами (`- [ ]`).

**Цель:** довести `django-pdf-sign` до публичного релиза 1.0 на PyPI с замороженным API, гарантированным качеством, внутренним security-ревью и полноценной документацией.

**Архитектура:** изменений архитектуры нет. Работы идут слоями: процесс релиза и версионирование (M1), глубина и надёжность тестов (M2), безопасность и эксплуатация (M3), документация и сообщество (M4), выпуск 1.0 (M5).

**Стек:** Python 3.11–3.13, Django 5.2/6.0/6.1, pyHanko 0.38, asn1crypto, cryptography, gostcrypto, pytest, hypothesis, atheris, pytest-benchmark, pytest-cov, ruff, mypy + django-stubs, uv, hatchling + hatch-vcs, MkDocs Material + mkdocstrings, GitHub Actions, PyPI Trusted Publishing.

**Спецификация:** `docs/superpowers/specs/2026-11-08-django-pdf-sign-design.md`

## Глобальные ограничения

- Поддерживаемые версии: Python 3.11 только с Django 5.2; Python 3.12 и 3.13 — с Django 5.2, 6.0 и 6.1. **Django 4.2 из поддержки исключается.**
- Первая публичная версия — `0.1.0`; тег `v0.1.0`; далее SemVer.
- Версия в артефакте берётся из git-тега через `hatch-vcs`, ручного дублирования нет.
- Публикация только через PyPI Trusted Publishing: `environment: testpypi` автоматически, `environment: pypi` — после ручного одобрения. Токены и пароли не хранятся.
- Публичные имена API перечислены в `docs/api.md`; всё остальное — внутреннее и может меняться без предупреждения.
- Покрытие ветвей не ниже 90% на момент 1.0; порог в CI обязателен.
- Безопасность: внутреннее ревью и fuzzing, внешний аудит не проводится.
- Секреты, закрытые ключи, PIN и сырая CMS в логах запрещены.
- Вся документация, docstring и комментарии — на русском языке.
- `ALLOW_FETCHING=False` по умолчанию; при включении обязателен `FETCH_ALLOWED_HOSTS`.

## Фокус ревью

- Публикация по тегу при отсутствии git-истории (`fetch-depth: 0`): версия не должна стать `0.0.0`.
- Конкурентный `complete_signing` на PostgreSQL: должна встроиться ровно одна подпись.
- Установленное колесо, а не editable: шрифт, `py.typed` и миграции доступны.
- Недоверенный ASN.1: произвольные байты дают только `VerificationError`/`CertificateError`, без падений и зависаний.
- `ALLOW_FETCHING=True` без allowlist: запрос к произвольному хосту должен быть отклонён.
- Некорректные настройки в `DJANGO_PDF_SIGN`: падение на старте с понятным сообщением, а не в момент подписи.

## Журнал верификации

Результат каждой задачи записывается сюда после последнего шага.

| Задача | Команда | Результат |
|--------|---------|-----------|
| — | — | — |

---

# M1. Стабилизация API и релизный процесс

### Задача 1: Версионирование из git-тега

**Файлы**
- Изменить: `pyproject.toml`, `src/django_pdf_sign/__init__.py`, `.gitignore`
- Создать: `src/django_pdf_sign/_version.py` (генерируется при сборке)

**Интерфейсы**
- Использует: git-теги вида `vX.Y.Z`.
- Даёт: `django_pdf_sign.__version__` всегда совпадает с тегом; `importlib.metadata.version("django-pdf-sign")` работает в установленном колесе.

- [ ] **Шаг 1: Написать падающий тест**

`tests/test_version.py`:

```python
import importlib.metadata

import django_pdf_sign


def test_version_is_pep440():
    version = django_pdf_sign.__version__
    assert version and version[0].isdigit()


def test_version_matches_distribution():
    assert django_pdf_sign.__version__ == importlib.metadata.version("django-pdf-sign")
```

- [ ] **Шаг 2: Убедиться, что тест падает**

Run: `uv run pytest tests/test_version.py -q`
Expected: FAIL — текущая версия задана вручную и не совпадает с метаданными после перехода на `dynamic`.

- [ ] **Шаг 3: Перевести `pyproject.toml` на `hatch-vcs`**

```toml
[build-system]
requires = ["hatchling>=1.27", "hatch-vcs>=0.5"]
build-backend = "hatchling.build"

[project]
dynamic = ["version"]

[tool.hatch.version]
source = "vcs"
raw-options = { version_scheme = "guess-next-dev", local_scheme = "no-local-version" }

[tool.hatch.build.hooks.vcs]
version-file = "src/django_pdf_sign/_version.py"
```

- [ ] **Шаг 4: Читать версию из метаданных**

`src/django_pdf_sign/__init__.py`:

```python
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("django-pdf-sign")
except PackageNotFoundError:  # исходное дерево без установки
    from django_pdf_sign._version import __version__
```

- [ ] **Шаг 5: Добавить `_version.py` в `.gitignore`**

- [ ] **Шаг 6: Проверить**

Run: `uv sync --all-extras && uv run pytest tests/test_version.py -q`
Expected: PASS.

Run: `uv build && uv run python -c "import zipfile,glob;print([n for n in zipfile.ZipFile(glob.glob('dist/*.whl')[0]).namelist() if '_version' in n])"`
Expected: файл `django_pdf_sign/_version.py` присутствует в колесе.

- [ ] **Шаг 7: Коммит**

```bash
git add pyproject.toml src/django_pdf_sign/__init__.py .gitignore tests/test_version.py
git commit -m "build: версия из git-тега через hatch-vcs"
```

---

### Задача 2: Публичный контракт API

**Файлы**
- Создать: `docs/api.md`, `docs/versioning.md`
- Изменить: `src/django_pdf_sign/services/__init__.py` (докстринг со ссылкой)

**Интерфейсы**
- Использует: существующие публичные имена.
- Даёт: перечень стабильных имён, правила SemVer и депрекации.

- [ ] **Шаг 1: Написать `docs/api.md`**

Таблица стабильных имён с сигнатурами:

| Имя | Модуль |
|-----|--------|
| `prepare_signing` | `django_pdf_sign.services` |
| `complete_signing` | `django_pdf_sign.services` |
| `verify_cms_over_bytes` | `django_pdf_sign.services` |
| `verify_signed_pdf` | `django_pdf_sign.services` |
| `VerificationPolicy` | `django_pdf_sign.services` |
| `PreparedSigning`, `CompletionResult`, `VerificationResult`, `ChainResult` | `django_pdf_sign.services` |
| `SigningSession`, `SignatureRecord` | `django_pdf_sign.models` |
| `DJANGO_PDF_SIGN` | `django_pdf_sign.conf` |

Явно указать: `django_pdf_sign.crypto.*`, `django_pdf_sign.pdf.*`, `django_pdf_sign.services.prepare/complete/verify` — внутренние.

- [ ] **Шаг 2: Написать `docs/versioning.md`**

SemVer; ломающее изменение — только в мажоре; удаление проходит через минорный релиз с `DeprecationWarning` и минимум один релиз; срок поддержки: текущая и предыдущая минорные, последняя LTS Django.

- [ ] **Шаг 3: Проверить, что документ соответствует коду**

Run: `uv run python -c "import django_pdf_sign.services as s; print(sorted(s.__all__))"`
Expected: каждое имя из вывода присутствует в `docs/api.md`.

- [ ] **Шаг 4: Коммит**

```bash
git add docs/api.md docs/versioning.md src/django_pdf_sign/services/__init__.py
git commit -m "docs: публичный контракт API и политика версий"
```

---

### Задача 3: CHANGELOG и SUPPORT

**Файлы**
- Создать: `CHANGELOG.md`, `SUPPORT.md`

**Интерфейсы**
- Использует: решения по версиям.
- Даёт: историю изменений и матрицу поддержки.

- [ ] **Шаг 1: Создать `CHANGELOG.md`** (Keep a Changelog, `## [Unreleased]`, `## [0.1.0]` со списком возможностей и удалением Django 4.2).

- [ ] **Шаг 2: Создать `SUPPORT.md`** с таблицей:

| Python | Django 5.2 LTS | Django 6.0 | Django 6.1 |
|--------|----------------|------------|------------|
| 3.11 | да | нет | нет |
| 3.12 | да | да | да |
| 3.13 | да | да | да |

- [ ] **Шаг 3: Коммит**

```bash
git add CHANGELOG.md SUPPORT.md
git commit -m "docs: changelog и матрица поддержки"
```

---

### Задача 4: Матрица CI и проверка миграций

**Файлы**
- Изменить: `pyproject.toml` (`django>=5.2`, классификаторы), `.github/workflows/ci.yml`

**Интерфейсы**
- Использует: `SUPPORT.md`.
- Даёт: CI на поддерживаемых комбинациях, проверка отсутствия неприменённых миграций.

- [ ] **Шаг 1: Обновить `pyproject.toml`**

`django>=5.2`; убрать классификатор `Framework :: Django :: 4.2`; `Development Status :: 4 - Beta`; добавить `Framework :: Django :: 6.0`.

- [ ] **Шаг 2: Обновить матрицу `.github/workflows/ci.yml`**

Комбинации: 3.11/5.2; 3.12/5.2, 6.0, 6.1; 3.13/5.2, 6.0, 6.1; ОС `ubuntu-latest` и `windows-latest`. Во все checkout добавить `fetch-depth: 0`.

- [ ] **Шаг 3: Добавить проверку миграций**

```yaml
- name: Migrations check
  run: uv run python -m django makemigrations --check --dry-run --settings=tests.settings
```

- [ ] **Шаг 4: Проверить локально**

Run: `uv run python -m django makemigrations --check --dry-run --settings=tests.settings`
Expected: `No changes detected`.

Run: `uv run pytest -q`
Expected: все тесты проходят.

- [ ] **Шаг 5: Коммит**

```bash
git add pyproject.toml .github/workflows/ci.yml
git commit -m "ci: матрица Django 5.2/6.0/6.1 и проверка миграций"
```

---

### Задача 5: Workflow релиза

**Файлы**
- Создать: `.github/workflows/release.yml`

**Интерфейсы**
- Использует: Trusted Publisher `pypi` и `testpypi` (зарегистрированы пользователем).
- Даёт: публикацию по тегу `v*` с проверкой, TestPyPI, ручным одобрением и provenance.

- [ ] **Шаг 1: Создать `.github/workflows/release.yml`**

```yaml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: astral-sh/setup-uv@v5
        with: { python-version: "3.13" }
      - run: uv sync --all-extras
      - run: uv build
      - run: uv run twine check dist/*
      - run: uv run python -c "import glob,zipfile;z=zipfile.ZipFile(glob.glob('dist/*.whl')[0]);print([n for n in z.namelist() if 'METADATA' in n])"
      - uses: actions/upload-artifact@v4
        with: { name: dist, path: dist/ }
  testpypi:
    needs: build
    runs-on: ubuntu-latest
    environment: testpypi
    permissions: { id-token: write }
    steps:
      - uses: actions/download-artifact@v4
        with: { name: dist, path: dist/ }
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/
          attestations: true
  pypi:
    needs: testpypi
    runs-on: ubuntu-latest
    environment: pypi
    permissions: { id-token: write }
    steps:
      - uses: actions/download-artifact@v4
        with: { name: dist, path: dist/ }
      - uses: pypa/gh-action-pypi-publish@release/v1
        with: { attestations: true }
```

- [ ] **Шаг 2: Проверить локально сборку и версию**

Run: `git tag v0.1.0 && uv build && uv run python -c "import glob;print(glob.glob('dist/*'))"`
Expected: имена артефактов содержат `0.1.0`; затем `git tag -d v0.1.0` до фактического релиза.

- [ ] **Шаг 3: Коммит**

```bash
git add .github/workflows/release.yml
git commit -m "ci: релиз на PyPI через Trusted Publishing"
```

---

### Задача 6: Первая публикация на TestPyPI

**Файлы:** нет.

**Интерфейсы**
- Использует: `release.yml`, Trusted Publisher.
- Даёт: подтверждённую публикацию `0.1.0` на TestPyPI.

- [ ] **Шаг 1: Поставить тег и запушить**

```bash
git tag v0.1.0
git push origin main --tags
```

- [ ] **Шаг 2: Проверить публикацию в чистом окружении**

Run (после успешного workflow):
`uv venv .tmp/tp --python 3.13; uv pip install --python .tmp/tp/Scripts/python.exe --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ django-pdf-sign==0.1.0; .tmp/tp/Scripts/python.exe -c "import django_pdf_sign; print(django_pdf_sign.__version__)"`
Expected: `0.1.0`.

- [ ] **Шаг 3: Одобрить публикацию на PyPI** (ручное действие пользователя в GitHub Environment).

---

# M2. Глубина проверки

### Задача 7: Порог покрытия

**Файлы**
- Изменить: `pyproject.toml`, `.github/workflows/ci.yml`

**Интерфейсы**
- Использует: существующие тесты.
- Даёт: обязательный порог покрытия ветвей.

- [ ] **Шаг 1: Замерить базу**

Run: `uv run pytest --cov=django_pdf_sign --cov-branch --cov-report=term-missing -q`
Expected: отчёт с текущим процентом; значение зафиксировать в журнале.

- [ ] **Шаг 2: Включить порог**

В `[tool.pytest.ini_options] addopts` добавить `--cov=django_pdf_sign --cov-branch --cov-report=term-missing --cov-fail-under=<база>`; в CI — отдельный шаг `coverage`.

- [ ] **Шаг 3: Проверить**

Run: `uv run pytest -q`
Expected: PASS при покрытии не ниже порога.

- [ ] **Шаг 4: Коммит**

```bash
git add pyproject.toml .github/workflows/ci.yml
git commit -m "test: обязательный порог покрытия ветвей"
```

---

### Задача 8: PostgreSQL и конкуренция

**Файлы**
- Создать: `tests/settings_postgres.py`, `tests/test_concurrency.py`
- Изменить: `.github/workflows/ci.yml`

**Интерфейсы**
- Использует: `complete_signing`, `SigningSession`.
- Даёт: доказанное поведение `select_for_update()` (`services/complete.py:49`).

- [ ] **Шаг 1: Написать падающий тест**

`tests/test_concurrency.py`:

```python
import threading

import pytest
from django.core.files.base import ContentFile
from django.db import connection, connections

from django_pdf_sign.exceptions import SessionError
from django_pdf_sign.services import complete_signing, prepare_signing
from tests.helpers import make_rsa_certificate, make_rsa_cms, minimal_pdf
from tests.models import Document

pytestmark = pytest.mark.skipif(
    connection.vendor != "postgresql", reason="нужен PostgreSQL"
)


@pytest.mark.django_db(transaction=True)
def test_concurrent_complete_embeds_once():
    info, key = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(minimal_pdf(), name="d.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    cms, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        barrier.wait()
        try:
            complete_signing(session_id=prepared.session.pk, cms=cms)
            outcomes.append("ok")
        except SessionError:
            outcomes.append("rejected")
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["ok", "rejected"]
```

- [ ] **Шаг 2: Создать `tests/settings_postgres.py`** — копия `tests/settings.py` с `DATABASES` из переменных `POSTGRES_*`.

- [ ] **Шаг 3: Добавить сервис PostgreSQL в CI** (`services: postgres:16`) и шаг с `--ds=tests.settings_postgres` для этого job.

- [ ] **Шаг 4: Проверить на PostgreSQL локально** (Docker):

Run: `docker run --rm -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16` и
`$env:POSTGRES_DB="postgres"; uv run pytest tests/test_concurrency.py --ds=tests.settings_postgres -q`
Expected: PASS.

- [ ] **Шаг 5: Коммит**

```bash
git add tests/settings_postgres.py tests/test_concurrency.py .github/workflows/ci.yml
git commit -m "test: конкуренция complete_signing на PostgreSQL"
```

---

### Задача 9: Проверка установленного колеса

**Файлы**
- Создать: `tests/test_wheel_install.py` (маркер `wheel`), `.github/workflows/ci.yml` (job)

**Интерфейсы**
- Использует: собранное колесо.
- Даёт: гарантию, что шрифт, `py.typed` и миграции попадают в артефакт.

- [ ] **Шаг 1: Написать тест-проверку артефакта**

`tests/test_wheel_install.py`:

```python
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
```

- [ ] **Шаг 2: Зарегистрировать маркеры и добавить job в CI**

В `[tool.pytest.ini_options] markers` добавить `wheel` и `benchmark` (иначе `--strict-markers` упадёт). Job `wheel`: `uv build`, затем `$env:WHEEL_PATH` = путь к собранному колесу и `uv run pytest tests/test_wheel_install.py -q`; отдельный шаг — установка колеса в чистый venv и smoke-импорт.

- [ ] **Шаг 3: Проверить**

Run: `uv build; $env:WHEEL_PATH = (Get-ChildItem dist/*.whl).FullName; uv run pytest tests/test_wheel_install.py -q`
Expected: PASS.

- [ ] **Шаг 4: Коммит**

```bash
git add tests/test_wheel_install.py pyproject.toml .github/workflows/ci.yml
git commit -m "test: проверка содержимого и установки колеса"
```

---

### Задача 10: Property-тесты парсеров

**Файлы**
- Создать: `tests/test_properties.py`
- Изменить: `pyproject.toml` (`hypothesis` в `dev`)

**Интерфейсы**
- Использует: `parse_cms`, `parse_certificate`, `evaluate_ocsps`, `verify_timestamp_token`.
- Даёт: гарантию, что недоверенный ввод даёт только доменные исключения.

- [ ] **Шаг 1: Написать тесты**

```python
from hypothesis import given, settings, strategies as st

from django_pdf_sign.crypto.certs import parse_certificate
from django_pdf_sign.crypto.cms import parse_cms
from django_pdf_sign.exceptions import CertificateError, VerificationError


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=4096))
def test_parse_cms_never_raises_other(data: bytes) -> None:
    try:
        parse_cms(data)
    except VerificationError:
        pass


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=4096))
def test_parse_certificate_never_raises_other(data: bytes) -> None:
    try:
        parse_certificate(data)
    except CertificateError:
        pass
```

- [ ] **Шаг 2: Проверить**

Run: `uv run pytest tests/test_properties.py -q`
Expected: PASS; найденные падения исправить в парсерах, а не ослаблять тест.

- [ ] **Шаг 3: Коммит**

```bash
git add tests/test_properties.py pyproject.toml
git commit -m "test: property-тесты разбора недоверенного ASN.1"
```

---

### Задача 11: Fuzzing

**Файлы**
- Создать: `fuzz/fuzz_cms.py`, `fuzz/fuzz_ocsp.py`, `fuzz/fuzz_timestamp.py`, `fuzz/fuzz_cert.py`, `.github/workflows/fuzz.yml`
- Изменить: `pyproject.toml` (extra `fuzz`)

**Интерфейсы**
- Использует: парсеры.
- Даёт: ночной fuzzing с падением CI при находке.

- [ ] **Шаг 1: Создать цели**

`fuzz/fuzz_cms.py`:

```python
import atheris
import sys

with atheris.instrument_imports():
    from django_pdf_sign.crypto.cms import parse_cms
    from django_pdf_sign.exceptions import VerificationError


def test_one_input(data: bytes) -> None:
    try:
        parse_cms(data)
    except VerificationError:
        pass


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
```

Аналогично для OCSP, метки времени и сертификата.

- [ ] **Шаг 2: Workflow `fuzz.yml`** — `ubuntu-latest`, `schedule` ночью и `workflow_dispatch`, `-max_total_time=120` на каждую цель.

- [ ] **Шаг 3: Проверить локально (Linux/Docker)**

Run: `docker run --rm -v "$PWD:/src" -w /src python:3.13 bash -lc "pip install atheris . && python fuzz/fuzz_cms.py -max_total_time=20"`
Expected: завершение без падений.

- [ ] **Шаг 4: Коммит**

```bash
git add fuzz .github/workflows/fuzz.yml pyproject.toml
git commit -m "test: fuzzing парсеров ASN.1"
```

---

### Задача 12: Граничные случаи PDF

**Файлы**
- Создать: `tests/test_pdf_edge_cases.py`

**Интерфейсы**
- Использует: `prepare_signing`, `complete_signing`, `verify_signed_pdf`.
- Даёт: покрытие краевых документов.

- [ ] **Шаг 1: Написать тесты**: шифрованный PDF → `SigningError`; PDF с инкрементальными обновлениями → подпись проходит; повреждённый PDF → `SigningError`; PDF с двумя полями подписи → `prepare_signing` создаёт третье, существующие не ломаются; пустой файл → `SigningError`; файл ровно на границе `MAX_DOCUMENT_BYTES` → проходит, на байт больше → `SigningError`; CMS больше плейсхолдера → `SigningError` и сессия остаётся `prepared`.

- [ ] **Шаг 2: Проверить**

Run: `uv run pytest tests/test_pdf_edge_cases.py -q`
Expected: PASS.

- [ ] **Шаг 3: Коммит**

```bash
git add tests/test_pdf_edge_cases.py
git commit -m "test: граничные случаи PDF"
```

---

### Задача 13: `signature_index` в `verify_signed_pdf`

**Файлы**
- Изменить: `src/django_pdf_sign/services/verify.py`, `tests/test_verify.py`

**Интерфейсы**
- Использует: существующий `verify_signed_pdf`.
- Даёт: `verify_signed_pdf(pdf: bytes, policy=None, signature_index: int = 0) -> VerificationResult`.

- [ ] **Шаг 1: Написать падающий тест** — PDF с двумя подписями: `signature_index=1` проверяет вторую, `signature_index=5` даёт `VerificationResult(valid=False)` с сообщением о недопустимом индексе.

- [ ] **Шаг 2: Реализовать параметр** (обратносовместимо, по умолчанию `0`).

- [ ] **Шаг 3: Проверить**

Run: `uv run pytest tests/test_verify.py -q`
Expected: PASS.

- [ ] **Шаг 4: Коммит**

```bash
git add src/django_pdf_sign/services/verify.py tests/test_verify.py
git commit -m "feat: выбор подписи по индексу в verify_signed_pdf"
```

---

### Задача 14: Бенчмарки и лимиты

**Файлы**
- Создать: `tests/test_benchmarks.py`, `docs/limits.md`
- Изменить: `pyproject.toml` (`pytest-benchmark`)

**Интерфейсы**
- Использует: `digest_for`, `prepare_document`.
- Даёт: документированные пределы.

- [ ] **Шаг 1: Написать бенчмарки** для `streebog256`/`streebog512` и `prepare_document` на 1/10/50 МБ (маркер `benchmark`, не входит в обычный прогон: `pytest -m benchmark`).

- [ ] **Шаг 2: Замерить и записать в `docs/limits.md`**: время на МБ, пиковая память, рекомендуемый `MAX_DOCUMENT_BYTES`.

- [ ] **Шаг 3: Коммит**

```bash
git add tests/test_benchmarks.py docs/limits.md pyproject.toml
git commit -m "test: бенчмарки и документированные лимиты"
```

---

### Задача 15: Порядок тестов и типы

**Файлы**
- Изменить: `pyproject.toml`, `.github/workflows/ci.yml`

**Интерфейсы**
- Использует: тесты и `django-stubs`.
- Даёт: независимость от порядка и проверку типов на двух версиях стабов.

- [ ] **Шаг 1: Добавить `pytest-randomly` и `pytest-xdist`** в `dev`, запуск `-p randomly -n auto` в CI.

- [ ] **Шаг 2: Добавить job mypy с `django-stubs~=5.2.0` и `~=6.1.0`.**

- [ ] **Шаг 3: Проверить**

Run: `uv run pytest -q -p randomly`
Expected: PASS при нескольких seed.

- [ ] **Шаг 4: Коммит**

```bash
git add pyproject.toml .github/workflows/ci.yml
git commit -m "ci: порядконезависимые тесты и mypy на двух версиях стабов"
```

---

# M3. Безопасность и эксплуатация

### Задача 16: SECURITY, модель угроз, ревью

**Файлы**
- Создать: `SECURITY.md`, `docs/threat-model.md`, `docs/security-review.md`

- [ ] **Шаг 1: `SECURITY.md`** — канал раскрытия (GitHub Security Advisories), сроки ответа (72 часа), поддерживаемые версии.

- [ ] **Шаг 2: `docs/threat-model.md`** — активы, границы доверия, сценарии: подмена байтов, подмена сертификата, повтор сессии, SSRF при загрузке отзыва, DoS через сложность ASN.1, утечка через логи.

- [ ] **Шаг 3: `docs/security-review.md`** — чек-лист с результатами и датой.

- [ ] **Шаг 4: Коммит**

```bash
git add SECURITY.md docs/threat-model.md docs/security-review.md
git commit -m "docs: политика безопасности, модель угроз и ревью"
```

---

### Задача 17: Зависимости, аудит, SBOM

**Файлы**
- Изменить: `pyproject.toml`, `.github/workflows/ci.yml`
- Создать: `.github/dependabot.yml`, `.github/workflows/security.yml`

- [ ] **Шаг 1: Верхние границы зависимостей**

`django>=5.2,<6.2`, `cryptography>=48,<51`, `asn1crypto>=1.5.1,<2`, `gostcrypto>=1.2.5,<2`, `pyhanko[opentype]>=0.38,<0.39`.

- [ ] **Шаг 2: `pip-audit` в CI**, Dependabot для pip и Actions, `cyclonedx-py` SBOM как артефакт.

- [ ] **Шаг 3: Проверить**

Run: `uv run pip-audit`
Expected: уязвимостей нет (или исправлены).

- [ ] **Шаг 4: Коммит**

```bash
git add pyproject.toml .github
git commit -m "build: границы зависимостей, аудит и SBOM"
```

---

### Задача 18: Allowlist для сетевой загрузки отзыва

**Файлы**
- Создать: `src/django_pdf_sign/crypto/fetchers.py`, `tests/test_fetchers.py`
- Изменить: `conf.py`, `crypto/policy.py`, `crypto/validation.py`

**Интерфейсы**
- Использует: `VerificationPolicy`.
- Даёт: `FETCH_ALLOWED_HOSTS: tuple[str, ...]`; fetcher отклоняет хосты вне списка.

- [ ] **Шаг 1: Написать падающий тест** — `allow_fetching=True` и пустой allowlist → `VerificationError`; хост вне списка → отказ; хост из списка → запрос разрешён (мок).

- [ ] **Шаг 2: Реализовать `AllowlistFetcherBackend`** и проверку конфигурации.

- [ ] **Шаг 3: Проверить**

Run: `uv run pytest tests/test_fetchers.py -q`
Expected: PASS.

- [ ] **Шаг 4: Коммит**

```bash
git add src/django_pdf_sign/crypto/fetchers.py tests/test_fetchers.py src/django_pdf_sign/conf.py src/django_pdf_sign/crypto
git commit -m "feat: allowlist хостов для сетевой загрузки отзыва"
```

---

### Задача 19: Django system checks

**Файлы**
- Создать: `src/django_pdf_sign/checks.py`, `tests/test_checks.py`
- Изменить: `apps.py`

- [ ] **Шаг 1: Написать падающие тесты** — несуществующий `TRUST_ROOTS`, неверный `REVOCATION_MODE`, `SESSION_TTL <= 0`, некорректный `DEFAULT_BOX`, неизвестный SubFilter → ошибка `checks.Error` с понятным текстом.

- [ ] **Шаг 2: Реализовать проверки** и подключить в `DjangoPdfSignConfig.ready()`.

- [ ] **Шаг 3: Проверить**

Run: `uv run pytest tests/test_checks.py -q`
Expected: PASS.

- [ ] **Шаг 4: Коммит**

```bash
git add src/django_pdf_sign/checks.py tests/test_checks.py src/django_pdf_sign/apps.py
git commit -m "feat: system checks настроек"
```

---

### Задача 20: Логирование и события

**Файлы**
- Создать: `src/django_pdf_sign/events.py`, `tests/test_events.py`
- Изменить: `services/prepare.py`, `services/complete.py`, `conf.py`

**Интерфейсы**
- Использует: настройку `ON_EVENT`.
- Даёт: события `session_prepared`, `signing_completed`, `verification_failed`; логгер `django_pdf_sign`; отсутствие CMS, ключей и PIN в сообщениях.

- [ ] **Шаг 1: Написать тесты** — событие вызывается с именем и безопасными полями; в логах нет CMS; исключение в обработчике не ломает подпись.

- [ ] **Шаг 2: Реализовать `emit(event, **fields)`** и вызовы в сервисах.

- [ ] **Шаг 3: Проверить**

Run: `uv run pytest tests/test_events.py -q`
Expected: PASS.

- [ ] **Шаг 4: Коммит**

```bash
git add src/django_pdf_sign/events.py tests/test_events.py src/django_pdf_sign/services src/django_pdf_sign/conf.py
git commit -m "feat: события и безопасное логирование"
```

---

### Задача 21: Документ эксплуатации

**Файлы**
- Создать: `docs/operations.md`

- [ ] **Шаг 1: Описать** приватное хранение PDF (локальный storage и S3), ретенцию, планировщик `pdf_sign_cleanup`, ротацию, мониторинг через `ON_EVENT`.

- [ ] **Шаг 2: Коммит**

```bash
git add docs/operations.md
git commit -m "docs: эксплуатация и ретенция"
```

---

# M4. Документация и сообщество

### Задача 22: Сайт документации

**Файлы**
- Создать: `mkdocs.yml`, `docs/index.md`, `docs/quickstart.md`, `docs/settings.md`, `docs/troubleshooting.md`, `docs/faq.md`, `.github/workflows/docs.yml`

- [ ] **Шаг 1: Настроить MkDocs Material и mkdocstrings**, навигацию по существующим разделам.

- [ ] **Шаг 2: Написать** quickstart, полный справочник настроек, troubleshooting, FAQ.

- [ ] **Шаг 3: Workflow `docs.yml`** — сборка на PR, публикация на GitHub Pages из `main`.

- [ ] **Шаг 4: Проверить**

Run: `uv run mkdocs build --strict`
Expected: сборка без предупреждений.

- [ ] **Шаг 5: Коммит**

```bash
git add mkdocs.yml docs .github/workflows/docs.yml
git commit -m "docs: сайт документации на MkDocs"
```

---

### Задача 23: Cookbook и пример

**Файлы**
- Создать: `docs/cookbook/views.md`, `docs/cookbook/drf.md`, `docs/cookbook/browser.md`, `docs/cookbook/policy.md`, `examples/` (минимальный проект)

- [ ] **Шаг 1: Написать** рецепты Django views, DRF, браузерного клиента, проверки по политике.

- [ ] **Шаг 2: Создать запускаемый пример** сервер + браузер.

- [ ] **Шаг 3: Коммит**

```bash
git add docs/cookbook examples
git commit -m "docs: cookbook и запускаемый пример"
```

---

### Задача 24: Сообщество

**Файлы**
- Создать: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `ROADMAP.md`, `.github/ISSUE_TEMPLATE/bug.yml`, `.github/ISSUE_TEMPLATE/feature.yml`, `.github/PULL_REQUEST_TEMPLATE.md`

- [ ] **Шаг 1: Написать** правила вклада, Contributor Covenant, дорожную карту, шаблоны.

- [ ] **Шаг 2: Коммит**

```bash
git add CONTRIBUTING.md CODE_OF_CONDUCT.md ROADMAP.md .github
git commit -m "docs: правила сообщества и шаблоны"
```

---

### Задача 25: pre-commit

**Файлы**
- Создать: `.pre-commit-config.yaml`

- [ ] **Шаг 1: Настроить** ruff, ruff-format, mypy, end-of-file-fixer, trailing-whitespace.

- [ ] **Шаг 2: Проверить**

Run: `uv run pre-commit run --all-files`
Expected: все хуки проходят.

- [ ] **Шаг 3: Коммит**

```bash
git add .pre-commit-config.yaml
git commit -m "chore: pre-commit"
```

---

### Задача 26: README для 1.0

**Файлы**
- Изменить: `README.md`

- [ ] **Шаг 1: Убрать строку о нестабильности**, обновить матрицу версий, добавить ссылки на сайт документации, changelog и политику безопасности.

- [ ] **Шаг 2: Коммит**

```bash
git add README.md
git commit -m "docs: README для 1.0"
```

---

# M5. Выпуск 1.0

### Задача 27: 1.0.0

**Файлы**
- Изменить: `CHANGELOG.md`, `pyproject.toml`

- [ ] **Шаг 1: Заморозить API**, обновить `docs/api.md` и `CHANGELOG.md` секцией `1.0.0`.

- [ ] **Шаг 2: Классификатор `Production/Stable`**, тег `v1.0.0`.

- [ ] **Шаг 3: Проверить публикацию**

Run: `uv venv .tmp/final --python 3.13; uv pip install --python .tmp/final/Scripts/python.exe django-pdf-sign==1.0.0; .tmp/final/Scripts/python.exe -c "import django_pdf_sign; print(django_pdf_sign.__version__)"`
Expected: `1.0.0`.

- [ ] **Шаг 4: Release notes и коммит**

```bash
git add CHANGELOG.md pyproject.toml docs/api.md README.md
git commit -m "release: 1.0.0"
git tag v1.0.0
git push origin main --tags
```

---

## Финальная проверка

- [ ] `uv run pytest -q` — все тесты проходят, покрытие не ниже порога.
- [ ] `uv run ruff check .`, `uv run ruff format --check .`, `uv run python -m mypy` — чисто.
- [ ] `uv build` и `uv run twine check dist/*` — оба артефакта проходят.
- [ ] Установка колеса в чистом venv: импорт, шрифт, миграции.
- [ ] `pip-audit` — без уязвимостей.
- [ ] Публикация на TestPyPI и PyPI с provenance.
- [ ] Результаты всех задач записаны в журнал верификации.

## Открытые решения (по умолчанию приняты, можно изменить)

1. Первая версия — `0.1.0` (публичной истории нет).
2. Схема релиза — TestPyPI автоматически по тегу, PyPI после ручного одобрения.
3. Хранилище — документируются оба варианта; тесты используют `InMemoryStorage` и `FileSystemStorage`.
4. Мультиподпись — только параметр `signature_index`, полноценная поддержка после 1.0.
