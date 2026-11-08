# django-pdf-sign

Клиентские электронные подписи PDF-документов в Django.

Сервер никогда не хранит закрытые ключи. Он подготавливает PDF с видимым
штампом, передаёт браузеру точные байты для подписи (плагин КриптоПро),
проверяет присланную отсоединённую CMS и встраивает её в документ.

- **ГОСТ Р 34.10-2012 / CAdES-BES** — квалифицированные подписи
  (Стрибог-256/512), проверяемые российскими валидаторами при наличии
  квалифицированного сертификата.
- **PAdES / RSA-ECDSA** — подписи, совместимые с Adobe.

## Установка

```bash
pip install django-pdf-sign
```

Серверу не нужен КриптоПро: проверка выполняется библиотеками `gostcrypto`
и `cryptography`.

## Быстрый старт

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "django.contrib.contenttypes",
    "django_pdf_sign",
]
```

```python
from django_pdf_sign.services import prepare_signing, complete_signing

# Шаг 1: браузер присылает сертификат, сервер готовит документ.
prepared = prepare_signing(
    document=invoice,
    user=request.user,
    certificate_der=certificate_der,  # DER-сертификат из браузера
    page=-1,                           # последняя страница
    box=(57, 57, 284, 170),            # 80x40 мм, отступы 20 мм
)

# Шаг 2: отдать браузеру.
response = {
    "session_id": str(prepared.session.pk),
    "bytes_to_sign": base64.b64encode(prepared.bytes_to_sign).decode(),
    "digest_algorithm": prepared.digest_algorithm,
    "expires_at": prepared.expires_at.isoformat(),
}

# Шаг 3: браузер вернул отсоединённую CMS — проверить и встроить.
result = complete_signing(
    session_id=prepared.session.pk,
    cms=cms_bytes,
    user=request.user,
)
result.signed_pdf      # байты подписанного PDF
result.record          # неизменяемая запись аудита
```

## Что делает пакет

- Добавляет поле подписи и штамп в российском стиле.
- Возвращает точные байты `/ByteRange` для подписи.
- Проверяет, что CMS покрывает именно эти байты, сертификат совпадает с
  сессией, а подпись криптографически верна.
- Встраивает CMS, сохраняет подписанный PDF и пишет запись аудита.
- Проверяет цепочку сертификатов, отзыв (CRL и OCSP) и метки времени
  CAdES-T, если задана политика.
- Помечает и удаляет брошенные сессии (`python manage.py pdf_sign_cleanup`).

## Чего пакет не делает

- Не хранит, не принимает и не журналирует закрытые ключи, PIN и контейнеры.
- Не является удостоверяющим центром и не выдаёт сертификаты.
- Не заменяет сертифицированное СКЗИ на стороне подписанта.
- Не даёт юридическую силу сам по себе: нужны квалифицированный сертификат и
  сертифицированное СКЗИ. Подробности в [docs/legal.md](docs/legal.md).

## Настройки

```python
DJANGO_PDF_SIGN = {
    "SESSION_TTL": 900,
    "BYTES_RESERVED": 16384,
    "MAX_DOCUMENT_BYTES": 25 * 1024 * 1024,
    "DEFAULT_PAGE": -1,
    "DEFAULT_BOX": (57, 57, 284, 170),
    "SUBFILTER": None,
    "STAMP": {
        "TEXT": "...",
        "FONT_PATH": None,
        "FONT_SIZE": 7,
        "BORDER_WIDTH": 1,
        "BACKGROUND_PATH": None,
    },
    "VERIFY": {
        "CHECK_CHAIN": False,
        "TRUST_ROOTS": (),
        "INTERMEDIATE_CERTS": (),
        "CRLS": (),
        "OCSPS": (),
        "REVOCATION_MODE": "soft-fail",  # none | soft-fail | require
        "ALLOW_FETCHING": False,
        "FETCH_ALLOWED_HOSTS": (),
        "CHECK_TIMESTAMPS": False,
        "REQUIRE_TIMESTAMP": False,
    },
    "PREPARED_UPLOAD_TO": "django_pdf_sign/prepared/%Y/%m/%d",
    "SIGNED_UPLOAD_TO": "django_pdf_sign/signed/%Y/%m/%d",
    "ON_EVENT": None,
}
```

Пути к корневым сертификатам, CRL и ответам OCSP — строки, файлы читаются при
создании политики.

## Документация

- [Сайт документации](https://selimoves.github.io/django_pdf_sign/) — быстрый старт, справочник настроек, cookbook.
- [API](docs/api.md) — стабильный публичный контракт.
- [Протокол](docs/protocol.md) — контракт сервер/клиент и пример на JS.
- [Штамп](docs/stamp.md) — шаблон, размещение, настройка.
- [Юридическая сила](docs/legal.md) — что делает подпись действительной.
- [Ограничения](docs/limits.md) — производительность и лимиты.
- [Эксплуатация](docs/operations.md) — хранилище, ретенция, мониторинг.
- [Фикстуры](docs/fixtures.md) — происхождение тестовых сертификатов.
- [Интероп с КриптоПро](docker/cryptopro/README.md) — проверка на реальном CSP.
- [CHANGELOG](CHANGELOG.md), [политика безопасности](SECURITY.md), [поддержка](SUPPORT.md).
- [Как внести вклад](CONTRIBUTING.md), [дорожная карта](ROADMAP.md).

## Требования

- Python 3.11+
- Django 5.2 LTS, 6.0 или 6.1 (Django 4.2 не поддерживается)
- `pyhanko[opentype]`, `asn1crypto`, `cryptography`, `gostcrypto`

## Разработка

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python -m mypy
uv build
```

## Лицензия

MIT. Встроенный шрифт DejaVu Sans распространяется по лицензии Bitstream Vera;
см. `src/django_pdf_sign/fonts/LICENSE.DejaVu`.
