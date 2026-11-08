# Настройки

Все настройки живут в словаре `DJANGO_PDF_SIGN`. Неизвестные ключи вызывают
`ImproperlyConfigured`, а некорректные значения ловятся Django system checks
при старте.

## Основные

| Ключ | По умолчанию | Назначение |
|------|--------------|------------|
| `SESSION_TTL` | `900` | срок жизни подготовленной сессии, секунды |
| `BYTES_RESERVED` | `16384` | резерв под CMS в байтах |
| `MAX_DOCUMENT_BYTES` | `26214400` | предел размера входного PDF (25 МиБ) |
| `DEFAULT_PAGE` | `-1` | страница штампа, отрицательная — с конца |
| `DEFAULT_BOX` | `(57, 57, 284, 170)` | прямоугольник штампа в точках PDF |
| `SUBFILTER` | `None` | `/adbe.pkcs7.detached` или `/ETSI.CAdES.detached`; `None` — по типу ключа |
| `PREPARED_UPLOAD_TO` | `django_pdf_sign/prepared/%Y/%m/%d` | путь подготовленных PDF |
| `SIGNED_UPLOAD_TO` | `django_pdf_sign/signed/%Y/%m/%d` | путь подписанных PDF |
| `ON_EVENT` | `None` | обработчик событий `(event, fields)` |

## Штамп

`DJANGO_PDF_SIGN["STAMP"]`:

| Ключ | По умолчанию | Назначение |
|------|--------------|------------|
| `TEXT` | «ДОКУМЕНТ ПОДПИСАН…» | шаблон текста с `%(serial)s`, `%(signer)s`, `%(valid_from)s`, `%(valid_to)s` |
| `FONT_PATH` | `None` | свой TTF; `None` — встроенный DejaVuSans |
| `FONT_SIZE` | `7` | размер шрифта |
| `BORDER_WIDTH` | `1` | толщина рамки |
| `BACKGROUND_PATH` | `None` | фоновая картинка штампа |

## Проверка

`DJANGO_PDF_SIGN["VERIFY"]`:

| Ключ | По умолчанию | Назначение |
|------|--------------|------------|
| `CHECK_CHAIN` | `False` | проверять цепочку сертификатов |
| `TRUST_ROOTS` | `()` | пути к корневым сертификатам (DER) |
| `INTERMEDIATE_CERTS` | `()` | пути к промежуточным сертификатам |
| `CRLS` | `()` | пути к CRL |
| `OCSPS` | `()` | пути к сохранённым ответам OCSP |
| `REVOCATION_MODE` | `"soft-fail"` | `none`, `soft-fail` или `require` |
| `ALLOW_FETCHING` | `False` | разрешить сетевую загрузку отзыва |
| `FETCH_ALLOWED_HOSTS` | `()` | allowlist хостов; обязателен при `ALLOW_FETCHING=True` |
| `CHECK_TIMESTAMPS` | `False` | учитывать ошибки метки времени |
| `REQUIRE_TIMESTAMP` | `False` | требовать метку времени |

## События

`ON_EVENT` вызывается с именем события и словарём безопасных полей:

```python
def on_event(event: str, fields: dict) -> None:
    logger.info("pdf_sign %s %s", event, fields)

DJANGO_PDF_SIGN = {"ON_EVENT": on_event}
```

События: `session_prepared`, `signing_completed`, `verification_failed`.
Исключение в обработчике не прерывает подпись.

## Проверка конфигурации

```powershell
uv run python manage.py check
```

Проверяются положительные размеры и сроки, `DEFAULT_BOX`, `SUBFILTER`,
`REVOCATION_MODE`, существование файлов `TRUST_ROOTS`/`CRLS`/`OCSPS`, наличие
allowlist при `ALLOW_FETCHING=True` и пути шрифтов штампа.
