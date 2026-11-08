# Эксплуатация

## Хранение файлов

Пакет пишет два вида файлов:

- подготовленный PDF (`SigningSession.prepared_pdf`);
- подписанный PDF (`SignatureRecord.signed_pdf`).

Каталоги задаются настройками `PREPARED_UPLOAD_TO` и `SIGNED_UPLOAD_TO`, а
файлы создаются под именем `<pk сессии>.pdf`. Имена загруженных пользователем
файлов в путь не попадают.

### Локальное хранилище

```python
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": "/srv/app/media", "base_url": None},
    }
}
```

`base_url=None` запрещает раздачу файлов по публичному URL: документы должны
выдаваться только через view с проверкой прав.

### S3 и совместимые хранилища

```python
STORAGES = {
    "default": {
        "BACKEND": "storages.backends.s3.S3Storage",
        "OPTIONS": {
            "bucket_name": "signing-private",
            "default_acl": "private",
            "querystring_auth": True,
            "querystring_expire": 300,
        },
    }
}
```

Бакет приватный, шифрование включено, доступ — только по подписанным ссылкам с
коротким сроком жизни.

## Ретенция

Подготовленные PDF нужны только до завершения подписи. Удаляйте их после
`SESSION_TTL` командой:

```powershell
uv run python manage.py pdf_sign_cleanup
```

- `--retention-days N` — удалять просроченные и неудачные сессии старше N дней
  (по умолчанию 7).
- `--dry-run` — показать, что будет удалено.

Запускайте ежедневно. Пример cron:

```cron
15 3 * * * cd /srv/app && uv run python manage.py pdf_sign_cleanup --retention-days 7
```

Подписанные PDF и `SignatureRecord` — доказательства подписи. Срок их хранения
определяется политикой организации и требованиями законодательства; команда их
не удаляет.

## Ротация и резервные копии

- Резервируйте каталог `media/` или бакет целиком: запись и файл должны
  сохраняться согласованно.
- Резервная копия `SignatureRecord` без `signed_pdf` бесполезна как
  доказательство.
- Храните резервные копии в отдельном аккаунте/регионе с ограниченным доступом.
- Ключи доступа к хранилищу ротируйте не реже раза в год.

## Мониторинг

Подпишитесь на логгер `django_pdf_sign`. События:

| Событие | Когда | Поля |
|---------|-------|------|
| `session_prepared` | создана сессия | `session_id`, `status` |
| `signing_completed` | подпись встроена | `session_id`, `record_id` |
| `verification_failed` | CMS не прошла проверку | `session_id`, `reason` |

Обработчик задаётся настройкой `ON_EVENT`:

```python
def on_event(event: str, fields: dict) -> None:
    metrics.increment(f"pdf_sign.{event}")
    if event == "verification_failed":
        alerting.warn("Отклонена подпись", fields)

DJANGO_PDF_SIGN = {"ON_EVENT": on_event}
```

Обработчик не должен бросать исключения: пакет их перехватывает и пишет в лог,
но подпись не прерывает. Не передавайте в обработчик CMS, ключи и PIN — пакет
их туда не кладёт.

## Настройки, влияющие на эксплуатацию

| Настройка | Назначение |
|-----------|------------|
| `SESSION_TTL` | срок жизни подготовленной сессии, секунды |
| `MAX_DOCUMENT_BYTES` | предел размера входного PDF |
| `BYTES_RESERVED` | резерв под CMS в байтах |
| `PREPARED_UPLOAD_TO` | путь подготовленных PDF |
| `SIGNED_UPLOAD_TO` | путь подписанных PDF |
| `ON_EVENT` | обработчик событий |
| `VERIFY.ALLOW_FETCHING` | сетевая загрузка CRL/OCSP, по умолчанию выключена |
| `VERIFY.FETCH_ALLOWED_HOSTS` | allowlist хостов при включённой загрузке |

При старте Django проверяет эти настройки (`manage.py check`). Ошибки
конфигурации не дают приложению подняться с нерабочей подписью.

## Проверка после развёртывания

```powershell
uv run python manage.py check
uv run python manage.py migrate --check
uv run python manage.py pdf_sign_cleanup --dry-run
```

Убедитесь, что подготовленный PDF удаляется после завершения подписи, а
подписанный — доступен только авторизованным пользователям.
