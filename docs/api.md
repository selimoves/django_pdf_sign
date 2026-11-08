# Публичный API

Всё, что перечислено в этом документе, — стабильный контракт пакета. С версии
1.0 он заморожен. Остальные модули и имена (`django_pdf_sign.crypto.*`,
`django_pdf_sign.pdf.*`, `django_pdf_sign.services.prepare`,
`django_pdf_sign.services.complete`, `django_pdf_sign.services.verify`)
считаются внутренними и могут меняться без предупреждения.

## Сервисы

Импорт: `from django_pdf_sign.services import ...`

| Имя | Сигнатура |
|-----|-----------|
| `prepare_signing` | `(*, document, certificate_der, user=None, file_field="file", page=None, box=None, reason=None, location=None, field_name=None, subfilter=None, bytes_reserved=None) -> PreparedSigning` |
| `complete_signing` | `(*, session_id, cms, user=None, policy=None) -> CompletionResult` |
| `verify_cms_over_bytes` | `(*, cms, data, expected_certificate_der=None, policy=None) -> VerificationResult` |
| `verify_signed_pdf` | `(pdf, policy=None, signature_index=0) -> VerificationResult` |
| `VerificationPolicy` | датакласс параметров проверки |
| `PreparedSigning` | результат подготовки |
| `CompletionResult` | результат встраивания |
| `VerificationResult` | результат проверки |
| `ChainResult` | результат проверки цепочки |

### `prepare_signing`

Готовит PDF с видимым штампом и возвращает точные байты для подписи.

- `document` — сохранённый экземпляр модели с файловым полем;
- `certificate_der` — DER-сертификат подписанта;
- `user` — владелец сессии (необязательно);
- `file_field` — имя файлового поля модели;
- `page`, `box` — страница и прямоугольник штампа (по умолчанию из настроек);
- `reason`, `location`, `field_name`, `subfilter` — параметры поля подписи;
- `bytes_reserved` — резерв под CMS (по умолчанию из настроек).

Возвращает `PreparedSigning(session, bytes_to_sign, digest_algorithm, expires_at)`.

### `complete_signing`

Проверяет присланную отсоединённую CMS и встраивает её в подготовленный PDF.

- `session_id` — идентификатор сессии `SigningSession`;
- `cms` — DER-кодированная CMS;
- `user` — владелец сессии для дополнительной проверки;
- `policy` — `VerificationPolicy`; по умолчанию собирается из настроек.

Возвращает `CompletionResult(session, record, signed_pdf)`.

### `verify_cms_over_bytes`

Проверяет отсоединённую CMS над указанными байтами, не изменяя документ.
Возвращает `VerificationResult`.

### `verify_signed_pdf`

Проверяет встроенную подпись PDF. `signature_index` выбирает подпись (по
умолчанию первая, `0`). Неверный индекс возвращает
`VerificationResult(valid=False)` с сообщением об ошибке.

### `VerificationPolicy`

| Поле | Тип | Значение по умолчанию |
|------|-----|-----------------------|
| `check_chain` | `bool` | `False` |
| `trust_roots` | `tuple[bytes, ...]` | `()` |
| `intermediate_certs` | `tuple[bytes, ...]` | `()` |
| `crls` | `tuple[bytes, ...]` | `()` |
| `ocsps` | `tuple[bytes, ...]` | `()` |
| `revocation_mode` | `str` | `"soft-fail"` |
| `allow_fetching` | `bool` | `False` |
| `fetch_allowed_hosts` | `tuple[str, ...]` | `()` |
| `moment` | `datetime \| None` | `None` |
| `check_timestamps` | `bool` | `False` |
| `require_timestamp` | `bool` | `False` |

## Модели

Импорт: `from django_pdf_sign.models import SignatureRecord, SigningSession`

| Имя | Назначение |
|-----|------------|
| `SigningSession` | сессия подготовки и завершения подписи |
| `SignatureRecord` | неизменяемая запись о встроенной подписи |

## Настройки

Импорт: `from django_pdf_sign.conf import get_setting`

`DJANGO_PDF_SIGN` — словарь настроек пакета. Полный справочник — в
`docs/stamp.md` и README.

## Версия

`django_pdf_sign.__version__` — версия установленного дистрибутива.
