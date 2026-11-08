# Внутреннее security-ревью

Дата: 2026-11-08. Ревью выполнено автором пакета, внешний аудит не проводился.

## Чек-лист

| Проверка | Статус | Где |
|----------|--------|-----|
| Закрытые ключи и PIN не хранятся на сервере | выполнено | `services/prepare.py`, `docs/legal.md` |
| CMS проверяется до встраивания | выполнено | `services/complete.py` |
| `messageDigest` сверяется с точными байтами `ByteRange` | выполнено | `services/complete.py` |
| Сессия привязана к отпечатку сертификата и алгоритму | выполнено | `services/complete.py` |
| Проверяется срок жизни сессии | выполнено | `services/complete.py` |
| Конкурентное завершение сериализовано | выполнено | `select_for_update`, `tests/test_concurrency.py` |
| `SignatureRecord` неизменяема | выполнено | `models.py`, `tests/test_models.py` |
| Недоверенный ASN.1 не роняет процесс | выполнено | `tests/test_properties.py`, `tests/test_crypto_branches.py`, `fuzz/` |
| Property-тесты и fuzzing в CI | выполнено | `.github/workflows/fuzz.yml` |
| Ошибки разбора — доменные исключения | выполнено | `crypto/cms.py`, `crypto/certs.py`, `crypto/ocsp.py`, `crypto/timestamp.py` |
| Верхние границы зависимостей | выполнено | `pyproject.toml` |
| Аудит зависимостей в CI | выполнено | `.github/workflows/security.yml` |
| Allowlist хостов и запрет редиректов | выполнено | `crypto/fetchers.py`, `tests/test_review_fixes.py` |
| Проверка настроек на старте | выполнено | `checks.py`, `tests/test_checks.py` |
| События и безопасное логирование | выполнено | `events.py`, `tests/test_events.py` |
| Подпись покрывает весь файл | выполнено | `services/verify.py` |
| Срок сертификата не подменяется меткой времени | выполнено | `services/complete.py` |
| Размер CMS ограничен до разбора ASN.1 | выполнено | `services/complete.py` |

## Найденные и исправленные проблемы

| Проблема | Исправление |
|----------|-------------|
| Падение на усечённом DER в CMS, сертификате и OCSP | доменная ошибка + регрессионные тесты |
| Падение на крафтовой структуре метки времени | весь разбор и проверка обёрнуты в доменный результат |
| Самодельная метка времени подменяла момент проверки сертификата | `policy.moment`/текущее время, `gen_time` не влияет на срок |
| RSA/ECDSA метки и OCSP отвергались из-за OID вместо имени хэша | таблица `SIGNATURE_DIGEST_OIDS` |
| `verify_signed_pdf` принимал изменения после подписи | проверка покрытия `ByteRange` до EOF |
| `complete_signing` игнорировал `VERIFY` из настроек | политика по умолчанию из `from_settings()` |
| Allowlist обходился HTTP-редиректом | `allow_redirects=False` |
| Некорректные типы настроек падали в момент подписи | расширенные system checks |
| `soft-fail`/`none` отвергали цепочку из-за просроченного OCSP | режимы отзыва соблюдаются |
| CMS произвольного размера разбиралась до проверки | лимит `session.bytes_reserved` |

## Остаточные риски

- Метка времени проверяется криптографически, но цепочка TSA не строится к
  доверенному корню. `timestamp_ok` не означает доверия к TSA; `signing_time`
  носит информационный характер.
- Чистый Python-Стрибог: высокая нагрузка CPU на больших документах в пределах
  `MAX_DOCUMENT_BYTES`.
- Время разбора ASN.1 не ограничено отдельным таймаутом, кроме лимита CMS.
- Внешний аудит не проводился; гарантии ограничены внутренним ревью и
  фаззингом.

## Как повторить

```powershell
uv run pytest -q
uv run pytest tests/test_properties.py -q --no-cov
uv run pytest -m benchmark -q --no-cov
uv run pip-audit
```

Fuzzing выполняется в Linux-контейнере (см. `.github/workflows/fuzz.yml`).
