# Интероп-проверка с КриптоПро

Образ на базе официального `CryptoPro/pycades`: КриптоПро CSP 5, CAdES и
`pycades`. Подписывает произвольные байты отсоединённой подписью CAdES-BES,
как браузерный плагин.

## Подготовка

1. Скачайте **КриптоПро CSP 5.0 для Linux, deb** (`linux-amd64_deb.tgz`) с
   <https://cryptopro.ru/products/csp/downloads>. Требуется вход в аккаунт.
2. Положите архив в `docker/cryptopro/dist/linux-amd64_deb.tgz`.
3. Соберите образ:

   ```bash
   docker build -t django-pdf-sign-cryptopro docker/cryptopro
   ```

   Свежая установка CSP содержит 90-дневную пробную лицензию.

## Запуск

Экспорт сертификата и подпись байтов:

```bash
uv run python tools/cryptopro_interop.py --build --cert cert.der
uv run python tools/cryptopro_interop.py --bytes-to-sign bytes.bin --out cms.der
```

Полный цикл с проверкой на хосте:

```bash
$env:RUN_CRYPTOPRO_INTEROP = "1"   # PowerShell
uv run pytest tests/test_cryptopro_interop.py -v
```

Без архива и переменной окружения тест пропускается; обычный прогон
КриптоПро не требует.

## Что внутри

- `Dockerfile` — CSP, `pycades`, установка тестового сертификата
  `pycades-test.pfx` и корневого `pycades-root.cer` из репозитория КриптоПро.
- `sign.py` — экспорт сертификата и отсоединённая подпись через `CADSCOM`.

Архив CSP и приватный ключ в репозиторий не попадают.
