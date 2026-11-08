Здесь лежит подпись, созданная настоящим КриптоПро CSP (образ из
`docker/cryptopro`), и её публичные артефакты:

- `pycades-test.cer` — сертификат подписанта (DER), выдан `pycades-root`;
- `pycades-test.bytes` — точные байты, которые подписывались;
- `pycades-test.cms` — отсоединённая CMS CAdES-BES (DER);
- `pycades-test-signed.pdf` — подписанный PDF.

Ключ — официальный тестовый `pycades-test.pfx` из репозитория КриптоПро
(`https://github.com/CryptoPro/pycades/tree/main/tests/fixtures`), пароль
пустой. Он не имеет ценности и в репозиторий не включён.

Артефакты создаются скриптом `tools/make_cryptopro_fixture.py` на машине с
Docker и скачанным архивом КриптоПро CSP. Перегенерировать нужно только при
смене формата или при обновлении фикстур КриптоПро.

Тесты, использующие эти файлы, не требуют Docker и работают в CI:
`tests/test_cryptopro_fixture.py`.
