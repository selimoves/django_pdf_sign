# Быстрый старт

## Установка

```powershell
uv add django-pdf-sign
```

Для квалифицированных подписей ГОСТ браузеру нужен плагин КриптоПро ЭЦП
Browser plug-in. Сервер не требует CSP.

## Подключение

```python
INSTALLED_APPS = [
    ...,
    "django_pdf_sign",
]
```

```python
DJANGO_PDF_SIGN = {
    "SESSION_TTL": 900,
}
```

Примените миграции:

```powershell
uv run python manage.py migrate
```

## Подпись документа

Три шага: браузер присылает сертификат, сервер готовит PDF, браузер возвращает
CMS.

```python
from django.http import HttpResponse, JsonResponse
from django_pdf_sign.services import complete_signing, prepare_signing

from myapp.models import Document


def prepare(request, pk: int):
    document = Document.objects.get(pk=pk)
    certificate = bytes.fromhex(request.POST["certificate_der"])
    prepared = prepare_signing(document=document, certificate_der=certificate)
    return JsonResponse(
        {
            "session_id": str(prepared.session.pk),
            "bytes_to_sign": prepared.bytes_to_sign.hex(),
            "digest_algorithm": prepared.digest_algorithm,
            "expires_at": prepared.expires_at.isoformat(),
        }
    )


def complete(request, session_id):
    result = complete_signing(
        session_id=session_id,
        cms=bytes.fromhex(request.POST["cms"]),
    )
    return HttpResponse(result.signed_pdf, content_type="application/pdf")
```

Клиент подписывает `bytes_to_sign` и присылает отсоединённую CMS в DER.
Сервер сам проверяет сертификат, `messageDigest` и подпись, затем встраивает
CMS в подготовленный PDF.

## Проверка подписи

```python
from django_pdf_sign.services import VerificationPolicy, verify_signed_pdf

policy = VerificationPolicy(
    check_chain=True,
    trust_roots=(root_ca_der,),
    crls=(crl_der,),
    revocation_mode="require",
)
result = verify_signed_pdf(signed_pdf, policy=policy)
if not result.valid:
    print(result.errors)
```

Для проверки второй и последующих подписей используйте `signature_index`.

## Настройки проверки

Файлы корневых сертификатов, CRL и OCSP задаются в `DJANGO_PDF_SIGN["VERIFY"]`:

```python
DJANGO_PDF_SIGN = {
    "VERIFY": {
        "CHECK_CHAIN": True,
        "TRUST_ROOTS": ("/etc/pki/root.crt",),
        "CRLS": ("/etc/pki/root.crl",),
        "REVOCATION_MODE": "require",
    }
}
```

Сетевая загрузка отзыва по умолчанию выключена. Если включаете
`ALLOW_FETCHING`, обязательно задайте `FETCH_ALLOWED_HOSTS`.

## Дальше

- [Справочник настроек](settings.md)
- [Протокол сервер/браузер](protocol.md)
- [Внешний вид штампа](stamp.md)
- [Эксплуатация](operations.md)
