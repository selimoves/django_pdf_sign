# Протокол

HTTP-контракт между сервером Django и браузерным клиентом. Пакет не содержит
представлений: приложение реализует эти эндпоинты и вызывает сервисы.

Шаги:

1. клиент присылает сертификат подписи;
2. сервер готовит PDF и возвращает точные байты для подписи;
3. клиент подписывает байты и возвращает отсоединённую CMS;
4. сервер проверяет CMS и встраивает её.

Шаг 1 нужен потому, что штамп показывает имя подписанта, серийный номер и срок
действия сертификата, а любое изменение PDF после хэширования ломает подпись.

## Константы

Имена алгоритмов дайджеста, как их возвращает `prepare_signing`:

| Имя | Для чего |
|-----|----------|
| `streebog256` | ГОСТ Р 34.10-2012 с ключом 256 бит |
| `streebog512` | ГОСТ Р 34.10-2012 с ключом 512 бит |
| `sha256` | RSA и ECDSA (PAdES) |

Значения `/SubFilter`:

| Значение | Для чего |
|----------|----------|
| `/adbe.pkcs7.detached` | ГОСТ CAdES-BES |
| `/ETSI.CAdES.detached` | PAdES (RSA/ECDSA) |

Сервер выбирает дайджест по алгоритму ключа сертификата, а SubFilter — по типу
подписи. Оба можно переопределить при вызове.

## Шаги 1–2 — подготовка

`POST /api/pdf-sign/prepare/`

Запрос:

```json
{
  "document_id": 42,
  "certificate": "<base64 от DER-сертификата>",
  "page": -1,
  "box": [57, 57, 284, 170],
  "reason": "Согласование",
  "location": "Москва"
}
```

- `document_id` — первичный ключ документа приложения.
- `certificate` — base64 DER, экспортированный из хранилища КриптоПро.
- `page` — индекс страницы с нуля; `-1` означает последнюю. По умолчанию `-1`.
- `box` — необязательный `[x1, y1, x2, y2]` в пунктах PDF. По умолчанию
  `[57, 57, 284, 170]` (80×40 мм, отступы 20 мм от левого нижнего угла).
- `reason`, `location` — необязательные поля словаря подписи.

Ответ `200`:

```json
{
  "session_id": "6f1c1b5e-7f4a-4a5f-9f1e-0f0b6d1f0c11",
  "bytes_to_sign": "<base64>",
  "digest_algorithm": "streebog256",
  "expires_at": "2026-11-08T12:15:00Z"
}
```

`bytes_to_sign` — конкатенация двух участков `/ByteRange`:
`pdf[0:sig_start] + pdf[sig_end:eof]`. Хэшировать нужно именно эти байты.

Сессия живёт `DJANGO_PDF_SIGN["SESSION_TTL"]` секунд (по умолчанию 900) и может
быть завершена только один раз.

## Шаг 3 — подпись в браузере

Эталонный клиент использует плагин КриптоПро:

```javascript
async function signBytes(bytesToSign) {
  const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
  await store.Open(
    cadesplugin.CAPICOM_CURRENT_USER_STORE,
    cadesplugin.CAPICOM_MY_STORE,
    cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
  );
  const certificates = await store.Certificates;
  const certificate = await certificates.Item(1); // выбор пользователя

  const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
  signer.Certificate = certificate;
  signer.CheckCertificate = true;

  const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
  data.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
  data.Content = bytesToSign; // base64

  return data.SignCades(signer, cadesplugin.CADESCOM_CADES_BES, true);
}
```

`SignCades(..., true)` создаёт **отсоединённую** CMS. Серверу не важно, каким
криптопровайдером пользовался клиент.

Экспорт сертификата для шага 1:

```javascript
const encoded = await certificate.Export(cadesplugin.CADESCOM_ENCODE_BASE64);
```

## Шаг 4 — завершение

`POST /api/pdf-sign/complete/`

Запрос:

```json
{
  "session_id": "6f1c1b5e-7f4a-4a5f-9f1e-0f0b6d1f0c11",
  "cms": "<base64 отсоединённой CMS>"
}
```

Ответ `200`:

```json
{
  "signature_id": 7,
  "verification_status": "valid",
  "chain_status": "valid",
  "revocation_status": "good",
  "timestamp_status": "absent",
  "signed_at": "2026-11-08T12:01:30Z"
}
```

Сервер проверяет по порядку:

1. сессия существует, в статусе `prepared`, не истекла и принадлежит вызывающему;
2. в CMS ровно один подписант и есть сертификат подписанта;
3. отпечаток сертификата совпадает с сессией;
4. `messageDigest` совпадает с дайджестом сохранённых байтов;
5. подпись над подписанными атрибутами криптографически верна;
6. если задана политика — цепочка сертификатов, отзыв и метка времени.

Только после этого CMS встраивается, подписанный PDF сохраняется и создаётся
`SignatureRecord`. Неудачная проверка оставляет сессию в `prepared`, чтобы
клиент мог повторить с исправленной CMS.

## Проверка (политика)

`VerificationPolicy` включает дополнительные проверки:

| Поле | Смысл |
|------|-------|
| `check_chain` | проверять цепочку до доверенного корня |
| `trust_roots` | DER корневых сертификатов |
| `intermediate_certs` | DER промежуточных сертификатов |
| `crls` | DER списков отзыва |
| `ocsps` | DER ответов OCSP |
| `revocation_mode` | `none`, `soft-fail`, `require` |
| `allow_fetching` | разрешить сетевую загрузку (по умолчанию запрещено) |
| `moment` | момент проверки |
| `check_timestamps` | проверять метку времени CAdES-T |
| `require_timestamp` | требовать метку времени |

По умолчанию политика выключена: проверяется только сама подпись и
`messageDigest`. Политику можно собрать из настроек:
`VerificationPolicy.from_settings()`.

## Ошибки

| Статус | Значение |
|--------|----------|
| `400` | Некорректный запрос, сертификат или CMS |
| `403` | Сессия принадлежит другому пользователю |
| `409` | Сессия не в статусе `prepared` |
| `413` | Документ больше `MAX_DOCUMENT_BYTES` |
| `422` | Проверка CMS не пройдена |

Не возвращайте в текстах ошибок сырую CMS и сертификат подписанта.

## Набросок на Django

```python
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django_pdf_sign.services import prepare_signing, complete_signing
from django_pdf_sign.exceptions import DjangoPdfSignError

@require_POST
def prepare(request):
    payload = json.loads(request.body)
    document = get_object_or_404(Document, pk=payload["document_id"])
    prepared = prepare_signing(
        document=document,
        user=request.user,
        certificate_der=base64.b64decode(payload["certificate"]),
        page=payload.get("page", -1),
        box=payload.get("box"),
    )
    return JsonResponse({
        "session_id": str(prepared.session.pk),
        "bytes_to_sign": base64.b64encode(prepared.bytes_to_sign).decode(),
        "digest_algorithm": prepared.digest_algorithm,
        "expires_at": prepared.expires_at.isoformat(),
    })
```

`complete_signing` возвращает `CompletionResult(session, record, signed_pdf)`.
