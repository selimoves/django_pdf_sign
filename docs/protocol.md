# Protocol

The HTTP contract between the Django server and the browser client. The package
does not ship views: your application implements these endpoints and calls the
services.

Three steps:

1. the client sends its signing certificate;
2. the server prepares the PDF and returns the exact bytes to sign;
3. the client signs those bytes and returns a detached CMS;
4. the server verifies the CMS and embeds it.

Step 1 exists because the stamp shows the signer's name, certificate serial and
validity, and any change to the PDF after hashing would invalidate the
signature.

## Constants

Digest algorithm names, exactly as returned by `prepare_signing`:

| Name | Used for |
|------|----------|
| `streebog256` | GOST 34.10-2012 with a 256-bit key |
| `streebog512` | GOST 34.10-2012 with a 512-bit key |
| `sha256` | RSA and ECDSA (PAdES) |

Signature `/SubFilter` values:

| Value | Used for |
|-------|----------|
| `/adbe.pkcs7.detached` | GOST CAdES-BES |
| `/ETSI.CAdES.detached` | PAdES (RSA/ECDSA) |

The server chooses the digest from the certificate's key algorithm and the
subfilter from the signature type. Both can be overridden per call.

## Step 1 and 2 — prepare

`POST /api/pdf-sign/prepare/`

Request:

```json
{
  "document_id": 42,
  "certificate": "<base64 of the DER certificate>",
  "page": -1,
  "box": [57, 57, 284, 170],
  "reason": "Approval",
  "location": "Moscow"
}
```

- `document_id` — the primary key of the application's document.
- `certificate` — base64 DER exported from the CryptoPro store.
- `page` — zero-based page index; `-1` means the last page. Default `-1`.
- `box` — optional `[x1, y1, x2, y2]` in PDF points. Default `[57, 57, 284, 170]`
  (80×40 mm, 20 mm from the bottom-left corner).
- `reason`, `location` — optional signature dictionary metadata.

Response `200`:

```json
{
  "session_id": "6f1c1b5e-7f4a-4a5f-9f1e-0f0b6d1f0c11",
  "bytes_to_sign": "<base64>",
  "digest_algorithm": "streebog256",
  "expires_at": "2026-11-08T12:15:00Z"
}
```

`bytes_to_sign` is the concatenation of the two `/ByteRange` segments:
`pdf[0:sig_start] + pdf[sig_end:eof]`. Hash exactly these bytes.

The session expires after `DJANGO_PDF_SIGN["SESSION_TTL"]` seconds (900 by
default) and can be completed once.

## Step 3 — sign in the browser

The reference client uses the CryptoPro Browser Plug-in:

```javascript
async function signBytes(bytesToSign, digestAlgorithm) {
  const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
  await store.Open(
    cadesplugin.CAPICOM_CURRENT_USER_STORE,
    cadesplugin.CAPICOM_MY_STORE,
    cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
  );
  const certificates = await store.Certificates;
  const certificate = await certificates.Item(1); // chosen by the user

  const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
  signer.Certificate = certificate;
  signer.CheckCertificate = true;

  const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
  data.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
  data.Content = bytesToSign; // base64

  return data.SignCades(signer, cadesplugin.CADESCOM_CADES_BES, true);
}
```

`SignCades(..., true)` produces a **detached** CMS. The server does not need to
know which cryptographic provider the client used.

To export the certificate for step 1:

```javascript
const encoded = await certificate.Export(cadesplugin.CADESCOM_ENCODE_BASE64);
```

## Step 4 — complete

`POST /api/pdf-sign/complete/`

Request:

```json
{
  "session_id": "6f1c1b5e-7f4a-4a5f-9f1e-0f0b6d1f0c11",
  "cms": "<base64 of the detached CMS>"
}
```

Response `200`:

```json
{
  "signature_id": 7,
  "verification_status": "valid",
  "signed_at": "2026-11-08T12:01:30Z"
}
```

The server checks, in order:

1. the session exists, is `prepared`, not expired and belongs to the caller;
2. the CMS contains exactly one signer and a signer certificate;
3. the certificate thumbprint equals the session's;
4. the signer certificate is valid at the current time;
5. `messageDigest` equals the digest of the stored bytes to sign;
6. the signature over the signed attributes is cryptographically valid.

Only then is the CMS embedded, the signed PDF stored and a `SignatureRecord`
created. A failed check leaves the session `prepared`, so the client may retry
with a corrected CMS.

## Errors

| Status | Meaning |
|--------|---------|
| `400` | Malformed request, unparsable certificate or CMS |
| `403` | Session belongs to another user |
| `409` | Session is not `prepared` (already completed, failed or expired) |
| `413` | Document exceeds `MAX_DOCUMENT_BYTES` |
| `422` | CMS verification failed |

Do not return the raw CMS or the signer's certificate in error messages.

## Django sketch

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

`complete_signing` returns `CompletionResult(session, record, signed_pdf)`.
