# Django views

Полный цикл: загрузка документа, подготовка, завершение, выдача файла.

```python
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST
from django_pdf_sign.exceptions import SessionError, SigningError, VerificationError
from django_pdf_sign.services import complete_signing, prepare_signing

from myapp.models import Document


@login_required
@require_POST
def prepare(request, pk: int):
    document = get_object_or_404(Document, pk=pk, owner=request.user)
    try:
        prepared = prepare_signing(
            document=document,
            certificate_der=bytes.fromhex(request.POST["certificate_der"]),
            user=request.user,
        )
    except SigningError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse(
        {
            "session_id": str(prepared.session.pk),
            "bytes_to_sign": prepared.bytes_to_sign.hex(),
            "digest_algorithm": prepared.digest_algorithm,
        }
    )


@login_required
@require_POST
def complete(request, session_id):
    try:
        result = complete_signing(
            session_id=session_id,
            cms=bytes.fromhex(request.POST["cms"]),
            user=request.user,
        )
    except (SessionError, VerificationError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return FileResponse(
        result.signed_pdf,
        as_attachment=True,
        filename=f"document-{result.session.pk}.pdf",
    )
```

Правила:

- проверяйте права на документ до вызова сервиса;
- не логируйте `certificate_der` и `cms`;
- отдавайте PDF через `FileResponse` с проверкой прав, а не по публичному URL;
- `SessionError` и `VerificationError` — ожидаемые ошибки клиента (400),
  `SigningError` при подготовке — тоже 400, остальные — 500.
