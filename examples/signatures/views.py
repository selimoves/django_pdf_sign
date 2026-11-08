"""Представления примера."""

from __future__ import annotations

import base64

from django.core.files.base import ContentFile
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_POST

from django_pdf_sign.exceptions import SessionError, SigningError, VerificationError
from django_pdf_sign.services import complete_signing, prepare_signing
from signatures.models import Document


def index(request: HttpRequest) -> HttpResponse:
    """Показать форму загрузки и подписи."""
    return render(request, "signatures/index.html")


@require_POST
def upload(request: HttpRequest) -> JsonResponse:
    """Сохранить загруженный PDF и вернуть его идентификатор."""
    uploaded = request.FILES["file"]
    document = Document.objects.create(
        file=ContentFile(uploaded.read(), name=uploaded.name),
        title=uploaded.name,
    )
    return JsonResponse({"pk": document.pk})


@require_POST
def prepare(request: HttpRequest, pk: int) -> JsonResponse:
    """Подготовить документ к подписи."""
    document = get_object_or_404(Document, pk=pk)
    certificate_der = base64.b64decode(request.POST["certificate_der"])
    try:
        prepared = prepare_signing(document=document, certificate_der=certificate_der)
    except SigningError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse(
        {
            "session_id": str(prepared.session.pk),
            "bytes_to_sign": base64.b64encode(prepared.bytes_to_sign).decode(),
        }
    )


@require_POST
def complete(request: HttpRequest, session_id: str) -> HttpResponse:
    """Проверить CMS и вернуть подписанный PDF."""
    try:
        result = complete_signing(
            session_id=session_id,
            cms=base64.b64decode(request.POST["cms"]),
        )
    except (SessionError, VerificationError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return FileResponse(
        result.signed_pdf,
        as_attachment=True,
        filename="signed.pdf",
    )
