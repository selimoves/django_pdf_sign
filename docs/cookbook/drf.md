# Django REST Framework

```python
from rest_framework import serializers, status
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from django_pdf_sign.exceptions import SessionError, SigningError, VerificationError
from django_pdf_sign.services import complete_signing, prepare_signing


class PrepareSerializer(serializers.Serializer):
    certificate_der = serializers.CharField()
    file = serializers.FileField()


class CompleteSerializer(serializers.Serializer):
    cms = serializers.CharField()


class PrepareView(APIView):
    parser_classes = [MultiPartParser]

    def post(self, request):
        data = PrepareSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        document = Document.objects.create(
            owner=request.user, file=data.validated_data["file"]
        )
        try:
            prepared = prepare_signing(
                document=document,
                certificate_der=bytes.fromhex(data.validated_data["certificate_der"]),
                user=request.user,
            )
        except SigningError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "session_id": str(prepared.session.pk),
                "bytes_to_sign": prepared.bytes_to_sign.hex(),
            }
        )


class CompleteView(APIView):
    def post(self, request, session_id):
        data = CompleteSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        try:
            result = complete_signing(
                session_id=session_id,
                cms=bytes.fromhex(data.validated_data["cms"]),
                user=request.user,
            )
        except (SessionError, VerificationError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "record_id": result.record.pk,
                "verification_status": result.record.verification_status,
            }
        )
```

Для больших PDF используйте `FILE_UPLOAD_MAX_MEMORY_SIZE` и отдавайте файл
отдельным эндпоинтом с проверкой прав.
