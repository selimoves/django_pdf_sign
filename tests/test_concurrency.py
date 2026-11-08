import threading

import pytest
from django.core.files.base import ContentFile
from django.db import connection, connections

from django_pdf_sign.exceptions import SessionError
from django_pdf_sign.services import complete_signing, prepare_signing
from tests.helpers import make_rsa_certificate, make_rsa_cms, minimal_pdf
from tests.models import Document

pytestmark = pytest.mark.skipif(
    connection.vendor != "postgresql", reason="нужен PostgreSQL"
)


@pytest.mark.django_db(transaction=True)
def test_concurrent_complete_embeds_once():
    info, key = make_rsa_certificate()
    document = Document.objects.create(file=ContentFile(minimal_pdf(), name="d.pdf"))
    prepared = prepare_signing(document=document, certificate_der=info.der)
    cms, _, _ = make_rsa_cms(data=prepared.bytes_to_sign, signer=(info, key))

    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        barrier.wait()
        try:
            complete_signing(session_id=prepared.session.pk, cms=cms)
            outcomes.append("ok")
        except SessionError:
            outcomes.append("rejected")
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["ok", "rejected"]
