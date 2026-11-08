"""События жизненного цикла подписи и безопасное логирование."""

from __future__ import annotations

import logging
from typing import Any

from django_pdf_sign.conf import get_setting

logger = logging.getLogger("django_pdf_sign")


def emit(event: str, **fields: Any) -> None:
    """Записать событие в журнал и передать обработчику ``ON_EVENT``."""
    logger.info("%s %s", event, fields)
    try:
        handler = get_setting("ON_EVENT")
    except Exception:
        return
    if handler is None:
        return
    try:
        handler(event, fields)
    except Exception:
        logger.exception("Обработчик ON_EVENT упал на событии %s", event)
