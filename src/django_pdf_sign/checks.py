"""Django system checks для настроек ``DJANGO_PDF_SIGN``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from django.core.checks import Error, register
from django.core.exceptions import ImproperlyConfigured

from django_pdf_sign.conf import DEFAULTS, get_setting
from django_pdf_sign.constants import SUBFILTER_ADOBE_PKCS7, SUBFILTER_PADES

_ALLOWED_SUBFILTERS = {None, SUBFILTER_ADOBE_PKCS7, SUBFILTER_PADES}
_ALLOWED_REVOCATION = {"none", "soft-fail", "require"}


def _error(identifier: str, message: str, hint: str = "") -> Error:
    return Error(message, id=f"django_pdf_sign.{identifier}", hint=hint)


def _missing_files(paths: Any) -> list[str]:
    return [str(path) for path in paths or () if not Path(path).is_file()]


@register()
def check_settings(app_configs: Any = None, **kwargs: Any) -> list[Error]:
    """Проверить корректность ``DJANGO_PDF_SIGN`` при старте."""
    try:
        config = {name: get_setting(name) for name in DEFAULTS}
    except ImproperlyConfigured as exc:
        return [_error("E001", str(exc), "Исправьте словарь DJANGO_PDF_SIGN")]

    errors: list[Error] = []

    for name in ("SESSION_TTL", "BYTES_RESERVED", "MAX_DOCUMENT_BYTES"):
        value = config[name]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(
                _error("E002", f"{name} должно быть положительным целым", name)
            )

    box = config["DEFAULT_BOX"]
    if (
        not isinstance(box, (tuple, list))
        or len(box) != 4
        or not all(isinstance(item, int) for item in box)
        or not (box[0] < box[2] and box[1] < box[3])
    ):
        errors.append(
            _error(
                "E003",
                "DEFAULT_BOX должен быть (x1, y1, x2, y2) с x1 < x2 и y1 < y2",
            )
        )

    if config["SUBFILTER"] not in _ALLOWED_SUBFILTERS:
        errors.append(
            _error(
                "E004",
                f"Неизвестный SUBFILTER: {config['SUBFILTER']!r}",
                f"Допустимо: {sorted(value for value in _ALLOWED_SUBFILTERS if value)}",
            )
        )

    verify = config["VERIFY"]
    if verify["REVOCATION_MODE"] not in _ALLOWED_REVOCATION:
        errors.append(
            _error(
                "E005",
                f"Неверный REVOCATION_MODE: {verify['REVOCATION_MODE']!r}",
                "Допустимо: none, soft-fail, require",
            )
        )

    for name in ("TRUST_ROOTS", "INTERMEDIATE_CERTS", "CRLS", "OCSPS"):
        missing = _missing_files(verify[name])
        if missing:
            errors.append(
                _error("E006", f"{name}: файлы не найдены: {', '.join(missing)}")
            )

    if verify["ALLOW_FETCHING"] and not verify["FETCH_ALLOWED_HOSTS"]:
        errors.append(
            _error(
                "E007",
                "ALLOW_FETCHING=True требует непустой FETCH_ALLOWED_HOSTS",
            )
        )

    stamp = config["STAMP"]
    font_size = stamp["FONT_SIZE"]
    if not isinstance(font_size, int) or isinstance(font_size, bool) or font_size <= 0:
        errors.append(_error("E008", "STAMP['FONT_SIZE'] должно быть положительным"))
    for name in ("FONT_PATH", "BACKGROUND_PATH"):
        path = stamp[name]
        if path is not None and not Path(path).is_file():
            errors.append(_error("E009", f"STAMP['{name}']: файл не найден: {path}"))

    return errors
