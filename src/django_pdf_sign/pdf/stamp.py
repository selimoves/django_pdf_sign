"""Настройка и отрисовка штампа подписи."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.stamp import TextStampStyle

from django_pdf_sign.conf import get_stamp_setting
from django_pdf_sign.crypto.certs import CertificateInfo, display_name

BUNDLED_FONT = Path(__file__).resolve().parent.parent / "fonts" / "DejaVuSans.ttf"


@dataclass(frozen=True)
class StampConfig:
    """Визуальная конфигурация штампа подписи."""

    text: str
    font_path: str | None
    font_size: int
    border_width: int
    background_path: str | None

    @classmethod
    def from_settings(cls) -> StampConfig:
        """Собрать конфигурацию из ``DJANGO_PDF_SIGN['STAMP']``."""
        return cls(
            text=get_stamp_setting("TEXT"),
            font_path=get_stamp_setting("FONT_PATH"),
            font_size=get_stamp_setting("FONT_SIZE"),
            border_width=get_stamp_setting("BORDER_WIDTH"),
            background_path=get_stamp_setting("BACKGROUND_PATH"),
        )


def build_stamp_style(config: StampConfig) -> TextStampStyle:
    """Собрать стиль текстового штампа pyHanko."""
    font = GlyphAccumulatorFactory(
        config.font_path or str(BUNDLED_FONT), config.font_size
    )
    text_box_style = TextBoxStyle(font=font, font_size=config.font_size)

    background = None
    if config.background_path:
        from pyhanko.pdf_utils.images import PdfImage

        background = PdfImage(config.background_path)

    return TextStampStyle(
        stamp_text=config.text,
        text_box_style=text_box_style,
        border_width=config.border_width,
        background=background,
    )


def stamp_text_params(info: CertificateInfo, *, timestamp: datetime) -> dict[str, str]:
    """Вернуть параметры подстановки для шаблона штампа."""
    return {
        "signer": display_name(info),
        "serial": info.serial_number,
        "valid_from": info.not_before.strftime("%d.%m.%Y"),
        "valid_to": info.not_after.strftime("%d.%m.%Y"),
        "ts": timestamp.strftime("%d.%m.%Y %H:%M:%S %Z"),
    }
