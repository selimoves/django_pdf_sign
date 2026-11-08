# Signature stamp

The stamp is a visual mark on the PDF. It is not the signature: the signature
is the CMS embedded in the file. The stamp exists so a human reading a printed
or on-screen copy sees who signed, with which certificate and when.

## Default template

```
ДОКУМЕНТ ПОДПИСАН
ЭЛЕКТРОННОЙ ПОДПИСЬЮ
Сертификат: 00A1B2C3...
Владелец: ООО "Ромашка", Иванов Иван Иванович
Действителен: с 01.01.2024 до 01.01.2025
```

Parameters:

| Parameter | Value |
|-----------|-------|
| `%(signer)s` | organization and common name, or the common name alone |
| `%(serial)s` | certificate serial number in uppercase hex |
| `%(valid_from)s` | `notBefore` as `DD.MM.YYYY` |
| `%(valid_to)s` | `notAfter` as `DD.MM.YYYY` |
| `%(ts)s` | signing time (only if the template uses it) |

## Placement

- Page: last page (`page=-1`) by default.
- Box: `[57, 57, 284, 170]` points, i.e. 80×40 mm with 20 mm margins from the
  bottom-left corner.
- Thin border, 7 pt text, bundled DejaVu Sans (Cyrillic).

## Rationale

ГОСТ Р 7.0.97-2016 defines the "отметка об электронной подписи" as a document
requisite that identifies the signer, the certificate and the signing time.
Russian electronic document operators (Диадок, СБИС, Контур) render it as the
four-line block above, which is what recipients and inspectors recognise.

There is no single mandatory coordinate system for the stamp. The defaults
follow common practice: a bottom-of-page block large enough for the four lines
and a full organisation name, with a margin that survives printing. Change the
box and text through settings when a document has its own signature area.

## Configuration

```python
DJANGO_PDF_SIGN = {
    "DEFAULT_PAGE": -1,
    "DEFAULT_BOX": (57, 57, 284, 170),
    "STAMP": {
        "TEXT": "ДОКУМЕНТ ПОДПИСАН\nЭЛЕКТРОННОЙ ПОДПИСЬЮ\n"
                "Сертификат: %(serial)s\n"
                "Владелец: %(signer)s\n"
                "Действителен: с %(valid_from)s до %(valid_to)s",
        "FONT_PATH": None,          # None uses the bundled DejaVu Sans
        "FONT_SIZE": 7,
        "BORDER_WIDTH": 1,
        "BACKGROUND_PATH": None,    # optional PNG background
    },
}
```

`FONT_PATH` must point to a TrueType or OpenType font with Cyrillic glyphs.
`BACKGROUND_PATH` requires Pillow, which is not installed by default; install
`pyhanko[image-support]` to use it.

## Static appearances

For a fully custom look, a stamp can be drawn as a separate one-page PDF and
passed as `StaticStampStyle`. The vector content is imported without
rasterisation. The default text stamp is enough for the standard Russian
appearance; a static appearance is useful for corporate templates.
