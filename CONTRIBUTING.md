# Как внести вклад

Спасибо за интерес к `django-pdf-sign`.

## Правила

- Общение — на русском или английском.
- Уязвимости не обсуждаются публично: см. `SECURITY.md`.
- Не прикладывайте закрытые ключи, PIN, реальные CMS и персональные данные.
- Для изменений нужен тест. Сначала падающий, затем реализация.

## Окружение

```powershell
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python -m mypy
```

Для тестов на PostgreSQL:

```powershell
docker run --rm -e POSTGRES_PASSWORD=postgres -p 55432:5432 -d postgres:16
$env:POSTGRES_PORT = "55432"
uv run pytest tests/test_concurrency.py --ds=tests.settings_postgres -q --no-cov
```

## Процесс

1. Создайте issue с описанием проблемы или предложения.
2. Сделайте ветку от `main`.
3. Напишите падающий тест, затем минимальную реализацию.
4. Убедитесь, что проходят тесты, линтер, формат и типы.
5. Откройте pull request и опишите изменение и проверку.

Коммиты — в стиле Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`,
`ci:`).

## Документация

Вся документация, docstring и комментарии — на русском языке. Комментарии
допустимы только там, где объясняют причину, а не поведение кода.

## Совместимость

Изменения публичного API фиксируются в `docs/api.md` и `CHANGELOG.md`.
Ломающие изменения — только в мажорной версии.
