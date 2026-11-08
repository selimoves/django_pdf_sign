# Политики проверки

## Только криптография

```python
result = verify_signed_pdf(pdf)
```

Проверяет `messageDigest` и подпись. Цепочка и отзыв не проверяются.

## Цепочка с корнем

```python
policy = VerificationPolicy(
    check_chain=True,
    trust_roots=(root_der,),
    intermediate_certs=(intermediate_der,),
)
```

## Цепочка, CRL и строгий отзыв

```python
policy = VerificationPolicy(
    check_chain=True,
    trust_roots=(root_der,),
    crls=(root_crl_der,),
    revocation_mode="require",
)
```

`require` отклоняет подпись, если пригодных данных отзыва нет.

## Сохранённые ответы OCSP

```python
policy = VerificationPolicy(
    check_chain=True,
    trust_roots=(root_der,),
    ocsps=(ocsp_response_der,),
    revocation_mode="require",
)
```

## Проверка на исторический момент

```python
from datetime import UTC, datetime

policy = VerificationPolicy(
    check_chain=True,
    trust_roots=(root_der,),
    crls=(root_crl_der,),
    moment=datetime(2025, 1, 1, tzinfo=UTC),
)
```

## Требовать метку времени

```python
policy = VerificationPolicy(check_timestamps=True, require_timestamp=True)
```

Если метка отсутствует, результат будет недействительным.

## Сетевая загрузка отзыва

```python
policy = VerificationPolicy(
    check_chain=True,
    trust_roots=(root_der,),
    allow_fetching=True,
    fetch_allowed_hosts=("crl.example.ru", "ocsp.example.ru"),
)
```

Пустой allowlist при `allow_fetching=True` — ошибка конфигурации.
