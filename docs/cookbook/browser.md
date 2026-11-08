# Браузерный клиент

Браузер подписывает `bytes_to_sign` плагином КриптоПро и отправляет
отсоединённую CMS в DER.

```html
<script src="https://www.cryptopro.ru/sites/default/files/products/cades/demopage/cadesplugin_api.js"></script>
<script>
async function signDocument(sessionId, bytesHex) {
  await cadesplugin;
  const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
  await store.Open(
    cadesplugin.CAPICOM_CURRENT_USER_STORE,
    "My",
    cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
  );
  const certificates = await store.Certificates;
  const count = await certificates.Count;
  if (count === 0) throw new Error("Нет сертификатов в хранилище");
  const certificate = await certificates.Item(1);

  const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
  const encoder = new TextEncoder();
  const base64 = btoa(String.fromCharCode(...encoder.encode(bytesHex)));
  const cms = await signer.SignCades(
    certificate,
    cadesplugin.CADES_BES,
    base64,
    true,
    cadesplugin.CADESCOM_BASE64_TO_BINARY
  );

  const response = await fetch(`/sign/${sessionId}/`, {
    method: "POST",
    body: new URLSearchParams({ cms }),
  });
  if (!response.ok) throw new Error(await response.text());
  return response.blob();
}
</script>
```

Замечания:

- `CADESCOM_BASE64_TO_BINARY` обязателен: иначе плагин подпишет base64-текст,
  а не байты PDF.
- `SignCades(..., true, ...)` создаёт отсоединённую подпись.
- Сертификат можно выбрать из списка, а не брать первый.
- Плагин работает только в Windows и требует установленного КриптоПро CSP.

Полный пример — в каталоге `examples/`.
