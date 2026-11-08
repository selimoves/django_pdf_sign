# Legal validity

This package builds and verifies PDF signatures. It does **not** make a
signature legally valid by itself, and it is not a qualified electronic
signature service.

## What the package does

- Prepares a PDF with a visible stamp and a signature placeholder.
- Returns the exact bytes to sign.
- Verifies that the returned CMS covers those bytes and belongs to the
  certificate that was used to prepare the document.
- Embeds the CMS and stores an audit record.

## What gives a signature legal weight

For a Russian qualified electronic signature (КЭП):

- a **qualified certificate** issued by an accredited certification authority;
- a **certified cryptographic provider** (СКЗИ) on the signer's side, for
  example CryptoPro CSP with a valid licence;
- the signer's **private key** stays in that provider (a token, the registry or
  an HSM). It never reaches this package or the server.

For a PAdES signature verified in Adobe:

- a certificate chaining to a trust anchor Adobe recognises;
- a signature format Adobe accepts (PAdES, RSA or ECDSA).

The package supports both, but it does not perform trust-chain validation,
revocation checks (OCSP/CRL) or timestamping in version 1. A recipient that
needs those checks uses a qualified validator: Gosuslugi, CryptoPro, or a
commercial validation service.

## Private keys

The server never holds, receives, logs or stores a private key, a PIN or a key
container. Only the public certificate and the finished CMS are handled.

## What to tell users

- The stamp is informational; the signature is the CMS, not the image.
- A signature is only as trustworthy as the certificate behind it.
- Changing the PDF after signing invalidates the signature, even if the change
  looks harmless.
- Keep the signed PDF and the audit record; the audit record alone is not the
  signed document.

## Audit

`SignatureRecord` stores the signer certificate, thumbprint, digest algorithm,
subfilter, CMS size, verification result and the signed PDF. It is immutable
at the model level. Store it according to your organisation's retention policy.
