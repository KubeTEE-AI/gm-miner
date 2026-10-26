# KubeTEE attestation fixtures

- `attestation.json`: one `GET https://llm.kubetee.ai/v1/attestation?nonce=<nonce>`
  response, captured 2026-09-27 (pod `litellm-5959f596d-l4qkl`). It carries the
  TDX quote, the CC event log, the echoed nonce and the TLS-possession proof.
- `session_leaf.der`: the leaf certificate `llm.kubetee.ai` presented on the TLS
  session that response arrived on.
- `collateral.json`: the Intel `QuoteCollateralV3` for that quote, fetched the
  same day from Phala's PCCS. Tests verify the quote offline at a fixed time
  inside its validity window.

`ec_session_leaf.der` and `ec_session_leaf_key.pk8` are a throwaway P-256
certificate/key pair (self-signed; the key protects nothing) for the
`ES256` TLS-possession proof tests: a per-boot serving key is EC P-256, so
the proof carries ECDSA over SHA-256 rather than RS256.

`es256_short_der_leaf.der` and `es256_short_der_sig.bin` pin that a valid
ASN.1 DER `ES256` signature of exactly 64 bytes is not mistaken for raw
`r||s` (28-byte `r` and `s`, each DER-padded to 29). Signing produces that
length with probability ~2^-47, so the pair is generated in reverse: short
`r`/`s` chosen first, then the P-256 key that verifies them derived and
certified (self-signed; no private key exists for it, and the tests never
check certificate chains).

`test_ca.der`, `test_leaf.der` and `test_leaf_key.pk8` are a throwaway PKI for
the tests' local TLS upstream: a root trusted only by those tests and an RSA
leaf for `llm.kubetee.ai` it signed. The key protects nothing.
