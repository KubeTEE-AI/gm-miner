# Pinned pure-Rust SEV-SNP ABI and certificate verification

Source: `virtee/sev` commit `d487809188c3c92e397bc92e2cb2a85eb982c980`,
as selected by the official Confidential Containers Trustee v0.23.0 dependency
lock. Apache-2.0 license retained. The crate identifies as `sev 7.1.0`.

This is a trimmed, local compatibility snapshot, not an unmodified release
archive. Legacy host launch APIs and unrelated tests/tooling/documentation are
omitted. The consumer sets `default-features = false` and enables exactly
`["snp", "serde", "crypto_nossl"]`. Legacy SEV symbols remaining in the library
do not authorize legacy SEV/SEV-ES evidence for the consumer.

Retained APIs:
- `AttestationReport` v2/v3+ binary and native structured JSON decoding/encoding.
- Native P-384 report signature verification (including negative tamper tests).
- AMD Milan/Genoa/Turin ARK/ASK(RSA)/VCEK certificate-chain verification.
- CoCo `Certificate`/`CertTableEntry` types, including certificate-table support.

There is no hardware launch code, no host root authority establishment, and no
secret material. Incomplete `crypto_nossl` compatibility was completed locally
for P-384 verification using the same `p384`, `rsa`, and `sha2` crates selected
by the source manifest. Empty module documentation needed by the crate's own
`#![deny(missing_docs)]` was added on the retained trimmed modules.

Capturing source commit and lockfile evidence must precede committing this
snapshot. The crate has existing unused/dead-code warnings when built with the
minimal feature set. Lint the consumer with `cargo clippy -p gm-miner-attestd
--lib --tests --no-deps -- -D warnings`; do not describe that as clearing
upstream vendored warnings or as having tested an entire upstream crate.

VLEK remains unsupported by the consumer, including any required hashstick
verification. It is fail-closed, not a VCEK compatibility path.
