//! The checks on a `KubeTEE` `/v1/attestation` payload, apart from fetching
//! it: the DCAP appraisal, the nonce binding, the event log replay and the
//! TLS-possession proof.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::TDReport10;
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256, Sha512};
use tracing::info;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION};
use x509_parser::parse_x509_certificate;

use crate::eventlog::{self, Register};
use crate::kubetee_verify::binding;
use crate::tee_evidence;

/// Repeated member names in the JSON response are rejected before
/// `serde_json::Value` collapses them: RFC 8785 requires object member
/// names be unique, so a served keyset with a repeated name is invalid JCS
/// input. Names are compared after JSON string decoding, so different
/// spellings of one name collide too.
fn reject_duplicate_names(text: &str) -> Result<()> {
    let mut stack: Vec<std::collections::BTreeSet<String>> = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => stack.push(std::collections::BTreeSet::new()),
            '}' => {
                stack
                    .pop()
                    .context("KubeTEE attestation response has unbalanced JSON")?;
            }
            '"' => {
                let mut token = String::from('"');
                while let Some(c) = chars.next() {
                    token.push(c);
                    match c {
                        '\\' => token.push(
                            chars
                                .next()
                                .context("KubeTEE attestation response has a truncated escape")?,
                        ),
                        '"' => break,
                        _ => {}
                    }
                }
                while matches!(chars.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                    chars.next();
                }
                if chars.peek() == Some(&':') {
                    if let Some(current) = stack.last_mut() {
                        let name: String = serde_json::from_str(&token)
                            .context("KubeTEE attestation response has a malformed member name")?;
                        ensure!(
                            current.insert(name.clone()),
                            "KubeTEE attestation response has duplicate member name {name}"
                        );
                    }
                }
            }
            _ => {}
        }
    }
    ensure!(
        stack.is_empty(),
        "KubeTEE attestation response has unbalanced JSON"
    );
    Ok(())
}

/// The signature algorithms a TLS-possession proof may name: `ES256` (ECDSA
/// over SHA-256 on P-256 — the per-boot serving key) and `RS256` (RSASSA-
/// PKCS1-v1_5 over SHA-256 — a legacy RSA key). The proof is accepted in
/// the encoding the named algorithm implies and fails closed on any other
/// spelling or on a key-type mismatch.
const ES256: &str = "ES256";
const RS256: &str = "RS256";

/// The `GET /v1/attestation` response body.
#[derive(Debug, Deserialize)]
pub struct AttestationPayload {
    pub nonce: String,
    pub quote: String,
    pub cc_eventlog: Option<String>,
    pub tls_possession: Option<TlsPossession>,
    #[serde(default)]
    pub pod: String,
}

/// A signature over the nonce made with the serving certificate's key.
#[derive(Clone, Debug, Deserialize)]
pub struct TlsPossession {
    pub tls_signature: String,
    pub tls_signature_alg: String,
    pub tls_cert_sha256: String,
}

/// The `kubetee.attestation.v1` fields of a v1 response: the served keyset
/// and its binding statement (spec sections 4-5). Optional: a response
/// without them is the legacy `SHA-512(nonce)` construction.
#[derive(Debug, Deserialize)]
pub struct BindingFields {
    pub keyset: Value,
    pub bindings: BindingStatement,
}

#[derive(Debug, Deserialize)]
pub struct BindingStatement {
    pub version: String,
    pub report_data_statement: String,
    pub keyset_digest: String,
}

/// The pre-quote v1 binding gate: hash the exact statement bytes into the
/// shape a v1 quote must carry, so `verify_report_data` checks one
/// construction. v2-only responses (both `keyset` and `bindings`) are also
/// checked here against this connection's leaf certificate: the served
/// keyset must name the same serving key, be unexpired, and carry the v1
/// version tag.
pub(crate) struct BindingGuard;

/// Binding fields checked against the serving key and statement. The
/// report data must still be authenticated by the quote before use.
#[derive(Debug)]
pub(crate) struct Binding {
    pub report_data: [u8; 64],
    pub not_after: DateTime<Utc>,
}

impl Binding {
    /// Recheck after collateral fetching and quote verification, which may
    /// have taken the connection past its keyset's deadline.
    pub(crate) fn ensure_current(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.not_after > now,
            "kubetee.attestation.v1 keyset is expired"
        );
        Ok(())
    }
}

impl BindingGuard {
    /// Derive the binding to verify from `body`, or fail closed on any
    /// malformed, mixed, or v1-shape response that does not verify.
    ///
    /// # Errors
    ///
    /// Returns an error when the response is v1-shaped and the statement,
    /// keyset, or version check fails.
    pub(crate) fn run(
        body: &[u8],
        nonce: &str,
        leaf: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Option<Binding>> {
        reject_duplicate_names(
            std::str::from_utf8(body).context("KubeTEE attestation response is not UTF-8")?,
        )?;
        let payload: Value =
            serde_json::from_slice(body).context("decode KubeTEE attestation response")?;
        let keyset_present = payload.get("keyset").is_some();
        let bindings_present = payload.get("bindings").is_some();
        match (keyset_present, bindings_present) {
            (true, true) => {
                let fields: BindingFields = serde_json::from_slice(body)
                    .context("decode kubetee.attestation.v1 binding fields")?;
                ensure!(
                    fields.bindings.version == binding::PURPOSE,
                    "kubetee.attestation.v1 binding has version {}, expected {}",
                    fields.bindings.version,
                    binding::PURPOSE
                );
                let not_after = Self::verify_served_keyset(
                    &fields.keyset,
                    &fields.bindings.keyset_digest,
                    leaf,
                )?;
                let report_data = binding::report_data_of_statement(
                    &fields.bindings.report_data_statement,
                    &fields.bindings.keyset_digest,
                    nonce,
                )?;
                let binding = Binding {
                    report_data,
                    not_after,
                };
                binding.ensure_current(now)?;
                Ok(Some(binding))
            }
            (false, false) => Ok(None),
            _ => bail!("KubeTEE attestation response has half a v1 binding"),
        }
    }

    fn verify_served_keyset(
        keyset: &Value,
        stated_digest: &str,
        leaf: &[u8],
    ) -> Result<DateTime<Utc>> {
        let (_, certificate) = parse_x509_certificate(leaf)
            .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
        let spki = certificate.public_key().raw;
        let recomputed = binding::recompute_keyset_digest(keyset)?;
        ensure!(
            recomputed == stated_digest,
            "kubetee.attestation.v1 keyset digest does not match the served keyset"
        );
        let spki_sha256 = hex::encode(Sha256::digest(spki));
        let matches = keyset
            .get("tls_public_keys")
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                keys.iter().any(|key| {
                    key.get("domain").and_then(Value::as_str) == Some(HOST_DOMAIN)
                        && key.get("spki_sha256").and_then(Value::as_str)
                            == Some(spki_sha256.as_str())
                })
            });
        ensure!(
            matches,
            "kubetee.attestation.v1 keyset does not name this connection's serving key"
        );
        let not_after = keyset
            .get("not_after")
            .and_then(Value::as_str)
            .context("kubetee.attestation.v1 keyset has no not_after")?;
        let expires = DateTime::parse_from_rfc3339(not_after)
            .context("kubetee.attestation.v1 keyset not_after is not RFC 3339")?
            .with_timezone(&Utc);
        let certificate_expires =
            DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0)
                .context("KubeTEE TLS certificate has an invalid not_after")?;
        ensure!(
            expires <= certificate_expires,
            "kubetee.attestation.v1 keyset outlives the serving certificate"
        );
        Ok(expires)
    }
}

/// The domain the v1 keyset's serving key must name.
const HOST_DOMAIN: &str = "llm.kubetee.ai";

/// The measured registers of the TD that minted a quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurements {
    pub mrtd: Register,
    pub mr_config_id: Register,
    pub rtmrs: [Register; 4],
}

impl Measurements {
    fn of(td: &TDReport10) -> Self {
        Self {
            mrtd: td.mr_td,
            mr_config_id: td.mr_config_id,
            rtmrs: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        }
    }
}

/// Check a verified attestation against the nonce this proxy
/// sent and the certificate of the connection it arrived on.
///
/// `claims` must come from Intel's chain of trust for `payload.quote`.
///
/// # Errors
///
/// Returns an error naming the first check that fails: the echoed nonce,
/// the DCAP appraisal, the nonce binding in `report_data`, the event log
/// replay, or the TLS-possession proof.
pub fn verify_attestation(
    payload: &AttestationPayload,
    nonce: &str,
    leaf: &[u8],
    claims: &QuoteClaims,
    now: u64,
) -> Result<Measurements> {
    verify_attestation_bound(payload, nonce, leaf, claims, now, None)
}

/// `verify_attestation` with the binding a v1 response already proved:
/// `Some(report_data)` from the served statement, `None` for the legacy
/// `SHA-512(nonce)` construction.
///
/// # Errors
///
/// Returns an error naming the first check that fails, as
/// [`verify_attestation`] does.
pub fn verify_attestation_bound(
    payload: &AttestationPayload,
    nonce: &str,
    leaf: &[u8],
    claims: &QuoteClaims,
    now: u64,
    binding: Option<[u8; 64]>,
) -> Result<Measurements> {
    ensure!(
        payload.nonce.as_bytes() == nonce.as_bytes(),
        "KubeTEE echoed a different nonce"
    );
    let td = tee_evidence::appraise(claims, now)?;
    verify_report_data_bound(td, nonce, binding)?;
    let measurements = Measurements::of(td);
    let log = payload
        .cc_eventlog
        .as_deref()
        .context("KubeTEE attestation has no cc_eventlog")?;
    verify_event_log(log, &measurements.rtmrs)?;
    let possession = payload
        .tls_possession
        .as_ref()
        .context("KubeTEE attestation has no tls_possession")?;
    verify_tls_possession(possession, nonce, leaf)?;
    Ok(measurements)
}

fn verify_report_data_bound(td: &TDReport10, nonce: &str, bound: Option<[u8; 64]>) -> Result<()> {
    let expected = bound.unwrap_or_else(|| Sha512::digest(nonce.as_bytes()).into());
    ensure!(
        td.report_data == expected,
        "TDX report_data is not the binding for the nonce sent"
    );
    Ok(())
}

fn verify_event_log(log: &str, quoted: &[Register; 4]) -> Result<()> {
    let log = STANDARD.decode(log).context("decode KubeTEE cc_eventlog")?;
    let replayed = eventlog::replay(&eventlog::parse(&log)?);
    for (index, (replayed, quoted)) in replayed.iter().zip(quoted).enumerate() {
        ensure!(
            replayed == quoted,
            "KubeTEE event log does not replay to the quote's RTMR{index}"
        );
    }
    Ok(())
}

/// Check that the TLS-possession proof names this connection's leaf
/// certificate and that its key signed `nonce`. The proof names its
/// algorithm (`tls_signature_alg`): `ES256` is ECDSA over SHA-256 with the
/// certificate's P-256 key — raw `r||s` (64 bytes) or ASN.1 DER, both
/// accepted — and `RS256` is RSASSA-PKCS1-v1_5 over SHA-256 with its RSA
/// key. Any other algorithm, or one that does not match the certificate's
/// key type, fails closed.
fn verify_tls_possession(possession: &TlsPossession, nonce: &str, leaf: &[u8]) -> Result<()> {
    let claimed = hex::decode(&possession.tls_cert_sha256)
        .context("decode KubeTEE TLS certificate fingerprint")?;
    ensure!(
        claimed.as_slice() == Sha256::digest(leaf).as_slice(),
        "KubeTEE TLS-possession names a certificate other than this connection's"
    );
    let (_, certificate) = parse_x509_certificate(leaf)
        .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
    let key = certificate.public_key();
    let signature = STANDARD
        .decode(&possession.tls_signature)
        .context("decode KubeTEE TLS-possession signature")?;
    match possession.tls_signature_alg.as_str() {
        RS256 => {
            ensure!(
                key.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION,
                "KubeTEE TLS-possession signature is RS256 but the certificate key is not RSA"
            );
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key.subject_public_key.data)
                .verify(nonce.as_bytes(), &signature)
                .map_err(|_| anyhow!("KubeTEE TLS-possession signature does not verify"))
        }
        ES256 => {
            ensure!(
                key.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
                    && key
                        .algorithm
                        .parameters
                        .as_ref()
                        .and_then(|params| params.as_oid().ok())
                        .is_some_and(|curve| curve == OID_EC_P256),
                "KubeTEE TLS-possession signature is ES256 but the certificate key is not P-256"
            );
            // The encoding is not reliably signable from the byte length:
            // raw r||s is always 64 bytes, but so is a DER signature whose
            // r and s integers are short. Accept either form over either
            // length and let verification — not classification — decide.
            let algorithms: &[&dyn ring::signature::VerificationAlgorithm] =
                &[&ECDSA_P256_SHA256_FIXED, &ECDSA_P256_SHA256_ASN1];
            algorithms
                .iter()
                .find_map(|algorithm| {
                    UnparsedPublicKey::new(*algorithm, &key.subject_public_key.data)
                        .verify(nonce.as_bytes(), &signature)
                        .ok()
                })
                .ok_or_else(|| anyhow!("KubeTEE TLS-possession signature does not verify"))
        }
        other => bail!("KubeTEE TLS-possession signature is {other}, expected {ES256} or {RS256}"),
    }
}

/// Log the replica and measured registers of a newly attested connection.
pub fn log_attested(pod: &str, measurements: &Measurements) {
    let [rtmr0, rtmr1, rtmr2, rtmr3] = measurements.rtmrs.map(hex::encode);
    info!(
        pod,
        mrtd = hex::encode(measurements.mrtd),
        mr_config_id = hex::encode(measurements.mr_config_id),
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        "KubeTEE connection attested"
    );
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures intentionally fail hard on malformed local values"
    )]

    use ring::rand::SystemRandom;
    use ring::signature::{
        EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
    };

    use super::*;

    const SESSION_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/session_leaf.der");
    const EC_SESSION_LEAF: &[u8] =
        include_bytes!("../../tests/fixtures/kubetee/ec_session_leaf.der");
    const EC_SESSION_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/kubetee/ec_session_leaf_key.pk8");
    /// A leaf whose P-256 key was constructed to verify
    /// `ES256_SHORT_DER_SIG`: a valid ASN.1 DER ES256 signature of exactly
    /// 64 bytes (28-byte `r` and `s`, each DER-padded to 29). Signing
    /// cannot practically produce that length (probability ~2^-47), so the
    /// fixture is generated in reverse — short `r`/`s` chosen first, the
    /// verifying key derived from them. See the fixtures README.
    const ES256_SHORT_DER_LEAF: &[u8] =
        include_bytes!("../../tests/fixtures/kubetee/es256_short_der_leaf.der");
    const ES256_SHORT_DER_SIG: &[u8] =
        include_bytes!("../../tests/fixtures/kubetee/es256_short_der_sig.bin");
    const FIXTURE_NONCE: &str = "cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a";
    const FIXTURE_KEYSET_DIGEST: &str =
        "sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d";
    const FIXTURE_STATEMENT: &str = r#"{"keyset_digest":"sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d","nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","purpose":"kubetee.attestation.v1"}"#;

    const SPKI_SHA256: &str = "3f728244ad1bb95542b14cdbf7f637105dc588f8958c862e4beffc450c000cd3";

    /// A fixed instant inside every fixture certificate's validity window,
    /// so keyset-deadline tests stay deterministic forever (`SESSION_LEAF`
    /// expires 2026-12-21T10:08:05Z and bounds every keyset deadline).
    fn test_now() -> DateTime<Utc> {
        "2026-11-01T00:00:00Z".parse().unwrap()
    }

    /// `SESSION_LEAF`'s `not_after`, the latest deadline a keyset may claim.
    const SESSION_LEAF_EXPIRY: &str = "2026-12-21T10:08:05Z";

    fn v1_keyset(not_after: &str, spki: &str) -> Value {
        serde_json::json!({
            "subject": "kubetee.attestation.v1/llm.kubetee.ai",
            "not_after": not_after,
            "tls_public_keys": [{"domain": "llm.kubetee.ai", "spki_sha256": spki}],
            "signing_keys": [],
            "e2ee_keys": []
        })
    }

    fn statement(digest: &str, nonce: &str) -> String {
        format!("{{\"keyset_digest\":\"{digest}\",\"nonce\":\"{nonce}\",\"purpose\":\"kubetee.attestation.v1\"}}")
    }

    fn fixture_body(keyset: &Value, statement: &str, digest: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "nonce": FIXTURE_NONCE,
            "keyset": keyset,
            "bindings": {"version": "kubetee.attestation.v1", "report_data_statement": statement, "keyset_digest": digest}
        }))
        .unwrap()
    }

    fn self_consistent_body(not_after: &str, spki: &str) -> Vec<u8> {
        let keyset = v1_keyset(not_after, spki);
        let digest = binding::recompute_keyset_digest(&keyset).unwrap();
        let stmt = statement(&digest, FIXTURE_NONCE);
        fixture_body(&keyset, &stmt, &digest)
    }

    #[test]
    fn a_v1_response_binds_the_serving_key() {
        // SESSION_LEAF_EXPIRY: the certificate's own not_after — what the
        // production gateway copies into the keyset, and the latest deadline
        // the bound in verify_served_keyset accepts.
        let keyset = v1_keyset(SESSION_LEAF_EXPIRY, SPKI_SHA256);
        let digest = binding::recompute_keyset_digest(&keyset).unwrap();
        let stmt = statement(&digest, FIXTURE_NONCE);
        let body = fixture_body(&keyset, &stmt, &digest);
        let bound = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, test_now())
            .unwrap()
            .unwrap();
        assert_eq!(
            bound.report_data,
            binding::report_data_of_statement(&stmt, &digest, FIXTURE_NONCE).unwrap()
        );
        assert_eq!(bound.report_data[32..], [0; 32]);
        assert_eq!(
            bound.not_after,
            SESSION_LEAF_EXPIRY.parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn a_legacy_response_binds_the_legacy_construction() {
        let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","quote":"","report_data_input":"sha512(nonce)"}"#;
        assert!(
            BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF, Utc::now())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_v1_keyset_for_another_serving_key_fails_closed() {
        let body = self_consistent_body(SESSION_LEAF_EXPIRY, &"0".repeat(64));
        let error = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, test_now()).unwrap_err();
        assert!(format!("{error:#}").contains("serving key"));
    }

    #[test]
    fn a_v1_keyset_expired_fails_closed() {
        let body = self_consistent_body("2000-01-01T00:00:00Z", SPKI_SHA256);
        let error = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, test_now()).unwrap_err();
        assert!(format!("{error:#}").contains("expired"));
    }

    /// A keyset may not claim a deadline past the serving certificate's
    /// `not_after`, or the pool could keep reusing the connection after the
    /// certificate itself has expired.
    #[test]
    fn a_v1_keyset_outliving_the_serving_certificate_fails_closed() {
        let body = self_consistent_body("2027-01-01T00:00:00Z", SPKI_SHA256);
        let error = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, test_now()).unwrap_err();
        assert!(format!("{error:#}").contains("outlives the serving certificate"));
    }

    /// RFC 8785 requires object member names be unique. `serde_json::Value`
    /// collapses a repeated name (last one wins) and would digest the
    /// collapsed keyset, so a duplicate anywhere in the response must fail
    /// before parsing — including a different spelling of one name.
    #[test]
    fn a_response_with_duplicate_member_names_fails_closed() {
        let body = format!(
            r#"{{"nonce":"{FIXTURE_NONCE}","nonce":"{FIXTURE_NONCE}","keyset":{{"subject":"a","subject":"b","not_after":"{SESSION_LEAF_EXPIRY}","tls_public_keys":[],"signing_keys":[],"e2ee_keys":[]}},"bindings":{{"version":"kubetee.attestation.v1","report_data_statement":"x","keyset_digest":"sha256:0"}}}}"#
        );
        let error = BindingGuard::run(body.as_bytes(), FIXTURE_NONCE, SESSION_LEAF, test_now())
            .unwrap_err();
        assert!(format!("{error:#}").contains("duplicate member name"));
    }

    #[test]
    fn a_response_with_duplicate_names_spelled_differently_fails_closed() {
        // `"\u006eonce"` decodes to `nonce`: one name, two spellings.
        let body = format!(
            r#"{{"nonce":"{FIXTURE_NONCE}","\u006eonce":"{FIXTURE_NONCE}","bindings":null}}"#
        );
        let error = BindingGuard::run(body.as_bytes(), FIXTURE_NONCE, SESSION_LEAF, test_now())
            .unwrap_err();
        assert!(format!("{error:#}").contains("duplicate member name"));
    }

    #[test]
    fn a_v1_binding_expires_at_its_deadline_including_after_verification_work() {
        // 2026-12-20: after TEST_NOW and before SESSION_LEAF_EXPIRY, so the
        // deadline is within the certificate bound and expiry — not the
        // bound — is what fails here.
        let deadline = "2026-12-20T00:00:00.123456789Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let body = self_consistent_body("2026-12-20T00:00:00.123456789Z", SPKI_SHA256);
        let before = deadline - chrono::Duration::nanoseconds(1);
        let binding = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, before)
            .unwrap()
            .unwrap();
        assert_eq!(binding.not_after, deadline);
        binding.ensure_current(before).unwrap();
        for now in [deadline, deadline + chrono::Duration::nanoseconds(1)] {
            // The same check runs after collateral/quote verification, before
            // a fresh attestation can authorize its first upstream request.
            assert!(binding
                .ensure_current(now)
                .unwrap_err()
                .to_string()
                .contains("expired"));
            assert!(BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, now)
                .unwrap_err()
                .to_string()
                .contains("expired"));
        }
    }

    #[test]
    fn a_half_v1_response_fails_closed() {
        let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","keyset":{}}"#;
        let error = BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF, Utc::now()).unwrap_err();
        assert!(format!("{error:#}").contains("half a v1 binding"));
    }

    #[test]
    fn the_statement_binding_matches_the_python_builder() {
        let bound = binding::report_data_of_statement(
            FIXTURE_STATEMENT,
            FIXTURE_KEYSET_DIGEST,
            FIXTURE_NONCE,
        )
        .unwrap();
        assert_eq!(
            hex::encode(bound),
            "9e4867826f437965258b4bcf964e603e30d31b662a4f3ef0ffc50cba611633710000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    /// An `ES256` possession proof over the per-boot P-256 key, as
    /// `kubetee_attestation.py` emits it (raw `r||s`) and in the DER
    /// encoding a TLS stack would produce. Both must verify.
    #[test]
    fn an_es256_proof_verifies_in_both_encodings() {
        let rng = SystemRandom::new();
        for algorithm in [
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &ECDSA_P256_SHA256_ASN1_SIGNING,
        ] {
            let key = EcdsaKeyPair::from_pkcs8(algorithm, EC_SESSION_KEY, &rng).unwrap();
            let signature = key.sign(&rng, FIXTURE_NONCE.as_bytes()).unwrap();
            let possession = TlsPossession {
                tls_signature: STANDARD.encode(signature.as_ref()),
                tls_signature_alg: ES256.to_owned(),
                tls_cert_sha256: hex::encode(Sha256::digest(EC_SESSION_LEAF)),
            };
            verify_tls_possession(&possession, FIXTURE_NONCE, EC_SESSION_LEAF).unwrap();
        }
    }

    /// A valid ASN.1 DER ES256 signature can be exactly 64 bytes (short `r`
    /// and `s` integers) and must verify; the length-based dispatch sent it
    /// to the raw `r||s` verifier alone, which rejects it — both failures
    /// are pinned here.
    #[test]
    fn a_64_byte_der_es256_proof_verifies() {
        assert_eq!(ES256_SHORT_DER_SIG.len(), 64);
        let (_, certificate) = parse_x509_certificate(ES256_SHORT_DER_LEAF).unwrap();
        // The old length-based classification: 64 bytes -> raw r||s only,
        // and that verifier rejects this valid DER signature.
        assert!(UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_FIXED,
            &certificate.public_key().subject_public_key.data
        )
        .verify(FIXTURE_NONCE.as_bytes(), ES256_SHORT_DER_SIG)
        .is_err());
        let possession = TlsPossession {
            tls_signature: STANDARD.encode(ES256_SHORT_DER_SIG),
            tls_signature_alg: ES256.to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(ES256_SHORT_DER_LEAF)),
        };
        verify_tls_possession(&possession, FIXTURE_NONCE, ES256_SHORT_DER_LEAF).unwrap();
    }

    /// A proof signed by some other P-256 key does not verify against the
    /// certificate it names.
    #[test]
    fn an_es256_proof_from_another_key_fails_closed() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let signature = key.sign(&rng, FIXTURE_NONCE.as_bytes()).unwrap();
        let possession = TlsPossession {
            tls_signature: STANDARD.encode(signature.as_ref()),
            tls_signature_alg: ES256.to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(EC_SESSION_LEAF)),
        };
        let error = verify_tls_possession(&possession, FIXTURE_NONCE, EC_SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("does not verify"));
    }

    /// `ES256` claimed over an RSA certificate key fails closed on the
    /// key type, before any signature check.
    #[test]
    fn an_es256_claim_over_an_rsa_leaf_fails_closed() {
        let possession = TlsPossession {
            tls_signature: STANDARD.encode([0_u8; 64]),
            tls_signature_alg: ES256.to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(SESSION_LEAF)),
        };
        let error = verify_tls_possession(&possession, FIXTURE_NONCE, SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("not P-256"));
    }

    /// An algorithm outside the accepted pair fails closed.
    #[test]
    fn an_unnamed_signature_algorithm_fails_closed() {
        let possession = TlsPossession {
            tls_signature: STANDARD.encode([0_u8; 64]),
            tls_signature_alg: "PS256".to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(EC_SESSION_LEAF)),
        };
        let error = verify_tls_possession(&possession, FIXTURE_NONCE, EC_SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("expected ES256 or RS256"));
    }
}
