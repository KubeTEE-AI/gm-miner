//! The checks on a `KubeTEE` `/v1/attestation` payload, apart from fetching
//! it: the DCAP appraisal, the nonce binding, the event log replay and the
//! TLS-possession proof.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::TDReport10;
use serde_json::Value;
use sha2::{Digest as _, Sha256, Sha512};
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;
use sha2::{Digest as _, Sha256, Sha512};
use tracing::info;
use x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION;
use x509_parser::parse_x509_certificate;

use crate::eventlog::{self, Register};
use crate::tee_evidence;

const SIGNATURE_ALGORITHM: &str = "RS256";

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

impl BindingGuard {
    /// Derive the binding to verify from `body`, or fail closed on any
    /// malformed, mixed, or v1-shape response that does not verify.
    ///
    /// # Errors
    ///
    /// Returns an error when the response is v1-shaped and the statement,
    /// keyset, or version check fails.
    pub(crate) fn run(body: &[u8], nonce: &str, leaf: &[u8]) -> Result<Option<[u8; 64]>> {
        let payload: Value = serde_json::from_slice(body).context("decode KubeTEE attestation response")?;
        let keyset = payload.get("keyset");
        let bindings = payload.get("bindings");
        match (keyset, bindings) {
            (Some(keyset), Some(bindings)) => {
                let fields: BindingFields = serde_json::from_slice(body)
                    .context("decode kubetee.attestation.v1 binding fields")?;
                ensure!(
                    fields.bindings.version == crate::kubetee_verify::binding::PURPOSE,
                    "kubetee.attestation.v1 binding has version {}, expected {}",
                    fields.bindings.version,
                    binding::PURPOSE
                );
                Self::verify_served_keyset(&fields.keyset, &fields.bindings.keyset_digest, leaf)?;
                let report_data = binding::report_data_of_statement(
                    &fields.bindings.report_data_statement,
                    &fields.bindings.keyset_digest,
                    nonce,
                )?;
                Ok(Some(report_data))
            }
            (None, None) => Ok(None),
            _ => bail!("KubeTEE attestation response has half a v1 binding"),
        }
    }

    fn verify_served_keyset(keyset: &Value, stated_digest: &str, leaf: &[u8]) -> Result<()> {
        let (_, certificate) =
            parse_x509_certificate(leaf).map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
        let spki = certificate.public_key().raw;
        let recomputed = binding::keyset_digest_of(spki, keyset)?;
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
                        && key.get("spki_sha256").and_then(Value::as_str) == Some(spki_sha256.as_str())
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
        ensure!(expires > Utc::now(), "kubetee.attestation.v1 keyset is expired");
        Ok(())
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

fn verify_report_data(td: &TDReport10, nonce: &str) -> Result<()> {
    verify_report_data_bound(td, nonce, None)
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
/// certificate and that its key signed `nonce` (RSASSA-PKCS1-v1_5, SHA-256).
fn verify_tls_possession(possession: &TlsPossession, nonce: &str, leaf: &[u8]) -> Result<()> {
    ensure!(
        possession.tls_signature_alg == SIGNATURE_ALGORITHM,
        "KubeTEE TLS-possession signature is {}, expected {SIGNATURE_ALGORITHM}",
        possession.tls_signature_alg
    );
    let claimed = hex::decode(&possession.tls_cert_sha256)
        .context("decode KubeTEE TLS certificate fingerprint")?;
    ensure!(
        claimed.as_slice() == Sha256::digest(leaf).as_slice(),
        "KubeTEE TLS-possession names a certificate other than this connection's"
    );
    let (_, certificate) = parse_x509_certificate(leaf)
        .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
    let key = certificate.public_key();
    ensure!(
        key.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION,
        "KubeTEE TLS certificate key is not RSA"
    );
    let signature = STANDARD
        .decode(&possession.tls_signature)
        .context("decode KubeTEE TLS-possession signature")?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key.subject_public_key.data)
        .verify(nonce.as_bytes(), &signature)
        .map_err(|_| anyhow!("KubeTEE TLS-possession signature does not verify"))
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

    use super::*;

    const SESSION_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/session_leaf.der");
    const FIXTURE_NONCE: &str = "cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a";
    const FIXTURE_KEYSET_DIGEST: &str =
        "sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d";
    const FIXTURE_STATEMENT: &str = r#"{"keyset_digest":"sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d","nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","purpose":"kubetee.attestation.v1"}"#;

    fn fixture_keyset() -> Value {
        serde_json::json!({
            "subject": "kubetee.attestation.v1/llm.kubetee.ai",
            "not_after": "2030-01-01T00:00:00Z",
            "tls_public_keys": [{"domain": "llm.kubetee.ai", "spki_sha256": "3f728244ad1bb95542b14cdbf7f637105dc588f8958c862e4beffc450c000cd3"}],
            "signing_keys": [],
            "e2ee_keys": []
        })
    }

    fn fixture_body(keyset: &Value, statement: &str, digest: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "nonce": FIXTURE_NONCE,
            "keyset": keyset,
            "bindings": {"version": "kubetee.attestation.v1", "report_data_statement": statement, "keyset_digest": digest}
        }))
        .unwrap()
    }

    #[test]
    fn a_v1_response_binds_the_serving_key() {
        let body = fixture_body(&fixture_keyset(), FIXTURE_STATEMENT, FIXTURE_KEYSET_DIGEST);
        let bound = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF).unwrap().unwrap();
        assert_eq!(hex::encode(bound[..32]), hex::encode(Sha256::digest(FIXTURE_STATEMENT.as_bytes())));
        assert_eq!(bound[32..], [0; 32]);
    }

    #[test]
    fn a_legacy_response_binds_the_legacy_construction() {
        let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","quote":"","report_data_input":"sha512(nonce)"}"#;
        assert!(BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF).unwrap().is_none());
    }
    }

    #[test]
    fn a_v1_keyset_for_another_serving_key_fails_closed() {
        let mut keyset = fixture_keyset();
        keyset["tls_public_keys"][0]["spki_sha256"] = serde_json::json!("0".repeat(64));
        let body = fixture_body(&keyset, FIXTURE_STATEMENT, FIXTURE_KEYSET_DIGEST);
        let error = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("keyset digest"));
    }

    #[test]
    fn a_v1_keyset_expired_fails_closed() {
        let mut keyset = fixture_keyset();
        keyset["not_after"] = serde_json::json!("2000-01-01T00:00:00Z");
        let body = fixture_body(&keyset, FIXTURE_STATEMENT, FIXTURE_KEYSET_DIGEST);
        let error = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("expired"));
    }

    #[test]
    fn a_half_v1_response_fails_closed() {
        let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","keyset":{}}"#;
        let error = BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("half a v1 binding"));
    }

    #[test]
    fn the_statement_binding_matches_the_python_builder() {
        let bound = binding::report_data_of_statement(FIXTURE_STATEMENT, FIXTURE_KEYSET_DIGEST, FIXTURE_NONCE)
            .unwrap();
        assert_eq!(
            hex::encode(bound),
            "9e4867826f437965258b4bcf964e603e30d31b662a4f3ef0ffc50cba611633710000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
