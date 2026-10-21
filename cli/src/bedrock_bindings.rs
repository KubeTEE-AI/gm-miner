//! Fixed-origin registry discovery for Bedrock Mantle model bindings.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use anyhow::{bail, Context as _, Result};
use reqwest::{redirect::Policy, Client, StatusCode};
use rustls::{ClientConfig, RootCertStore};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

use crate::network::Network;

pub const BEDROCK_MANTLE_IMAGE_FEATURE: &str = "bedrock-mantle-model-bindings-v1";
pub const MODEL_BINDING_REVISION_HEADER: &str = "x-gm-model-binding-revision";

const BINDINGS_PATH: &str = "/model-bindings/bedrock";
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_BINDINGS: usize = 1024;
const MAX_MODEL_ID_BYTES: usize = 256;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BedrockModelBinding {
    pub model: String,
    pub upstream_model: String,
    pub response_model: String,
    pub revision: u64,
}

/// Fetches the selected network's approved bindings from its fixed registry
/// origin. This endpoint deliberately ignores gmcli's configurable API URL.
///
/// # Errors
///
/// Returns an error when the fixed endpoint cannot be reached, its response
/// exceeds the bounds, or its snapshot does not match the shared schema.
pub async fn fetch_bedrock_model_bindings(network: Network) -> Result<Vec<BedrockModelBinding>> {
    let url = registry_url(network);
    let response = trusted_registry_client()?
        .get(&url)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .context("fetch fixed Bedrock model bindings")?;
    if response.status() != StatusCode::OK {
        bail!(
            "fixed Bedrock model-binding endpoint returned {}",
            response.status()
        );
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        bail!("fixed Bedrock model-binding endpoint did not return JSON");
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        bail!("fixed Bedrock model-binding response exceeds its size limit");
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read Bedrock model bindings")?
    {
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            bail!("fixed Bedrock model-binding response exceeds its size limit");
        }
        body.extend_from_slice(&chunk);
    }
    parse_bindings(&body, network)
}

fn registry_url(network: Network) -> String {
    format!("{}{BINDINGS_PATH}", network.default_registry_url())
}

fn trusted_registry_client() -> Result<Client> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("configure fixed Bedrock registry TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Client::builder()
        .no_proxy()
        .https_only(true)
        .http1_only()
        .pool_max_idle_per_host(0)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .user_agent("gmcli-bedrock-model-bindings/1")
        .use_preconfigured_tls(tls)
        .build()
        .context("initialize fixed Bedrock registry transport")
}

fn parse_bindings(bytes: &[u8], network: Network) -> Result<Vec<BedrockModelBinding>> {
    let value = parse_unique_json(bytes).context("parse Bedrock model-binding JSON")?;
    let object = value
        .as_object()
        .filter(|object| {
            object_has_exact_keys(
                object,
                &["schema_version", "network", "revision", "bindings"],
            )
        })
        .context("invalid Bedrock model-binding envelope")?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        bail!("unsupported Bedrock model-binding schema version");
    }
    if object.get("network").and_then(Value::as_str) != Some(network.as_str()) {
        bail!("Bedrock model-binding response is for a different network");
    }
    let snapshot_revision = object
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision <= MAX_SAFE_INTEGER)
        .context("invalid Bedrock model-binding snapshot revision")?;
    let rows = object
        .get("bindings")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= MAX_BINDINGS)
        .context("invalid Bedrock model-binding list")?;

    let mut bindings = Vec::with_capacity(rows.len());
    let mut models = BTreeSet::new();
    for row in rows {
        let row = row
            .as_object()
            .filter(|row| {
                object_has_exact_keys(
                    row,
                    &[
                        "provider",
                        "model",
                        "upstream_model",
                        "response_model",
                        "revision",
                    ],
                )
            })
            .context("invalid Bedrock model-binding row")?;
        if row.get("provider").and_then(Value::as_str) != Some("anthropic") {
            bail!("unsupported Bedrock model-binding provider");
        }
        let model = row
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| valid_model_id(value))
            .context("invalid canonical Bedrock model id")?;
        let upstream_model = row
            .get("upstream_model")
            .and_then(Value::as_str)
            .filter(|value| valid_bedrock_selector(value))
            .context("invalid Bedrock upstream selector")?;
        let response_model = row
            .get("response_model")
            .and_then(Value::as_str)
            .filter(|value| valid_model_id(value))
            .context("invalid Bedrock response identity")?;
        let revision = row
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|revision| {
                *revision > 0 && *revision <= MAX_SAFE_INTEGER && *revision <= snapshot_revision
            })
            .context("invalid Bedrock model-binding row revision")?;
        if !models.insert(model.to_owned()) {
            bail!("duplicate Bedrock provider/model identity");
        }
        bindings.push(BedrockModelBinding {
            model: model.to_owned(),
            upstream_model: upstream_model.to_owned(),
            response_model: response_model.to_owned(),
            revision,
        });
    }
    bindings.sort_by(|left, right| left.model.cmp(&right.model));
    Ok(bindings)
}

fn object_has_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MODEL_ID_BYTES
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_bedrock_selector(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("anthropic.") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= MAX_MODEL_ID_BYTES
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test assertions use known-valid fixtures"
)]
#[expect(
    clippy::expect_used,
    reason = "test fixture serialization and valid bindings are known-valid"
)]
mod tests {
    use super::*;

    const VALID: &str = r#"{"schema_version":1,"network":"mainnet","revision":9,"bindings":[{"provider":"anthropic","model":"future-model:2027","upstream_model":"anthropic.future-model-2027-v1","response_model":"future-model-provider-echo","revision":4}]}"#;

    #[test]
    fn registry_origins_are_fixed_by_network() {
        assert_eq!(
            registry_url(Network::Mainnet),
            "https://registry.saygm.com/model-bindings/bedrock"
        );
        assert_eq!(
            registry_url(Network::Testnet),
            "https://test-registry.saygm.com/model-bindings/bedrock"
        );
    }

    #[test]
    fn parses_future_binding_with_distinct_raw_identity() {
        let bindings = parse_bindings(VALID.as_bytes(), Network::Mainnet).unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].model, "future-model:2027");
        assert_eq!(bindings[0].upstream_model, "anthropic.future-model-2027-v1");
        assert_eq!(bindings[0].response_model, "future-model-provider-echo");
        assert_eq!(bindings[0].revision, 4);
    }

    #[test]
    fn distinct_canonical_models_may_share_raw_selector_and_echo() {
        let aliases = r#"{"schema_version":1,"network":"mainnet","revision":9,"bindings":[{"provider":"anthropic","model":"future-model-one","upstream_model":"anthropic.shared-system-id","response_model":"shared-provider-echo","revision":4},{"provider":"anthropic","model":"future-model-two","upstream_model":"anthropic.shared-system-id","response_model":"shared-provider-echo","revision":5}]}"#;
        let bindings = parse_bindings(aliases.as_bytes(), Network::Mainnet).expect("valid aliases");
        assert_eq!(bindings.len(), 2);
    }

    #[test]
    fn rejects_duplicate_keys_duplicate_models_unknowns_and_bad_revisions() {
        for invalid in [
            VALID.replace("\"revision\":9", "\"revision\":9,\"revision\":9"),
            VALID.replace(
                "\"model\":\"future-model:2027\"",
                "\"model\":\"future-model:2027\",\"model\":\"other\"",
            ),
            VALID.replace("\"revision\":4", "\"revision\":10"),
            VALID.replace("\"model\":\"future-model:2027\"", "\"model\":\"bad/model\""),
            VALID.replace("\"provider\":\"anthropic\"", "\"provider\":\"openai\""),
            VALID.replace(
                "\"response_model\":\"future-model-provider-echo\"",
                "\"response_model\":\"future-model-provider-echo\",\"custom\":true",
            ),
            VALID.replace("\"revision\":9", "\"revision\":9007199254740992"),
        ] {
            assert!(parse_bindings(invalid.as_bytes(), Network::Mainnet).is_err());
        }
    }

    #[test]
    fn rejects_wrong_network_and_duplicate_binding_identities() {
        assert!(parse_bindings(VALID.as_bytes(), Network::Testnet).is_err());
        let duplicate = r#"{"schema_version":1,"network":"mainnet","revision":9,"bindings":[{"provider":"anthropic","model":"future-model:2027","upstream_model":"anthropic.future-model-2027-v1","response_model":"future-model-provider-echo","revision":4},{"provider":"anthropic","model":"future-model:2027","upstream_model":"anthropic.other-v1","response_model":"other-echo","revision":5}]}"#;
        assert!(parse_bindings(duplicate.as_bytes(), Network::Mainnet).is_err());
    }

    #[test]
    fn rejects_overlong_ids_and_more_than_the_binding_limit() {
        let overlong_model = VALID.replace(
            "future-model:2027",
            &format!("m{}", "x".repeat(MAX_MODEL_ID_BYTES)),
        );
        assert!(parse_bindings(overlong_model.as_bytes(), Network::Mainnet).is_err());

        let rows = (0..=MAX_BINDINGS)
            .map(|index| {
                serde_json::json!({
                    "provider": "anthropic",
                    "model": format!("future-model-{index}"),
                    "upstream_model": format!("anthropic.system-{index}"),
                    "response_model": format!("raw-echo-{index}"),
                    "revision": 1,
                })
            })
            .collect::<Vec<_>>();
        let too_many = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "network": "mainnet",
            "revision": 1,
            "bindings": rows,
        }))
        .expect("test JSON");
        assert!(parse_bindings(&too_many, Network::Mainnet).is_err());
    }
}
