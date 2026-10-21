//! Fixed Bedrock Mantle Messages adapter for the qualified Opus 4.8 tuple.
//!
//! The inbound Anthropic request is parsed into a bounded, duplicate-aware
//! JSON value. Only the reviewed Messages fields and client-executed custom
//! tool protocol are accepted. The adapter then builds a fresh request to the
//! fixed Mantle hostname and path, replacing only the request model selector.
//! Response model identity is checked before returning any response bytes and
//! the original AWS response body is never rewritten.

use std::{collections::BTreeSet, io, sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
        HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    },
    routing::any,
    Router,
};
use futures_util::{stream, StreamExt};
use reqwest::{redirect::Policy, Client};
use rustls::{ClientConfig, RootCertStore};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use tokio::net::TcpListener;
use tracing::info;

pub const BEDROCK_MANTLE_FEATURE: &str = "bedrock-mantle-opus48-v2";
pub const BEDROCK_MANTLE_BIND_ADDR: &str = "127.0.0.1:8085";
pub const BEDROCK_MANTLE_HOST: &str = "bedrock-mantle.us-east-1.api.aws";
pub const BEDROCK_MANTLE_PATH: &str = "/anthropic/v1/messages";
pub const BEDROCK_BUYER_MODEL: &str = "claude-opus-4-8";
pub const BEDROCK_SYSTEM_MODEL: &str = "anthropic.claude-opus-4-8";
pub const BEDROCK_RESPONSE_MODEL: &str = "claude-opus-4-8";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
pub const EXECUTION_POLICY_HEADER: &str = "x-gm-execution-policy";
pub const EXACT_CANONICAL_NO_REPLAY_POLICY: &str = "exact-canonical-no-replay-v1";

const BEDROCK_MANTLE_URL: &str = "https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages";
const MAX_REQUEST_BODY: usize = 20 * 1024 * 1024;
const MAX_RESPONSE_BODY: usize = 32 * 1024 * 1024;
const MAX_STREAM_PREAMBLE: usize = 64 * 1024;
const MAX_TOKENS: u64 = 128_000;
const MAX_MESSAGES: usize = 16_384;

#[derive(Clone)]
pub struct BedrockMantleState {
    client: Client,
    authorization: HeaderValue,
    #[cfg(test)]
    test_upstream_url: Option<String>,
}

impl BedrockMantleState {
    /// Construct the production transport from the one configured Bedrock API
    /// key. No endpoint, proxy, CA, redirect, region, or AWS account override
    /// is accepted from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the qualified region or key is missing or invalid,
    /// or when the fixed TLS client cannot be initialized.
    pub fn from_environment() -> Result<Self, &'static str> {
        let region = std::env::var("BEDROCK_REGION").map_err(|_| "missing Bedrock region")?;
        if region != "us-east-1" {
            return Err("Bedrock Mantle Opus 4.8 requires us-east-1");
        }
        let key = std::env::var("BEDROCK_API_KEY").map_err(|_| "missing Bedrock API key")?;
        if key.is_empty() || key.contains(';') {
            return Err("Bedrock API key must be one non-empty value");
        }
        let authorization = HeaderValue::from_str(&format!("Bearer {key}"))
            .map_err(|_| "Bedrock API key is not a valid HTTP credential")?;

        let client = production_http_client()?;

        Ok(Self {
            client,
            authorization,
            #[cfg(test)]
            test_upstream_url: None,
        })
    }

    #[cfg(test)]
    #[expect(
        clippy::expect_used,
        reason = "test setup uses a fixed local client and credential"
    )]
    fn for_test(url: &str, authorization: &str) -> Self {
        let client = Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .retry(reqwest::retry::never())
            .redirect(Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .expect("test HTTP client");
        Self {
            client,
            authorization: HeaderValue::from_str(authorization).expect("test credential"),
            test_upstream_url: Some(url.to_owned()),
        }
    }
}

/// Build the fixed production transport with an explicit TLS crypto provider.
/// Other workspace dependencies can enable multiple rustls providers, so
/// relying on rustls process-wide auto-selection can panic at startup.
fn production_http_client() -> Result<Client, &'static str> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "failed to configure fixed Bedrock TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();

    // Messages inference is billable. Use one HTTP/1.1 request per new
    // connection, disable reqwest's protocol retry policy, and avoid
    // pooled-connection cancellation retries.
    Client::builder()
        .no_proxy()
        .https_only(true)
        .http1_only()
        .pool_max_idle_per_host(0)
        .retry(reqwest::retry::never())
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30 * 60))
        .user_agent("gm-bedrock-mantle-adapter/1")
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|_| "failed to initialize fixed Bedrock Mantle transport")
}

#[derive(Clone)]
struct AppState(BedrockMantleState);

/// Bind and serve the private loopback adapter used by Envoy.
///
/// # Errors
///
/// Returns an error if the server stops with an I/O failure.
pub async fn serve(listener: TcpListener, state: BedrockMantleState) -> Result<(), &'static str> {
    let app = Router::new()
        .route("/v1/messages", any(handle_request))
        .with_state(AppState(state));
    info!(
        bind = BEDROCK_MANTLE_BIND_ADDR,
        "Bedrock Mantle adapter ready"
    );
    axum::serve(listener, app)
        .await
        .map_err(|_| "Bedrock Mantle adapter stopped")
}

async fn handle_request(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    match forward_request(state.0, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reject {
    Method,
    Path,
    Header,
    BodyTooLarge,
    InvalidBody,
    Upstream,
}

impl Reject {
    fn into_response(self) -> Response<Body> {
        let (status, error_type, message) = match self {
            Self::Method => (
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request_error",
                "Bedrock Messages requires POST",
            ),
            Self::Path => (
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                "Bedrock Messages path or query is not allowed",
            ),
            Self::Header => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock Messages headers are invalid",
            ),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                "Bedrock Messages body exceeds the adapter limit",
            ),
            Self::InvalidBody => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock Messages body is not supported",
            ),
            Self::Upstream => (
                StatusCode::BAD_GATEWAY,
                "api_error",
                "Bedrock Mantle request failed",
            ),
        };
        let body = format!("{{\"error\":{{\"type\":\"{error_type}\",\"message\":\"{message}\"}}}}");
        response(status, "application/json", Body::from(body))
    }
}

async fn forward_request(
    state: BedrockMantleState,
    request: Request<Body>,
) -> Result<Response<Body>, Reject> {
    if request.method() != Method::POST {
        return Err(Reject::Method);
    }
    if request
        .uri()
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        != Some("/v1/messages")
    {
        return Err(Reject::Path);
    }
    validate_inbound_headers(request.headers())?;

    let bytes = to_bytes(request.into_body(), MAX_REQUEST_BODY)
        .await
        .map_err(|_| Reject::BodyTooLarge)?;
    let (upstream_body, stream_response) = prepare_request_body(&bytes)?;

    let accept = if stream_response {
        "text/event-stream"
    } else {
        "application/json"
    };
    let url = upstream_url({
        #[cfg(test)]
        {
            state.test_upstream_url.as_deref()
        }
        #[cfg(not(test))]
        {
            None
        }
    });
    let upstream = state
        .client
        .post(url)
        .header(AUTHORIZATION, state.authorization)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, accept)
        .body(upstream_body)
        .send()
        .await
        .map_err(|_| Reject::Upstream)?;

    if upstream.status() != StatusCode::OK {
        return Err(Reject::Upstream);
    }
    if stream_response {
        let content_type = upstream
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(Reject::Upstream);
        }
        let source = upstream
            .bytes_stream()
            .map(|result| {
                result.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "upstream stream interrupted",
                    )
                })
            })
            .boxed();
        let (preamble, source) = validate_stream_identity(source).await?;
        let first = stream::once(async move { Ok::<Bytes, io::Error>(preamble) });
        let body = Body::from_stream(guard_stream(first.chain(source).boxed()));
        Ok(response(StatusCode::OK, "text/event-stream", body))
    } else {
        let content_type = upstream
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(Reject::Upstream);
        }
        let body = read_bounded_response(upstream).await?;
        validate_response_identity(&body)?;
        Ok(response(
            StatusCode::OK,
            "application/json",
            Body::from(body),
        ))
    }
}

fn validate_inbound_headers(headers: &HeaderMap) -> Result<(), Reject> {
    let mut execution_policies = headers.get_all(EXECUTION_POLICY_HEADER).iter();
    if execution_policies
        .next()
        .and_then(|value| value.to_str().ok())
        != Some(EXACT_CANONICAL_NO_REPLAY_POLICY)
        || execution_policies.next().is_some()
        || headers.contains_key("x-gm-bedrock-mantle-opus48-route")
    {
        return Err(Reject::Header);
    }

    if headers.contains_key("anthropic-workspace-id")
        || headers.contains_key("anthropic-beta")
        || headers.contains_key(CONTENT_ENCODING)
    {
        return Err(Reject::Header);
    }
    if headers.keys().any(|name| {
        name.as_str().starts_with("x-amzn-bedrock-")
            || (name.as_str().starts_with("anthropic-") && name.as_str() != "anthropic-version")
    }) {
        return Err(Reject::Header);
    }

    let content_types = headers.get_all(CONTENT_TYPE).iter().collect::<Vec<_>>();
    if content_types.len() != 1
        || content_types[0]
            .to_str()
            .ok()
            .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
    {
        return Err(Reject::Header);
    }
    let versions = headers
        .get_all("anthropic-version")
        .iter()
        .collect::<Vec<_>>();
    if versions.len() != 1
        || versions[0]
            .to_str()
            .ok()
            .is_none_or(|value| value != ANTHROPIC_VERSION)
    {
        return Err(Reject::Header);
    }
    Ok(())
}

fn prepare_request_body(bytes: &[u8]) -> Result<(String, bool), Reject> {
    let mut value = parse_unique_json(bytes).map_err(|_| Reject::InvalidBody)?;
    let object = value.as_object_mut().ok_or(Reject::InvalidBody)?;
    let allowed = [
        "model",
        "max_tokens",
        "messages",
        "system",
        "stop_sequences",
        "temperature",
        "top_p",
        "top_k",
        "stream",
        "tools",
        "tool_choice",
        "thinking",
        "output_config",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(Reject::InvalidBody);
    }

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .ok_or(Reject::InvalidBody)?;
    if model != BEDROCK_BUYER_MODEL {
        return Err(Reject::InvalidBody);
    }
    let max_tokens = object
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|value| (1..=MAX_TOKENS).contains(value))
        .ok_or(Reject::InvalidBody)?;
    let _ = max_tokens;
    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .filter(|messages| !messages.is_empty() && messages.len() <= MAX_MESSAGES)
        .ok_or(Reject::InvalidBody)?;
    for message in messages {
        validate_message(message)?;
    }
    if let Some(system) = object.get("system") {
        validate_text_content(system)?;
    }
    let stream_response = match object.get("stream") {
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(Reject::InvalidBody),
        None => false,
    };
    if let Some(Value::Array(stops)) = object.get("stop_sequences") {
        if stops.len() > 64 || stops.iter().any(|value| value.as_str().is_none()) {
            return Err(Reject::InvalidBody);
        }
    } else if object.contains_key("stop_sequences") {
        return Err(Reject::InvalidBody);
    }
    if let Some(value) = object.get("temperature") {
        if !valid_unit_float(value) {
            return Err(Reject::InvalidBody);
        }
    }
    if let Some(value) = object.get("top_p") {
        if !valid_unit_float(value) {
            return Err(Reject::InvalidBody);
        }
    }
    if let Some(value) = object.get("top_k") {
        if value.as_u64().is_none_or(|value| value > 500) {
            return Err(Reject::InvalidBody);
        }
    }
    if let Some(value) = object.get("tools") {
        validate_tools(value)?;
    }
    if let Some(value) = object.get("tool_choice") {
        validate_tool_choice(value)?;
    }
    if let Some(value) = object.get("thinking") {
        validate_thinking(value)?;
    }
    if let Some(value) = object.get("output_config") {
        validate_output_config(value)?;
    }
    object.insert(
        "model".to_owned(),
        Value::String(BEDROCK_SYSTEM_MODEL.to_owned()),
    );
    serde_json::to_string(&value)
        .map(|body| (body, stream_response))
        .map_err(|_| Reject::InvalidBody)
}

fn valid_unit_float(value: &Value) -> bool {
    value
        .as_number()
        .and_then(Number::as_f64)
        .is_some_and(|value| value.is_finite() && (0.0..=1.0).contains(&value))
}

fn validate_message(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "role" | "content"))
    {
        return Err(Reject::InvalidBody);
    }
    if !matches!(
        object.get("role").and_then(Value::as_str),
        Some("user" | "assistant")
    ) {
        return Err(Reject::InvalidBody);
    }
    let content = object.get("content").ok_or(Reject::InvalidBody)?;
    validate_content(content, true)
}

fn validate_text_content(value: &Value) -> Result<(), Reject> {
    match value {
        Value::String(_) => Ok(()),
        Value::Array(blocks) => {
            for block in blocks {
                validate_block(block, false)?;
            }
            Ok(())
        }
        _ => Err(Reject::InvalidBody),
    }
}

fn validate_content(value: &Value, allow_tool_blocks: bool) -> Result<(), Reject> {
    match value {
        Value::String(_) => Ok(()),
        Value::Array(blocks) => {
            for block in blocks {
                validate_block(block, allow_tool_blocks)?;
            }
            Ok(())
        }
        _ => Err(Reject::InvalidBody),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the complete closed content-block allowlist stays together for audit"
)]
fn validate_block(value: &Value, allow_tool_blocks: bool) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Reject::InvalidBody)?;
    match kind {
        "text" => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "text" | "cache_control"))
                || object.get("text").and_then(Value::as_str).is_none()
            {
                return Err(Reject::InvalidBody);
            }
            validate_cache_control(object.get("cache_control"))
        }
        "image" => {
            if !allow_tool_blocks
                || object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "type" | "source" | "cache_control"))
            {
                return Err(Reject::InvalidBody);
            }
            validate_cache_control(object.get("cache_control"))?;
            validate_inline_source(
                object.get("source").ok_or(Reject::InvalidBody)?,
                &["image/jpeg", "image/png", "image/gif", "image/webp"],
            )
        }
        "document" => {
            if !allow_tool_blocks
                || object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "type" | "source" | "title" | "context" | "cache_control"
                    )
                })
            {
                return Err(Reject::InvalidBody);
            }
            for key in ["title", "context"] {
                if object
                    .get(key)
                    .is_some_and(|value| value.as_str().is_none())
                {
                    return Err(Reject::InvalidBody);
                }
            }
            validate_cache_control(object.get("cache_control"))?;
            validate_inline_source(
                object.get("source").ok_or(Reject::InvalidBody)?,
                &["application/pdf"],
            )
        }
        "tool_use" if allow_tool_blocks => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "id" | "name" | "input"))
                || object.get("id").and_then(Value::as_str).is_none()
                || object.get("name").and_then(Value::as_str).is_none()
                || object.get("input").is_none()
            {
                return Err(Reject::InvalidBody);
            }
            Ok(())
        }
        "tool_result" if allow_tool_blocks => {
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type" | "tool_use_id" | "content" | "is_error" | "cache_control"
                )
            }) || object.get("tool_use_id").and_then(Value::as_str).is_none()
                || object
                    .get("is_error")
                    .is_some_and(|value| value.as_bool().is_none())
            {
                return Err(Reject::InvalidBody);
            }
            validate_cache_control(object.get("cache_control"))?;
            if let Some(content) = object.get("content") {
                validate_content(content, true)?;
            }
            Ok(())
        }
        "thinking" if allow_tool_blocks => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "thinking" | "signature"))
                || object.get("thinking").and_then(Value::as_str).is_none()
                || object.get("signature").and_then(Value::as_str).is_none()
            {
                return Err(Reject::InvalidBody);
            }
            Ok(())
        }
        "redacted_thinking" if allow_tool_blocks => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "data"))
                || object.get("data").and_then(Value::as_str).is_none()
            {
                return Err(Reject::InvalidBody);
            }
            Ok(())
        }
        _ => Err(Reject::InvalidBody),
    }
}

fn validate_inline_source(value: &Value, allowed_media_types: &[&str]) -> Result<(), Reject> {
    let source = value.as_object().ok_or(Reject::InvalidBody)?;
    if source
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "media_type" | "data"))
        || source.get("type").and_then(Value::as_str) != Some("base64")
        || source
            .get("media_type")
            .and_then(Value::as_str)
            .is_none_or(|media| !allowed_media_types.contains(&media))
        || source.get("data").and_then(Value::as_str).is_none()
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_cache_control(value: Option<&Value>) -> Result<(), Reject> {
    let Some(value) = value else {
        return Ok(());
    };
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "ttl"))
        || object.get("type").and_then(Value::as_str) != Some("ephemeral")
        || object
            .get("ttl")
            .is_some_and(|ttl| !matches!(ttl.as_str(), Some("5m" | "1h")))
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_tools(value: &Value) -> Result<(), Reject> {
    let tools = value.as_array().ok_or(Reject::InvalidBody)?;
    if tools.len() > 128 {
        return Err(Reject::InvalidBody);
    }
    for tool in tools {
        let object = tool.as_object().ok_or(Reject::InvalidBody)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type" | "name" | "description" | "input_schema" | "cache_control" | "strict"
            )
        }) || object
            .get("type")
            .is_some_and(|value| value.as_str() != Some("custom"))
            || object
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || object
                .get("input_schema")
                .and_then(Value::as_object)
                .is_none()
            || object
                .get("description")
                .is_some_and(|value| value.as_str().is_none())
            || object
                .get("strict")
                .is_some_and(|value| value.as_bool().is_none())
        {
            return Err(Reject::InvalidBody);
        }
        validate_cache_control(object.get("cache_control"))?;
    }
    Ok(())
}

fn validate_tool_choice(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "name" | "disable_parallel_tool_use"))
        || !matches!(
            object.get("type").and_then(Value::as_str),
            Some("auto" | "any" | "tool" | "none")
        )
        || object
            .get("name")
            .is_some_and(|value| value.as_str().is_none())
        || object
            .get("disable_parallel_tool_use")
            .is_some_and(|value| value.as_bool().is_none())
    {
        return Err(Reject::InvalidBody);
    }
    if object.get("type").and_then(Value::as_str) == Some("tool")
        && object.get("name").and_then(Value::as_str).is_none()
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_thinking(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "budget_tokens" | "effort"))
        || !matches!(
            object.get("type").and_then(Value::as_str),
            Some("enabled" | "adaptive" | "disabled")
        )
        || object.get("budget_tokens").is_some_and(|value| {
            value
                .as_u64()
                .is_none_or(|value| value == 0 || value > MAX_TOKENS)
        })
        || object
            .get("effort")
            .is_some_and(|value| !matches!(value.as_str(), Some("low" | "medium" | "high" | "max")))
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_output_config(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "effort" | "format"))
        || object
            .get("effort")
            .is_some_and(|value| !matches!(value.as_str(), Some("low" | "medium" | "high" | "max")))
    {
        return Err(Reject::InvalidBody);
    }
    if let Some(format) = object.get("format") {
        let format = format.as_object().ok_or(Reject::InvalidBody)?;
        if format
            .keys()
            .any(|key| !matches!(key.as_str(), "type" | "schema"))
            || format.get("type").and_then(Value::as_str) != Some("json_schema")
            || format.get("schema").and_then(Value::as_object).is_none()
        {
            return Err(Reject::InvalidBody);
        }
    }
    Ok(())
}

async fn read_bounded_response(response: reqwest::Response) -> Result<Vec<u8>, Reject> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Reject::Upstream)?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY {
            return Err(Reject::Upstream);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_response_identity(bytes: &[u8]) -> Result<(), Reject> {
    let value = parse_unique_json(bytes).map_err(|_| Reject::Upstream)?;
    let object = value.as_object().ok_or(Reject::Upstream)?;
    if object.get("model").and_then(Value::as_str) != Some(BEDROCK_RESPONSE_MODEL) {
        return Err(Reject::Upstream);
    }
    Ok(())
}

type BoxBodyStream = futures_util::stream::BoxStream<'static, Result<Bytes, io::Error>>;

async fn validate_stream_identity(
    mut source: BoxBodyStream,
) -> Result<(Bytes, BoxBodyStream), Reject> {
    let mut buffer = Vec::new();
    let mut scanned = 0usize;
    let mut preamble_bytes = 0usize;
    loop {
        let Some(next) = source.next().await else {
            return Err(Reject::Upstream);
        };
        let chunk = next.map_err(|_| Reject::Upstream)?;
        buffer.extend_from_slice(&chunk);
        loop {
            let Some((frame_end, separator_end)) = find_sse_frame(&buffer[scanned..]) else {
                if buffer.len().saturating_sub(scanned) > MAX_STREAM_PREAMBLE
                    || preamble_bytes.saturating_add(buffer.len().saturating_sub(scanned))
                        > MAX_STREAM_PREAMBLE
                {
                    return Err(Reject::Upstream);
                }
                break;
            };
            let frame_start = scanned;
            let frame_end = scanned + frame_end;
            let after_frame = scanned + separator_end;
            let frame = &buffer[frame_start..frame_end];
            preamble_bytes = preamble_bytes.saturating_add(after_frame - frame_start);
            if preamble_bytes > MAX_STREAM_PREAMBLE {
                return Err(Reject::Upstream);
            }
            match parse_sse_preamble_frame(frame)? {
                StreamPreambleEvent::Empty | StreamPreambleEvent::Ping => {
                    scanned = after_frame;
                }
                StreamPreambleEvent::MessageStart => {
                    return Ok((Bytes::from(buffer), source));
                }
                StreamPreambleEvent::Other => return Err(Reject::Upstream),
            }
        }
        if buffer.len().saturating_sub(scanned) > MAX_STREAM_PREAMBLE {
            return Err(Reject::Upstream);
        }
        if scanned > 0 && scanned >= buffer.len() / 2 {
            buffer.drain(..scanned);
            scanned = 0;
        }
    }
}

/// Preserve the AWS event bytes while requiring a well-formed terminal event.
/// The stream is deliberately not retried: an interrupted response becomes a
/// body error after the already validated message-start event.
fn guard_stream(source: BoxBodyStream) -> BoxBodyStream {
    let guarded = stream::unfold(
        (source, Vec::new(), 0usize, false, false, false),
        |(mut source, mut pending, mut total, mut started, mut terminal, failed)| async move {
            if failed {
                return None;
            }
            match source.next().await {
                Some(Ok(chunk)) => {
                    total = total.saturating_add(chunk.len());
                    if total > MAX_RESPONSE_BODY || (terminal && !chunk.is_empty()) {
                        let error = io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Bedrock Mantle event stream",
                        );
                        return Some((
                            Err(error),
                            (source, pending, total, started, terminal, true),
                        ));
                    }
                    pending.extend_from_slice(&chunk);
                    let mut consumed = 0usize;
                    while let Some((frame_end, separator_end)) =
                        find_sse_frame(&pending[consumed..])
                    {
                        let start = consumed;
                        let frame_end = consumed + frame_end;
                        let after_frame = consumed + separator_end;
                        match parse_stream_event(&pending[start..frame_end]) {
                            Ok(StreamEvent::Empty | StreamEvent::Ping) if !terminal => {}
                            Ok(StreamEvent::MessageStart) if !started && !terminal => {
                                started = true;
                            }
                            Ok(StreamEvent::MessageStop | StreamEvent::Error)
                                if started && !terminal =>
                            {
                                terminal = true;
                            }
                            Ok(StreamEvent::Other) if started && !terminal => {}
                            _ => {
                                let error = io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid Bedrock Mantle event stream",
                                );
                                return Some((
                                    Err(error),
                                    (source, pending, total, started, terminal, true),
                                ));
                            }
                        }
                        consumed = after_frame;
                        if terminal && consumed < pending.len() {
                            let error = io::Error::new(
                                io::ErrorKind::InvalidData,
                                "data follows terminal Bedrock Mantle event",
                            );
                            return Some((
                                Err(error),
                                (source, pending, total, started, terminal, true),
                            ));
                        }
                    }
                    if pending.len().saturating_sub(consumed) > MAX_STREAM_PREAMBLE {
                        let error = io::Error::new(
                            io::ErrorKind::InvalidData,
                            "oversized Bedrock Mantle event frame",
                        );
                        return Some((
                            Err(error),
                            (source, pending, total, started, terminal, true),
                        ));
                    }
                    if consumed > 0 {
                        pending.drain(..consumed);
                    }
                    Some((
                        Ok(chunk),
                        (source, pending, total, started, terminal, false),
                    ))
                }
                Some(Err(error)) => Some((
                    Err(error),
                    (source, pending, total, started, terminal, true),
                )),
                None if terminal && pending.is_empty() => None,
                None => {
                    let error = io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Bedrock Mantle event stream ended without a terminal event",
                    );
                    Some((
                        Err(error),
                        (source, pending, total, started, terminal, true),
                    ))
                }
            }
        },
    );
    guarded.boxed()
}

enum StreamEvent {
    Empty,
    Ping,
    MessageStart,
    MessageStop,
    Error,
    Other,
}

fn parse_stream_event(frame: &[u8]) -> Result<StreamEvent, Reject> {
    let text = std::str::from_utf8(frame).map_err(|_| Reject::Upstream)?;
    let mut event = None;
    let mut data: Option<Vec<u8>> = None;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            if event.replace(value.trim_start()).is_some() {
                return Err(Reject::Upstream);
            }
        } else if let Some(value) = line.strip_prefix("data:") {
            if data.is_some() {
                return Err(Reject::Upstream);
            }
            data = Some(value.trim_start().as_bytes().to_vec());
        } else {
            return Err(Reject::Upstream);
        }
    }
    let Some(event) = event else {
        return if data.is_none() {
            Ok(StreamEvent::Empty)
        } else {
            Err(Reject::Upstream)
        };
    };
    if event == "ping" {
        if let Some(data) = data {
            if !data.is_empty()
                && parse_unique_json(&data)
                    .ok()
                    .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
                    .as_deref()
                    != Some("ping")
            {
                return Err(Reject::Upstream);
            }
        }
        return Ok(StreamEvent::Ping);
    }
    let data = data
        .filter(|data| !data.is_empty())
        .ok_or(Reject::Upstream)?;
    let value = parse_unique_json(&data).map_err(|_| Reject::Upstream)?;
    if value.get("type").and_then(Value::as_str) != Some(event) {
        return Err(Reject::Upstream);
    }
    match event {
        "message_start" => Ok(StreamEvent::MessageStart),
        "message_stop" => Ok(StreamEvent::MessageStop),
        "error" => Ok(StreamEvent::Error),
        "content_block_start" | "content_block_delta" | "content_block_stop" | "message_delta" => {
            Ok(StreamEvent::Other)
        }
        _ => Err(Reject::Upstream),
    }
}

enum StreamPreambleEvent {
    Empty,
    Ping,
    MessageStart,
    Other,
}

fn parse_sse_preamble_frame(frame: &[u8]) -> Result<StreamPreambleEvent, Reject> {
    let text = std::str::from_utf8(frame).map_err(|_| Reject::Upstream)?;
    let mut event = None;
    let mut data = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            if event.is_some() {
                return Err(Reject::Upstream);
            }
            event = Some(value.trim_start());
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                return Err(Reject::Upstream);
            }
            data.extend_from_slice(value.trim_start().as_bytes());
        } else {
            return Err(Reject::Upstream);
        }
    }
    let Some(event) = event else {
        return if data.is_empty() {
            Ok(StreamPreambleEvent::Empty)
        } else {
            Err(Reject::Upstream)
        };
    };
    if event == "ping" {
        if !data.is_empty() {
            let ping = parse_unique_json(&data).map_err(|_| Reject::Upstream)?;
            if ping.get("type").and_then(Value::as_str) != Some("ping") {
                return Err(Reject::Upstream);
            }
        }
        return Ok(StreamPreambleEvent::Ping);
    }
    if event != "message_start" || data.is_empty() {
        return Ok(StreamPreambleEvent::Other);
    }
    let value = parse_unique_json(&data).map_err(|_| Reject::Upstream)?;
    if value.get("type").and_then(Value::as_str) != Some("message_start")
        || value
            .get("message")
            .and_then(|message| message.get("model"))
            .and_then(Value::as_str)
            != Some(BEDROCK_RESPONSE_MODEL)
    {
        return Err(Reject::Upstream);
    }
    Ok(StreamPreambleEvent::MessageStart)
}

fn find_sse_frame(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|window| window == b"\n\n");
    let crlf = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) if crlf < lf => Some((crlf, crlf + 4)),
        (Some(lf), _) => Some((lf, lf + 2)),
        (None, Some(crlf)) => Some((crlf, crlf + 4)),
        (None, None) => None,
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
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

fn response(status: StatusCode, content_type: &'static str, body: Body) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn upstream_url(test_override: Option<&str>) -> &str {
    test_override.unwrap_or(BEDROCK_MANTLE_URL)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions use known-valid fixtures"
)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, routing::post};
    use serde_json::json;
    use tokio::task::JoinHandle;

    const VALID_BODY: &str = r#"{"model":"claude-opus-4-8","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}"#;

    #[test]
    fn production_transport_initializes_with_explicit_crypto_provider() {
        assert!(production_http_client().is_ok());
    }

    #[test]
    fn request_model_is_closed_and_rewritten_only_to_the_fixed_system_id() {
        let (rewritten, streaming) = prepare_request_body(VALID_BODY.as_bytes()).expect("body");
        let value: Value = serde_json::from_str(&rewritten).expect("rewritten json");
        assert_eq!(value["model"], BEDROCK_SYSTEM_MODEL);
        assert_eq!(value["messages"][0]["content"], "hello");
        assert!(!streaming);
        for model in [
            "anthropic/claude-opus-4-8",
            "anthropic.claude-opus-4-8",
            "claude-sonnet-4-6",
        ] {
            let body = VALID_BODY.replace(BEDROCK_BUYER_MODEL, model);
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
    }

    #[test]
    fn parser_rejects_duplicate_selectors_and_nested_duplicate_fields() {
        let duplicate_model = br#"{"model":"claude-opus-4-8","model":"claude-sonnet-4-6","max_tokens":32,"messages":[{"role":"user","content":"x"}]}"#;
        assert_eq!(
            prepare_request_body(duplicate_model),
            Err(Reject::InvalidBody)
        );
        let duplicate_nested = br#"{"model":"claude-opus-4-8","max_tokens":32,"messages":[{"role":"user","content":[{"type":"text","text":"a","text":"b"}]}]}"#;
        assert_eq!(
            prepare_request_body(duplicate_nested),
            Err(Reject::InvalidBody)
        );
    }

    #[test]
    fn rejects_cloudtrail_selector_type_confusion_and_unknown_capture_fields() {
        for field in [
            r#""stream":"false""#,
            r#""max_tokens":"32""#,
            r#""metadata":{"user_id":"buyer"}"#,
            r#""mcp_servers":[]"#,
            r#""container":{"id":"remote"}"#,
            r#""unknown_feature":true"#,
        ] {
            let body = format!(
                r#"{{"model":"{BEDROCK_BUYER_MODEL}","max_tokens":32,"messages":[{{"role":"user","content":"hello"}}],{field}}}"#
            );
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody),
                "{field}"
            );
        }
    }

    #[test]
    fn preserves_client_side_tool_workflows_and_inline_media_semantically() {
        let value = json!({
            "model": BEDROCK_BUYER_MODEL,
            "max_tokens": 1024,
            "stream": true,
            "system": [{ "type": "text", "text": "follow the tool schema", "cache_control": { "type": "ephemeral", "ttl": "5m" } }],
            "tools": [{
                "name": "lookup_order",
                "description": "Read order data",
                "input_schema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] }
            }],
            "tool_choice": { "type": "auto" },
            "messages": [
                { "role": "user", "content": [{ "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "aGVsbG8=" } }] },
                { "role": "assistant", "content": [{ "type": "tool_use", "id": "toolu_1", "name": "lookup_order", "input": { "id": "42" } }] },
                { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "toolu_1", "content": "order found" }] },
                { "role": "assistant", "content": [{ "type": "text", "text": "done" }] }
            ]
        });
        let bytes = serde_json::to_vec(&value).expect("json");
        let (body, stream) = prepare_request_body(&bytes).expect("tool workflow");
        let rewritten: Value = serde_json::from_str(&body).expect("rewritten body");
        assert_eq!(rewritten["model"], BEDROCK_SYSTEM_MODEL);
        assert_eq!(rewritten["messages"], value["messages"]);
        assert_eq!(rewritten["tools"], value["tools"]);
        assert_eq!(rewritten["system"], value["system"]);
        assert!(stream);
    }

    #[test]
    fn rejects_server_side_tools_and_external_or_file_media() {
        let bodies = [
            r#"{"type":"web_search_20250305","name":"search","input_schema":{"type":"object"}}"#,
            r#"{"type":"mcp_toolset","mcp_servers":[]}"#,
        ];
        for tool in bodies {
            let body = format!("{{\"model\":\"{BEDROCK_BUYER_MODEL}\",\"max_tokens\":32,\"tools\":[{tool}],\"messages\":[{{\"role\":\"user\",\"content\":\"x\"}}]}}" );
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
        for source in [
            r#"{"type":"url","url":"https://example.invalid/prompt.pdf"}"#,
            r#"{"type":"file_id","file_id":"file_123"}"#,
        ] {
            let body = format!("{{\"model\":\"{BEDROCK_BUYER_MODEL}\",\"max_tokens\":32,\"messages\":[{{\"role\":\"user\",\"content\":[{{\"type\":\"image\",\"source\":{source}}}]}}]}}" );
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
    }

    #[test]
    fn response_identity_is_required_and_raw_model_string_is_preserved() {
        let correct = br#"{"id":"msg_1","type":"message","model":"claude-opus-4-8","content":[],"stop_reason":"end_turn"}"#;
        validate_response_identity(correct).expect("identity");
        let wrong = br#"{"model":"claude-opus-4-7"}"#;
        assert_eq!(validate_response_identity(wrong), Err(Reject::Upstream));
        let duplicate = br#"{"model":"claude-opus-4-8","model":"claude-opus-4-7"}"#;
        assert_eq!(validate_response_identity(duplicate), Err(Reject::Upstream));
        assert_eq!(BEDROCK_RESPONSE_MODEL, "claude-opus-4-8");
    }

    #[tokio::test]
    async fn stream_is_not_released_before_the_identity_event() {
        let wrong = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-7\"}}\n\n";
        let chunks = stream::iter([Ok(Bytes::copy_from_slice(wrong))]).boxed();
        assert!(validate_stream_identity(chunks).await.is_err());
        let correct = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-8\"}}\n\n";
        let chunks = stream::iter([Ok(Bytes::copy_from_slice(correct))]).boxed();
        let (preamble, mut rest) = validate_stream_identity(chunks)
            .await
            .expect("stream identity");
        assert_eq!(&preamble[..], correct);
        assert!(rest.next().await.is_none());
    }

    #[tokio::test]
    async fn guarded_stream_requires_a_terminal_event_and_preserves_valid_bytes() {
        let valid = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-8\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        let chunks = stream::iter([Ok(Bytes::from_static(valid.as_bytes()))]).boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 1);
        assert_eq!(
            collected[0].as_ref().expect("valid stream").as_ref(),
            valid.as_bytes()
        );

        let unterminated = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-8\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\"}\n\n"
        );
        let chunks = stream::iter([Ok(Bytes::from_static(unterminated.as_bytes()))]).boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 2);
        assert!(collected[0].is_ok());
        assert_eq!(
            collected[1]
                .as_ref()
                .expect_err("missing terminal must fail")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn guarded_stream_rejects_data_after_terminal_and_interrupted_transport() {
        let after_terminal = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-8\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            "event: ping\ndata: {\"type\":\"ping\"}\n\n"
        );
        let chunks = stream::iter([Ok(Bytes::from_static(after_terminal.as_bytes()))]).boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 1);
        assert_eq!(
            collected[0]
                .as_ref()
                .expect_err("data after terminal must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let interrupted = stream::iter([
            Ok(Bytes::from_static(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-8\"}}\n\n")),
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "test interruption")),
        ]).boxed();
        let collected = guard_stream(interrupted).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 2);
        assert_eq!(
            collected[1]
                .as_ref()
                .expect_err("interrupted stream must fail")
                .kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn local_proxy_rejects_query_path_and_workspace_before_upstream() {
        let (state, calls) = test_state().await;
        let response = handle_request(
            State(AppState(state.clone())),
            request("/v1/messages?workspace=attacker", VALID_BODY),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let mut workspace = request("/v1/messages", VALID_BODY);
        workspace
            .headers_mut()
            .insert("anthropic-workspace-id", HeaderValue::from_static("other"));
        let response = handle_request(State(AppState(state)), workspace).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn execution_policy_must_be_single_and_exact_before_upstream_dispatch() {
        let (state, calls) = test_state().await;
        let cases = [
            ("missing", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().remove(EXECUTION_POLICY_HEADER);
                request
            }),
            ("duplicate", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().append(
                    EXECUTION_POLICY_HEADER,
                    HeaderValue::from_static(EXACT_CANONICAL_NO_REPLAY_POLICY),
                );
                request
            }),
            ("wrong value", {
                let mut request = request("/v1/messages", VALID_BODY);
                request
                    .headers_mut()
                    .insert(EXECUTION_POLICY_HEADER, HeaderValue::from_static("true"));
                request
            }),
            ("legacy marker only", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().remove(EXECUTION_POLICY_HEADER);
                request.headers_mut().insert(
                    "x-gm-bedrock-mantle-opus48-route",
                    HeaderValue::from_static("1"),
                );
                request
            }),
            ("legacy marker with valid policy", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().insert(
                    "x-gm-bedrock-mantle-opus48-route",
                    HeaderValue::from_static("1"),
                );
                request
            }),
        ];
        for (label, request) in cases {
            let response = handle_request(State(AppState(state.clone())), request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn failed_upstream_dispatch_is_attempted_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let attempts = std::sync::Arc::new(AtomicUsize::new(0));
        let recorded = attempts.clone();
        let accept_task = tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                recorded.fetch_add(1, Ordering::Relaxed);
            }
            if tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
            {
                recorded.fetch_add(1, Ordering::Relaxed);
            }
        });
        let url = format!("http://{address}/anthropic/v1/messages");
        let state = BedrockMantleState::for_test(&url, "Bearer configured-only");
        let response =
            handle_request(State(AppState(state)), request("/v1/messages", VALID_BODY)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        accept_task.await.expect("accept task");
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn proxy_sends_only_fixed_headers_and_rewrites_only_model() {
        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let capture = received.clone();
        let upstream_app = Router::new().route(
            "/anthropic/v1/messages",
            post(move |request: Request<Body>| {
                let capture = capture.clone();
                async move {
                    let headers = request.headers().clone();
                    let body = to_bytes(request.into_body(), MAX_REQUEST_BODY)
                        .await
                        .expect("body");
                    *capture.lock().expect("capture") = Some((headers, body.to_vec()));
                    (
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"model":"claude-opus-4-8","id":"msg_1"}"#,
                    )
                }
            }),
        );
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let upstream_addr = upstream_listener.local_addr().expect("address");
        let upstream_task: JoinHandle<()> = tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app)
                .await
                .expect("upstream");
        });
        let url = format!("http://{upstream_addr}/anthropic/v1/messages");
        let state = BedrockMantleState::for_test(&url, "Bearer configured-only");
        let mut request = request("/v1/messages", VALID_BODY);
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_static("Bearer buyer-secret"),
        );
        request
            .headers_mut()
            .insert("x-private", HeaderValue::from_static("must-not-forward"));
        let response = handle_request(State(AppState(state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let raw = to_bytes(response.into_body(), MAX_RESPONSE_BODY)
            .await
            .expect("response body");
        assert!(std::str::from_utf8(&raw)
            .expect("utf8")
            .contains("\"model\":\"claude-opus-4-8\""));
        let (headers, sent) = received
            .lock()
            .expect("capture")
            .take()
            .expect("upstream request");
        let value: Value = serde_json::from_slice(&sent).expect("sent json");
        assert_eq!(value["model"], BEDROCK_SYSTEM_MODEL);
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer configured-only")
        );
        assert_eq!(
            headers
                .get("anthropic-version")
                .and_then(|value| value.to_str().ok()),
            Some(ANTHROPIC_VERSION)
        );
        assert!(headers.get("x-private").is_none());
        assert!(headers.get(EXECUTION_POLICY_HEADER).is_none());
        upstream_task.abort();
    }

    fn request(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(EXECUTION_POLICY_HEADER, EXACT_CANONICAL_NO_REPLAY_POLICY)
            .body(Body::from(body.to_owned()))
            .expect("request")
    }

    async fn test_state() -> (
        BedrockMantleState,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = count.clone();
        let upstream_app = Router::new().route(
            "/anthropic/v1/messages",
            post(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"model":"claude-opus-4-8"}"#,
                    )
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, upstream_app).await.expect("upstream");
        });
        let state = BedrockMantleState::for_test(
            &format!("http://{address}/anthropic/v1/messages"),
            "Bearer configured-only",
        );
        (state, count)
    }
}
