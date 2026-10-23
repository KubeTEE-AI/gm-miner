use std::io::ErrorKind;

use reqwest::StatusCode;

use crate::arm::AzureHttpStatusError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerificationFailureKind {
    Transient,
    Definitive,
}

pub(crate) fn classify_verification_error(error: &anyhow::Error) -> VerificationFailureKind {
    for cause in error.chain() {
        if let Some(status_error) = cause.downcast_ref::<AzureHttpStatusError>() {
            return if status_is_transient(status_error.status) {
                VerificationFailureKind::Transient
            } else {
                VerificationFailureKind::Definitive
            };
        }
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            if reqwest_error.is_timeout()
                || reqwest_error.is_connect()
                || reqwest_error.is_decode()
                || reqwest_error.status().is_some_and(status_is_transient)
                || is_dropped_connection(reqwest_error)
            {
                return VerificationFailureKind::Transient;
            }
        }
    }
    VerificationFailureKind::Definitive
}

/// The peer reset, aborted or closed the connection before the response was
/// complete: a pooled keep-alive connection the far end had already dropped,
/// or one cut mid-response. Nothing was verified either way, so it is retried
/// like a timeout.
fn is_dropped_connection(error: &reqwest::Error) -> bool {
    std::iter::successors(std::error::Error::source(error), |cause| cause.source())
        .any(cause_is_dropped_connection)
}

fn cause_is_dropped_connection(cause: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
        return matches!(
            io_error.kind(),
            ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
        );
    }
    cause
        .downcast_ref::<hyper::Error>()
        .is_some_and(hyper::Error::is_incomplete_message)
}

pub(crate) fn status_is_transient(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::REQUEST_TIMEOUT
        )
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on a broken local test server"
)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::arm::{AzureHttpStatusError, AzureVerifier};
    use crate::config::{AzureProvider, AzureVerifyConfig};

    /// What the one-shot server does once it has read the request head.
    #[derive(Clone, Copy)]
    enum Peer {
        ResetBeforeResponse,
        ResetMidBody,
        CloseBeforeResponse,
        CloseMidBody,
        Forbidden,
    }

    const PARTIAL_BODY_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
        content-type: application/json\r\ncontent-length: 4096\r\n\r\n{\"access_token\":";

    const FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 13\r\n\r\naccess denied";

    async fn read_request_head(stream: &mut TcpStream) {
        let mut head = Vec::new();
        let mut buf = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buf).await.expect("read request");
            assert!(read > 0, "client closed before sending a request head");
            head.extend_from_slice(&buf[..read]);
        }
    }

    /// Serve exactly one connection, behaving as `peer` after the request head.
    async fn serve_once(peer: Peer) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            read_request_head(&mut stream).await;
            let (response, reset): (&[u8], bool) = match peer {
                Peer::ResetBeforeResponse => (b"", true),
                Peer::ResetMidBody => (PARTIAL_BODY_HEAD, true),
                Peer::CloseBeforeResponse => (b"", false),
                Peer::CloseMidBody => (PARTIAL_BODY_HEAD, false),
                Peer::Forbidden => (FORBIDDEN, false),
            };
            stream.write_all(response).await.expect("write response");
            stream.flush().await.expect("flush response");
            if reset {
                stream.set_zero_linger().expect("SO_LINGER 0");
            }
            drop(stream);
        });
        format!("http://{address}")
    }

    async fn entra_token_error(peer: Peer) -> anyhow::Error {
        let base = serve_once(peer).await;
        token_error(reqwest::Client::new(), &base).await
    }

    async fn token_error(client: reqwest::Client, base: &str) -> anyhow::Error {
        let verifier = AzureVerifier::with_endpoints(client, base, base);
        let config = AzureVerifyConfig {
            provider: AzureProvider::Foundry,
            endpoint: "https://acct.services.ai.azure.com".to_owned(),
            tenant_id: "tenant".to_owned(),
            subscription_id: "subscription".to_owned(),
            resource_group: "resource-group".to_owned(),
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
        };
        verifier
            .fetch_entra_token(&config)
            .await
            .expect_err("the token endpoint never yields a token")
    }

    async fn wiremock_token_error(
        client: reqwest::Client,
        response: wiremock::ResponseTemplate,
    ) -> anyhow::Error {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(response)
            .mount(&server)
            .await;
        token_error(client, &server.uri()).await
    }

    async fn assert_transient(peer: Peer) {
        let error = entra_token_error(peer).await;
        assert_eq!(
            classify_verification_error(&error),
            VerificationFailureKind::Transient,
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_connection_reset_before_the_response_is_transient() {
        assert_transient(Peer::ResetBeforeResponse).await;
    }

    #[tokio::test]
    async fn a_connection_reset_mid_body_is_transient() {
        assert_transient(Peer::ResetMidBody).await;
    }

    #[tokio::test]
    async fn a_connection_closed_before_the_response_is_transient() {
        assert_transient(Peer::CloseBeforeResponse).await;
    }

    #[tokio::test]
    async fn a_connection_closed_mid_body_is_transient() {
        assert_transient(Peer::CloseMidBody).await;
    }

    #[test]
    fn only_a_dropped_connection_io_error_counts() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(
                cause_is_dropped_connection(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData,
            ErrorKind::Other,
        ] {
            assert!(
                !cause_is_dropped_connection(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_refused_connection_is_transient() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local addr");
        drop(listener);
        let error = token_error(reqwest::Client::new(), &format!("http://{address}")).await;
        assert_eq!(
            classify_verification_error(&error),
            VerificationFailureKind::Transient,
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_timed_out_request_is_transient() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .expect("client");
        let slow =
            wiremock::ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5));
        let error = wiremock_token_error(client, slow).await;
        assert_eq!(
            classify_verification_error(&error),
            VerificationFailureKind::Transient,
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn an_undecodable_body_is_transient() {
        let garbled = wiremock::ResponseTemplate::new(200).set_body_string("not json");
        let error = wiremock_token_error(reqwest::Client::new(), garbled).await;
        assert_eq!(
            classify_verification_error(&error),
            VerificationFailureKind::Transient,
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_redirect_loop_is_definitive() {
        let looping = wiremock::ResponseTemplate::new(302)
            .insert_header("location", "/tenant/oauth2/v2.0/token");
        let error = wiremock_token_error(reqwest::Client::new(), looping).await;
        assert!(
            error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<reqwest::Error>())
                .any(reqwest::Error::is_redirect),
            "{error:#}"
        );
        assert_eq!(
            classify_verification_error(&error),
            VerificationFailureKind::Definitive,
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_forbidden_response_over_the_wire_is_definitive() {
        let error = entra_token_error(Peer::Forbidden).await;
        assert_eq!(
            classify_verification_error(&error),
            VerificationFailureKind::Definitive,
            "{error:#}"
        );
    }

    #[test]
    fn verification_error_classification_separates_transient_from_definitive() {
        let transient = anyhow::Error::new(AzureHttpStatusError {
            label: "Azure Cognitive Services account",
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: "temporary outage".to_owned(),
        });
        assert_eq!(
            classify_verification_error(&transient),
            VerificationFailureKind::Transient
        );

        for status in [StatusCode::TOO_MANY_REQUESTS, StatusCode::REQUEST_TIMEOUT] {
            let transient_status = anyhow::Error::new(AzureHttpStatusError {
                label: "Azure Cognitive Services account",
                status,
                body: "throttled".to_owned(),
            });
            assert_eq!(
                classify_verification_error(&transient_status),
                VerificationFailureKind::Transient
            );
        }

        let definitive_status = anyhow::Error::new(AzureHttpStatusError {
            label: "Azure Cognitive Services account",
            status: StatusCode::FORBIDDEN,
            body: "access denied".to_owned(),
        });
        assert_eq!(
            classify_verification_error(&definitive_status),
            VerificationFailureKind::Definitive
        );

        let definitive_policy =
            anyhow::anyhow!("Azure account properties.raiMonitorConfig must be null or absent");
        assert_eq!(
            classify_verification_error(&definitive_policy),
            VerificationFailureKind::Definitive
        );
    }
}
