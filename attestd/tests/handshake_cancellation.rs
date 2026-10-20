#![expect(clippy::unwrap_used, reason = "local test fixtures")]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gm_miner_attestd::upstream_proxy;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn pending_handshake() -> (
    tokio::task::JoinHandle<anyhow::Result<upstream_proxy::UpstreamConnection>>,
    tokio::net::TcpStream,
    Logs,
    tracing::dispatcher::DefaultGuard,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = TlsConnector::from(Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let client = tokio::spawn(async move {
        upstream_proxy::connect(&tls, "TestUpstream", "upstream.test", Some(address), 0).await
    });
    let (mut tcp, _) = listener.accept().await.unwrap();
    let mut header = [0; 5];
    tcp.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 22, "expected a TLS handshake record");
    let mut record = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    tcp.read_exact(&mut record).await.unwrap();
    assert_eq!(record[0], 1, "expected ClientHello");
    (client, tcp, logs, guard)
}

#[tokio::test]
async fn cancelling_pending_tls_logs_the_stage_and_closes_the_socket() {
    let (client, mut tcp, logs, _guard) = pending_handshake().await;
    client.abort();
    assert!(client.await.err().unwrap().is_cancelled());
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("upstream TLS handshake cancelled"),
        "{output}"
    );
    assert!(output.contains("provider=\"TestUpstream\""), "{output}");
    assert!(output.contains("peer=127.0.0.1:"), "{output}");
    assert!(output.contains("elapsed_ms="), "{output}");
}

#[tokio::test]
async fn a_tls_error_is_not_reported_as_cancellation() {
    let (client, tcp, logs, _guard) = pending_handshake().await;
    drop(tcp);
    let result = client.await.unwrap();
    assert!(result.is_err());
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!output.contains("handshake cancelled"), "{output}");
}

#[tokio::test]
async fn a_tls_timeout_is_not_reported_as_cancellation() {
    let (client, _tcp, logs, _guard) = pending_handshake().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    let result = client.await.unwrap();
    let error = result.err().unwrap();
    assert!(format!("{error:#}").contains("TestUpstream TLS handshake timed out"));
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!output.contains("handshake cancelled"), "{output}");
}
