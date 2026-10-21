//! Fixed AWS Bedrock Mantle Messages adapter.

use std::process::ExitCode;

use anyhow::{Context, Result};
use gm_miner_attestd::bedrock_mantle::{serve, BEDROCK_MANTLE_BIND_ADDR};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "Bedrock Mantle adapter failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let state = gm_miner_attestd::bedrock_mantle::BedrockMantleState::from_environment()
        .map_err(anyhow::Error::msg)
        .context("validate fixed Bedrock Mantle configuration")?;
    let listener = TcpListener::bind(BEDROCK_MANTLE_BIND_ADDR)
        .await
        .context("bind Bedrock Mantle adapter")?;
    info!(
        bind_addr = BEDROCK_MANTLE_BIND_ADDR,
        "Bedrock Mantle adapter listening"
    );
    serve(listener, state)
        .await
        .map_err(anyhow::Error::msg)
        .context("serve Bedrock Mantle adapter")
}
