//! Parse the gateway's native `CoCo` AMD evidence and verify its trust chain.
//! Intel DCAP parsing remains an entirely separate verifier arm.

use anyhow::{ensure, Context, Result};
use base64::Engine as _;
use serde_json::Value;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertTableEntry;
use sev::parser::ByteParser as _;

use super::policy::{self, AmdEndpoint, Kds};

/// The four supported wire states reduce to two standard `CoCo` objects:
/// a report-encoded hex/base64 string, or a `CoCo` structured report. The
/// gateway uses the latter; neither is ever a byte offset in an Intel quote.
pub(crate) fn report(evidence: &Value) -> Result<AttestationReport> {
    let report = evidence.get("attestation_report").unwrap_or(evidence);
    if let Some(report) = report.as_object() {
        if let Some(encoded) = report.get("attestation_report").and_then(Value::as_str) {
            let mut bytes = encoded.as_bytes();
            if bytes.starts_with(b"0x") {
                bytes = &bytes[2..];
            }
            let report = if encoded.len() == 2368 || encoded.starts_with("0x") {
                hex::decode(bytes).context("decode SNP report hex")?
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(bytes)
                    .context("decode SNP report base64")?
            };
            return AttestationReport::from_bytes(&report)
                .map_err(|error| anyhow::Error::from(error).context("decode raw SNP report"));
        }
        return serde_json::from_value(Value::Object(report.clone()))
            .context("decode structured CoCo SNP report");
    }
    let raw = report
        .as_str()
        .context("SNP attestation_report must be CoCo structured JSON or raw hex/base64")?;
    let hex_string = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = if hex_string.len() == 2368 {
        hex::decode(hex_string).context("decode SNP report hex")?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(raw)
            .context("decode SNP report base64")?
    };
    AttestationReport::from_bytes(&bytes)
        .map_err(|error| anyhow::Error::from(error).context("decode raw SNP report"))
}

fn certificates(evidence: &Value) -> Result<Vec<CertTableEntry>> {
    match evidence.get("cert_chain") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(certificates) => serde_json::from_value(certificates.clone())
            .context("parse native CoCo SNP certificate table"),
    }
}

async fn verify_with(
    endpoint: &impl AmdEndpoint,
    evidence: &Value,
    report_data: &[u8; 64],
) -> Result<AttestationReport> {
    let report = report(evidence)?;
    ensure!(
        report.report_data == *report_data,
        "SNP signed report_data is not the v1 nonce/keyset binding"
    );
    ensure!(
        (3..=5).contains(&report.version),
        "unsupported SNP report version {}",
        report.version
    );
    let supplied_chain = policy::chain_from_table(&certificates(evidence)?)?;
    let signed_by = supplied_chain
        .as_ref()
        .map(super::policy::vek_kind)
        .transpose()?;
    if let Some(super::policy::VekKind::Vlek) = signed_by {
        anyhow::bail!(
            "VLEK requires AMD hashstick validation and is not accepted by this consumer"
        );
    }
    let vek = policy::verify_vek(&report, endpoint).await?;
    if let Some(chain) = supplied_chain {
        // Treat the whole CoCo table as supplied *data*. CoCo verifies its
        // path; this comparison prevents it substituting an endorsement key.
        ensure!(
            chain.to_der().map_err(anyhow::Error::from)?
                == vek.to_der().map_err(anyhow::Error::from)?,
            "supplied AMD endorsement key differs from the KDS binding for this report"
        );
    }
    Ok(report)
}

pub(crate) async fn verify(evidence: &Value, report_data: &[u8; 64]) -> Result<AttestationReport> {
    verify_with(&Kds, evidence, report_data).await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::result_large_err,
        reason = "vendored hardware verifier's stable API uses std::io::Error"
    )]
    #![expect(
        clippy::unwrap_used,
        reason = "CoCo fixture tests deliberately reject malformed local fixtures"
    )]
    use super::*;
    use sev::certs::snp::{builtin::milan, Certificate, Verifiable};

    const REPORT: &[u8] = include_bytes!("../../tests/fixtures/kubetee/snp/test-report.bin");
    const VCEK: &[u8] = include_bytes!("../../tests/fixtures/kubetee/snp/test-vcek.der");

    fn evidence() -> Value {
        let report = AttestationReport::from_bytes(REPORT).unwrap();
        serde_json::json!({ "schema": "kubetee.snp-evidence/1", "attestation_report": report, "cert_chain": [{"cert_type":"VCEK","data":VCEK}] })
    }
    #[test]
    fn native_structured_report_and_certificate_table_round_trip() {
        let report = report(&evidence()).unwrap();
        assert_eq!(
            report.measurement,
            AttestationReport::from_bytes(REPORT).unwrap().measurement
        );
        let certs = policy::chain_from_table(&certificates(&evidence()).unwrap())
            .unwrap()
            .unwrap();
        let ca = sev::certs::snp::ca::Chain {
            ark: Certificate::from_pem(milan::ARK).unwrap(),
            ask: Certificate::from_pem(milan::ASK).unwrap(),
        };
        let vek = sev::certs::snp::Chain { ca, vek: certs };
        (&vek).verify().unwrap();
        (&vek.vek, &report).verify().unwrap();
        let mut tampered = report;
        tampered.measurement[0] ^= 1;
        assert!((&vek.vek, &tampered).verify().is_err());
    }
    #[test]
    fn a_v2_fixture_never_gets_accepted_as_current_snp_hardware_proof() {
        let error = runtime()
            .block_on(verify_with(
                &RejectAnyRequest,
                &evidence(),
                &AttestationReport::from_bytes(REPORT).unwrap().report_data,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported SNP report version 2"));
    }
    #[test]
    fn vlek_is_rejected_before_unsupported_hardware_lookup() {
        let raw = include_bytes!("../../tests/fixtures/kubetee/snp/test-vlek-report.bin");
        let raw_vcek = include_bytes!("../../tests/fixtures/kubetee/snp/test-vlek.der");
        let report = AttestationReport::from_bytes(raw).unwrap();
        let evidence = serde_json::json!({"attestation_report":report, "cert_chain":[{"cert_type":"VLEK", "data":raw_vcek.as_slice()}]});
        let error = runtime()
            .block_on(verify_with(
                &RejectAnyRequest,
                &evidence,
                &report.report_data,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("VLEK"), "{error:#}");
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
    }
    #[test]
    fn a_different_signed_statement_fails_before_kds_access() {
        let error = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(verify_with(&RejectAnyRequest, &evidence(), &[0; 64]))
            .unwrap_err();
        assert!(format!("{error:#}").contains("nonce/keyset"));
    }
    #[test]
    fn native_kds_response_verify_report_and_pin_requested_cpu_tcb() {
        struct PinCpuTcb;
        impl AmdEndpoint for PinCpuTcb {
            async fn fetch(&self, url: url::Url) -> Result<Vec<u8>> {
                let report = AttestationReport::from_bytes(REPORT).unwrap();
                let tcb = report.reported_tcb;
                assert_eq!(url.scheme(), "https");
                assert_eq!(url.host_str(), Some("kdsintf.amd.com"));
                assert_eq!(
                    url.path(),
                    format!("/vcek/v1/Milan/{}", hex::encode(report.chip_id))
                );
                let query: std::collections::HashMap<_, _> =
                    url.query_pairs().into_owned().collect();
                assert_eq!(query.len(), 4);
                assert_eq!(query["blSPL"], tcb.bootloader.to_string());
                assert_eq!(query["teeSPL"], tcb.tee.to_string());
                assert_eq!(query["snpSPL"], tcb.snp.to_string());
                assert_eq!(query["ucodeSPL"], tcb.microcode.to_string());
                Ok(VCEK.to_vec())
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let error = runtime
            .block_on(verify_with(
                &PinCpuTcb,
                &evidence(),
                &AttestationReport::from_bytes(REPORT).unwrap().report_data,
            ))
            .unwrap_err();
        // The KDS URL and certificate are verified before report-version policy.
        assert!(format!("{error:#}").contains("unsupported SNP report version 2"));
    }
    #[test]
    fn coco_v3_fixture_cryptographic_chain_result_is_tested_not_assumed() {
        let mut evidence: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/kubetee/coco-snp-evidence.json"
        ))
        .unwrap();
        if let Some(object) = evidence.as_object_mut() {
            object.insert(
                "schema".into(),
                Value::String("kubetee.snp-evidence/1".into()),
            );
        }
        let full = &evidence;
        let report = report(full).unwrap();
        assert_eq!(report.version, 3);
        assert_eq!(
            policy::Generation::of(&report).unwrap().to_string(),
            "Genoa"
        );
        let cert = policy::chain_from_table(&certificates(full).unwrap())
            .unwrap()
            .unwrap();
        let ca = sev::certs::snp::ca::Chain {
            ark: Certificate::from_pem(sev::certs::snp::builtin::genoa::ARK).unwrap(),
            ask: Certificate::from_pem(sev::certs::snp::builtin::genoa::ASK).unwrap(),
        };
        let report_result = (&cert, &report).verify();
        let chain = sev::certs::snp::Chain { ca, vek: cert };
        let chain_result = (&chain).verify();
        assert!(
            report_result.is_ok() && chain_result.is_ok(),
            "public CoCo fixture chain failed: {report_result:?} / {chain_result:?}"
        );
        assert!(
            policy::accept(&report).is_err(),
            "test evidence is not an approved release"
        );
    }
    #[test]
    fn snp_launch_digest_and_host_data_remain_distinct() {
        let report = AttestationReport::from_bytes(REPORT).unwrap();
        assert_eq!(report.measurement.len(), 48);
        assert_eq!(report.host_data.len(), 32);
    }
    #[test]
    fn a_malformed_legacy_recursive_encoding_is_not_guessed() {
        let malformed = serde_json::json!({ "attestation_report": {"to_python": {}} });
        assert!(report(&malformed).is_err());
    }
    struct RejectAnyRequest;
    impl AmdEndpoint for RejectAnyRequest {
        async fn fetch(&self, url: url::Url) -> Result<Vec<u8>> {
            anyhow::bail!("unexpected AMD request {url}")
        }
    }
}
