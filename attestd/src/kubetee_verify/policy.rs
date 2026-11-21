//! AMD platform verification, separate from `KubeTEE` workload authorization.
//!
//! AMD ARK authenticates ASK; ASK authenticates VCEK; VCEK authenticates the
//! report. KDS also binds chip generation + measured TCB to the VCEK's custom
//! extensions. Valid hardware evidence never bypasses workload policy.

use std::fmt::{Display, Formatter};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use asn1_rs::FromDer as _;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client,
};
use sev::certs::snp::{
    builtin::{genoa, milan, turin},
    ca, Certificate, Verifiable,
};
use sev::firmware::guest::AttestationReport;
use url::Url;

const HWID_OID: &str = "1.3.6.1.4.1.3704.1.4";
const MICROCODE_OID: &str = "1.3.6.1.4.1.3704.1.3.8";
const SNP_OID: &str = "1.3.6.1.4.1.3704.1.3.3";
const TEE_OID: &str = "1.3.6.1.4.1.3704.1.3.2";
const BOOTLOADER_OID: &str = "1.3.6.1.4.1.3704.1.3.1";
const FMC_OID: &str = "1.3.6.1.4.1.3704.1.3.9";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Generation {
    Milan,
    Genoa,
    Turin,
}
impl Generation {
    fn name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }
    fn has_fmc(self) -> bool {
        matches!(self, Self::Turin)
    }
    pub(crate) fn of(report: &AttestationReport) -> Result<Self> {
        let family = report.cpuid_fam_id.with_context(|| {
            format!(
                "SNP report v{} lacks its CPU family; CoCo requires v3+",
                report.version
            )
        })?;
        let model = report.cpuid_mod_id.context("SNP report has no CPU model")?;
        match (family, model) {
            (0x19, 0x00..=0x0f) => Ok(Self::Milan),
            (0x19, 0x10..=0x1f | 0xa0..=0xaf) => Ok(Self::Genoa),
            (0x1a, 0x00..=0x11) => Ok(Self::Turin),
            _ => bail!("unsupported AMD family={family:#x} model={model:#x}"),
        }
    }
    fn root(self) -> Result<Certificate> {
        Certificate::from_pem(match self {
            Self::Milan => milan::ARK,
            Self::Genoa => genoa::ARK,
            Self::Turin => turin::ARK,
        })
        .map_err(|error| anyhow::Error::from(error).context("decode built-in AMD root"))
    }
    fn ask(self) -> Result<Certificate> {
        Certificate::from_pem(match self {
            Self::Milan => milan::ASK,
            Self::Genoa => genoa::ASK,
            Self::Turin => turin::ASK,
        })
        .map_err(|error| anyhow::Error::from(error).context("decode built-in AMD intermediate"))
    }
}
impl Display for Generation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub(crate) trait AmdEndpoint: Send + Sync {
    fn fetch(&self, url: Url) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}
pub(crate) struct Kds;
impl AmdEndpoint for Kds {
    async fn fetch(&self, url: Url) -> Result<Vec<u8>> {
        ensure!(
            url.scheme() == "https" && url.host_str() == Some("kdsintf.amd.com"),
            "unrecognized AMD KDS URL"
        );
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()?;
        let mut headers = HeaderMap::new();
        // gm CLI's optional API-proxy forwards public AMD collateral via this
        // metadata header without changing the inference/TEE boundary.
        headers.insert("x-gm-proxy-fetch", HeaderValue::from_str(url.as_str())?);
        let response = client
            .get(url.clone())
            .headers(headers)
            .send()
            .await
            .with_context(|| format!("AMD KDS {url}"))?;
        let status = response.status();
        let bytes = response.bytes().await.context("read AMD KDS response")?;
        ensure!(status.is_success(), "AMD KDS {url} returned {status}");
        ensure!(
            !bytes.is_empty() && bytes.len() <= 1 << 20,
            "AMD KDS returned an unreasonable response"
        );
        Ok(bytes.to_vec())
    }
}

fn der(certificate: &Certificate) -> Result<Vec<u8>> {
    certificate
        .to_der()
        .map_err(|error| anyhow::Error::from(error).context("encode AMD certificate"))
}
pub(crate) fn subject(certificate: &Certificate) -> Result<String> {
    let der = der(certificate)?;
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&der).context("parse AMD certificate")?;
    let names: Vec<String> = certificate
        .subject()
        .iter_common_name()
        .map(|name| name.as_str().map(ToOwned::to_owned))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(names.len() == 1, "AMD VEK needs a unique subject CN");
    names.into_iter().next().context("missing AMD VEK subject")
}
fn extension<'a>(
    certificate: &'a x509_parser::certificate::X509Certificate<'a>,
    name: &str,
) -> Result<&'a [u8]> {
    let oid = name.parse::<asn1_rs::Oid>()?;
    Ok(certificate
        .get_extension_unique(&oid)?
        .with_context(|| format!("missing AMD extension {name}"))?
        .value)
}
fn octets<const N: usize>(certificate: &Certificate) -> Result<[u8; N]> {
    let der = der(certificate)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der).context("parse AMD VCEK")?;
    let value = extension(&certificate, HWID_OID)?;
    // CoCo accepts both the current DER OCTET STRING and legacy raw hwID.
    if value.len() == N {
        return value
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid AMD chip-ID extension"));
    }
    let (_, integer) =
        asn1_rs::OctetString::from_der(value).map_err(|error| anyhow::anyhow!("{error}"))?;
    integer
        .as_ref()
        .try_into()
        .context("invalid AMD chip-ID extension")
}
fn integer(certificate: &Certificate, name: &str) -> Result<u8> {
    let der = der(certificate)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der).context("parse AMD VCEK")?;
    let (_, integer) = asn1_rs::Integer::from_der(extension(&certificate, name)?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    integer.as_u8().map_err(Into::into)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VekKind {
    Vcek,
    Vlek,
}
pub(crate) fn vek_kind(vek: &Certificate) -> Result<VekKind> {
    match subject(vek)?.as_str() {
        "VCEK" | "SEV-VCEK" => Ok(VekKind::Vcek),
        "VLEK" | "SEV-VLEK" => Ok(VekKind::Vlek),
        other => bail!("unexpected AMD VEK subject {other}"),
    }
}

/// Use `CoCo`'s standard certificate-table extraction, then pin the root rather
/// than accepting a CA certificate chosen by the endpoint. Missing tables use
/// the independently fetched KDS key. VEK validity is checked in `verify_vek`.
pub(crate) fn chain_from_table(
    entries: &[sev::firmware::host::CertTableEntry],
) -> Result<Option<Certificate>> {
    if entries.is_empty() {
        return Ok(None);
    }
    let certificate = entries
        .iter()
        .find(|e| {
            matches!(
                e.cert_type,
                sev::firmware::host::CertType::VCEK | sev::firmware::host::CertType::VLEK
            )
        })
        .map(|e| Certificate::from_der(&e.data))
        .transpose()
        .map_err(|error| anyhow::Error::from(error).context("decode SNP endorsement key"))?;
    Ok(certificate)
}

pub(crate) async fn verify_vek(
    report: &AttestationReport,
    endpoint: &impl AmdEndpoint,
) -> Result<Certificate> {
    let generation = Generation::of(report)?;
    let chip_id = if generation.has_fmc() {
        hex::encode(&report.chip_id[..8])
    } else {
        hex::encode(report.chip_id)
    };
    let tcb = &report.reported_tcb;
    let mut url = Url::parse(&format!(
        "https://kdsintf.amd.com/vcek/v1/{generation}/{chip_id}"
    ))?;
    url.query_pairs_mut()
        .append_pair("blSPL", &tcb.bootloader.to_string())
        .append_pair("teeSPL", &tcb.tee.to_string())
        .append_pair("snpSPL", &tcb.snp.to_string())
        .append_pair("ucodeSPL", &tcb.microcode.to_string());
    if generation.has_fmc() {
        url.query_pairs_mut().append_pair(
            "fmcSPL",
            &tcb.fmc.context("Turin report is missing FMC")?.to_string(),
        );
    }
    let der = endpoint.fetch(url).await?;
    let vek = Certificate::from_der(&der)
        .map_err(anyhow::Error::from)
        .context("parse AMD KDS VCEK")?;
    ensure!(
        matches!(subject(&vek)?.as_str(), "SEV-VCEK" | "VCEK"),
        "unexpected AMD KDS endorsement key subject"
    );
    ensure!(
        octets::<64>(&vek)? == report.chip_id,
        "VCEK chip ID does not match the report"
    );
    ensure!(
        integer(&vek, MICROCODE_OID)? == tcb.microcode,
        "VCEK microcode is not the report's measured TCB"
    );
    ensure!(
        integer(&vek, SNP_OID)? == tcb.snp,
        "VCEK SNP firmware is not the report's measured TCB"
    );
    ensure!(
        integer(&vek, TEE_OID)? == tcb.tee,
        "VCEK TEE is not the report's measured TCB"
    );
    ensure!(
        integer(&vek, BOOTLOADER_OID)? == tcb.bootloader,
        "VCEK boot loader is not the report's measured TCB"
    );
    if generation.has_fmc() {
        ensure!(
            integer(&vek, FMC_OID)? == tcb.fmc.context("Turin report is missing FMC")?,
            "VCEK FMC is not the report's measured TCB"
        );
    }
    let ca = ca::Chain {
        ark: generation.root()?,
        ask: generation.ask()?,
    };
    (&ca).verify().context("AMD ARK/ASK chain is invalid")?;
    sev::certs::snp::Chain {
        ca,
        vek: vek.clone(),
    }
    .verify()
    .context("AMD ARK/ASK/VCEK chain is invalid")?;
    (&vek, report)
        .verify()
        .context("SEV-SNP report signature is invalid")?;
    Ok(vek)
}

/// Exact release tuples measured in the candidate guest. Updated only after
/// genuine candidate appraisal, never from host-written JSON claims alone.
/// Pre-release the registry is empty and every SNP payload therefore fails.
static RELEASES: &[Release] = &[];
struct Release {
    measurement: [u8; 48],
    host_data: [u8; 32],
    microcode: u8,
    bootloader: u8,
    snp: u8,
}
pub(crate) fn accept(report: &AttestationReport) -> Result<()> {
    ensure!(report.vmpl == 0, "SNP report VMPL is not zero");
    ensure!(!report.policy.debug_allowed(), "SNP guest permits debug");
    ensure!(
        !report.policy.migrate_ma_allowed(),
        "SNP guest permits migration"
    );
    ensure!(RELEASES.iter().any(|release| release.measurement == report.measurement && release.host_data == report.host_data && report.reported_tcb.microcode >= release.microcode && report.reported_tcb.bootloader >= release.bootloader && report.reported_tcb.snp >= release.snp), "SNP guest measurements are outside the explicit KubeTEE release policy (live candidate appraisal pending)");
    Ok(())
}
