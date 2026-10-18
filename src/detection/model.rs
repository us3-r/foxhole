use super::{DetectionConfig, Limits};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Completed,
    Partial,
    TimedOut,
    Unavailable,
    Failed,
    InvalidOutput,
    Disabled,
    Skipped,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Warning {
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackIdentity {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub trusted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginalResult {
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScannerResult {
    pub schema_version: u32,
    pub scanner: String,
    pub version: String,
    pub status: Status,
    /// "primary" or an exact artifact-manifest relative path, resolved by the host.
    pub target: String,
    pub target_sha256: String,
    #[serde(default)]
    pub started_at_ms: Option<u64>,
    #[serde(default)]
    pub completed_at_ms: Option<u64>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    pub rule_packs: Vec<PackIdentity>,
    pub limits: Limits,
    pub truncated: bool,
    pub warnings: Vec<Warning>,
    pub evidence_ids: Vec<String>,
    pub original: Option<OriginalResult>,
    pub findings: Vec<ScannerFinding>,
    pub strings: Vec<ExtractedString>,
    pub pe: Option<PeMetadata>,
    pub packets: Vec<PacketObservation>,
}
impl ScannerResult {
    pub fn empty(
        scanner: &str,
        target: &str,
        hash: &str,
        status: Status,
        limits: Limits,
        code: &str,
    ) -> Self {
        Self {
            schema_version: 1,
            scanner: scanner.into(),
            version: match scanner {
                "yara" => super::YARA_VERSION,
                "capa" => super::CAPA_VERSION,
                "pe" => super::PE_VERSION,
                "network" => super::PACKET_VERSION,
                _ => "1",
            }
            .into(),
            status,
            target: target.into(),
            target_sha256: hash.into(),
            started_at_ms: None,
            completed_at_ms: None,
            duration_ms: None,
            rule_packs: vec![],
            limits,
            truncated: false,
            warnings: vec![Warning {
                code: code.into(),
                message: code.replace('_', " "),
            }],
            evidence_ids: vec![],
            original: None,
            findings: vec![],
            strings: vec![],
            pe: None,
            packets: vec![],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct MatchLocation {
    pub kind: String,
    pub offset: u64,
    pub length: u64,
    /// Hex only; never raw matched binary data.
    pub excerpt_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScannerFinding {
    pub id: String,
    pub rule: String,
    pub namespace: String,
    pub title: String,
    pub tags: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub maec: BTreeMap<String, String>,
    pub scope: String,
    pub locations: Vec<MatchLocation>,
    pub features: Vec<String>,
    pub rule_pack: String,
    pub evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExtractedString {
    pub value: String,
    pub method: String,
    pub offset: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Section {
    pub name: String,
    pub raw_size: u64,
    pub virtual_size: u64,
    pub offset: u64,
    pub entropy: f64,
    pub permissions: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PeMetadata {
    pub architecture: String,
    pub subsystem: u16,
    pub entry_point: u64,
    pub image_base: u64,
    pub compile_timestamp_untrusted: u32,
    pub sections: Vec<Section>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub resources: Vec<String>,
    pub debug: Vec<String>,
    pub overlay_size: u64,
    pub authenticode_status: String,
    pub certificates: Vec<BTreeMap<String, String>>,
    pub imphash: Option<String>,
    pub authentihash: Option<String>,
    pub fuzzy_hash: Option<String>,
    pub packer_compiler: Vec<String>,
    pub tls_callbacks: Vec<u64>,
    pub embedded_pe_offsets: Vec<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PacketObservation {
    pub id: String,
    pub packet: u64,
    pub timestamp_us: Option<u64>,
    pub flow: String,
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: String,
    pub direction: String,
    pub bytes: u64,
    pub dns_query: Option<String>,
    pub dns_answers: Vec<String>,
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_path: Option<String>,
    pub user_agent: Option<String>,
    pub tls_sni: Option<String>,
    pub tls: BTreeMap<String, String>,
    pub evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DetectionReport {
    #[serde(default)]
    pub packet_correlations: Vec<PacketCorrelation>,
    #[serde(default)]
    pub network_flows: Vec<NetworkFlow>,
    #[serde(default)]
    pub coverage: BTreeMap<String, Status>,
    pub schema_version: u32,
    pub effective_config: DetectionConfig,
    pub stages: Vec<ScannerResult>,
    pub behavioral_status: Status,
    pub warnings: Vec<Warning>,
}
impl Default for DetectionReport {
    fn default() -> Self {
        Self {
            packet_correlations: vec![],
            network_flows: vec![],
            coverage: BTreeMap::new(),
            schema_version: 1,
            effective_config: DetectionConfig::default().public(),
            stages: vec![],
            behavioral_status: Status::Unavailable,
            warnings: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PacketCorrelation {
    pub capture_sha256: String,
    pub packet_id: String,
    pub flow: String,
    pub pid: u32,
    pub method: String,
    pub confidence: u8,
    pub evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlow {
    pub capture_sha256: String,
    pub flow: String,
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: String,
    pub first_timestamp_us: Option<u64>,
    pub last_timestamp_us: Option<u64>,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub evidence_ids: Vec<String>,
}
