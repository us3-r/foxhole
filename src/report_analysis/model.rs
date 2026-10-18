use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const NORMALIZED_SCHEMA_VERSION: &str = "1.0";
pub const VERDICT_SCHEMA_VERSION: &str = "1.0";
pub const IOC_SCHEMA_VERSION: &str = "1.0";
pub const VIRUSTOTAL_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawEventCounts {
    pub process: usize,
    pub network: usize,
    pub filesystem: usize,
    pub registry: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ValidationWarning {
    pub code: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_index: Option<usize>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NormalizedRun {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capture_health: Vec<crate::structs::CaptureHealth>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_attempts: Vec<Value>,
    #[serde(default)]
    pub detection: crate::detection::DetectionReport,
    pub schema_version: String,
    pub run_id: String,
    pub target: Value,
    pub target_hashes: Vec<HashIndicator>,
    pub sandbox: Value,
    pub execution: Value,
    pub coverage: Value,
    pub limitations: Vec<String>,
    pub raw_event_counts: RawEventCounts,
    pub normalized_event_counts: RawEventCounts,
    pub processes: Vec<Process>,
    pub file_events: Vec<FileEvent>,
    pub registry_events: Vec<RegistryEvent>,
    pub network_events: Vec<NetworkEvent>,
    pub artifacts: Vec<Artifact>,
    pub validation_warnings: Vec<ValidationWarning>,
    pub source_paths: Vec<String>,
    pub raw: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashIndicator {
    pub algorithm: String,
    pub value: String,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Process {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image: String,
    pub command_line: Option<String>,
    pub status: String,
    pub observed_at_ms: u64,
    pub observations: Vec<ProcessObservation>,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProcessObservation {
    pub evidence_id: String,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image: String,
    pub command_line: Option<String>,
    pub status: String,
    pub observed_at_ms: u64,
    pub source: String,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessAssociation {
    pub pid: u32,
    pub image: String,
    pub parent_pid: Option<u32>,
    pub inferred: bool,
    pub method: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FileEvent {
    pub evidence_id: String,
    pub pid: u32,
    pub path: String,
    pub action: String,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub hash_source: Option<String>,
    pub observed_at_ms: u64,
    pub source: String,
    pub association: ProcessAssociation,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RegistryEvent {
    pub evidence_id: String,
    pub pid: u32,
    pub key: String,
    pub operation: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub observed_at_ms: u64,
    pub source: String,
    pub association: ProcessAssociation,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NetworkEvent {
    pub evidence_id: String,
    pub pid: u32,
    pub protocol: String,
    pub direction: String,
    pub local_address: String,
    pub local_port: Option<u16>,
    pub remote_address: String,
    pub remote_port: Option<u16>,
    pub domain: Option<String>,
    pub state: String,
    pub observed_at_ms: u64,
    pub source: String,
    pub association: ProcessAssociation,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Artifact {
    pub evidence_id: String,
    pub relative_path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub exists: bool,
    pub hash_verified: bool,
    pub source: String,
    pub raw: Value,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Suspicious,
    Malicious,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EvidenceReference {
    pub evidence_id: String,
    pub kind: String,
    pub pid: u32,
    pub process_image: String,
    pub parent_pid: Option<u32>,
    pub observed_at_ms: u64,
    pub source_artifact: String,
    pub exact_value: String,
    pub inferred: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<FindingDetails>,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<EvidenceReference>,
    pub confidence: f64,
    pub score_contribution: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TimelineEvent {
    pub observed_at_ms: u64,
    pub kind: String,
    pub evidence_id: String,
    pub pid: u32,
    pub process_image: String,
    pub parent_pid: Option<u32>,
    pub source_artifact: String,
    pub exact_value: String,
    pub inferred: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerdictReport {
    pub schema_version: String,
    pub run_id: String,
    pub normalized_input_sha256: String,
    pub verdict: String,
    pub score: u32,
    pub confidence: f64,
    pub scoring_model: BTreeMap<String, Value>,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub warnings: Vec<ValidationWarning>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct IocSource {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub artifact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IocRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<IocDetails>,
    #[serde(rename = "type")]
    pub ioc_type: String,
    pub value: String,
    pub normalized_value: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub contextual: bool,
    pub likely_benign: bool,
    pub sources: Vec<IocSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FindingDetails {
    pub version: String,
    pub source: String,
    pub namespace: String,
    pub file_sha256: Option<String>,
    pub attack: Vec<String>,
    pub required_events: Vec<String>,
    pub window_ms: Option<u64>,
    pub association: String,
    pub false_positive_guidance: String,
    pub score_group: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IocDetails {
    pub confidence: u8,
    pub source_categories: Vec<String>,
    pub file_sha256: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub extraction_methods: Vec<String>,
    pub validation_status: String,
    pub related_findings: Vec<String>,
    pub relationships: Vec<String>,
    pub offsets: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IocReport {
    pub schema_version: String,
    pub run_id: String,
    pub normalized_input_sha256: String,
    pub counts_by_type: BTreeMap<String, usize>,
    pub indicators: Vec<IocRecord>,
    pub extraction_warnings: Vec<ValidationWarning>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirusTotalStats {
    pub malicious: u64,
    pub suspicious: u64,
    pub harmless: u64,
    pub undetected: u64,
    pub timeout: u64,
    pub failure: u64,
    pub type_unsupported: u64,
    pub confirmed_timeout: u64,
}

impl VirusTotalStats {
    pub fn total(&self) -> u64 {
        self.malicious
            + self.suspicious
            + self.harmless
            + self.undetected
            + self.timeout
            + self.failure
            + self.type_unsupported
            + self.confirmed_timeout
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirusTotalEngineResult {
    pub engine_name: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_update: Option<String>,
    pub trusted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirusTotalFileReport {
    pub role: String,
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub status: String,
    pub permalink: String,
    pub discussion_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meaningful_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<u64>,
    pub stats: VirusTotalStats,
    pub engines: Vec<VirusTotalEngineResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirusTotalReport {
    pub schema_version: String,
    pub run_id: String,
    pub status: String,
    pub files: Vec<VirusTotalFileReport>,
    pub warnings: Vec<String>,
}
