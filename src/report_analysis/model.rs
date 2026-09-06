use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const NORMALIZED_SCHEMA_VERSION: &str = "1.0";
pub const VERDICT_SCHEMA_VERSION: &str = "1.0";
pub const IOC_SCHEMA_VERSION: &str = "1.0";

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
pub struct IocReport {
    pub schema_version: String,
    pub run_id: String,
    pub normalized_input_sha256: String,
    pub counts_by_type: BTreeMap<String, usize>,
    pub indicators: Vec<IocRecord>,
    pub extraction_warnings: Vec<ValidationWarning>,
}
