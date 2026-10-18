use serde::{Deserialize, Serialize};
use std::path::Path;

pub const YARA_VERSION: &str = "4.5.2";
pub const CAPA_VERSION: &str = "9.2.1";
pub const PE_VERSION: &str = "2024.8.26";
pub const PACKET_VERSION: &str = "foxhole-packet-1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub timeout_seconds: u64,
    pub memory_bytes: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub findings: usize,
    pub strings: usize,
    pub string_bytes: usize,
    pub match_bytes: usize,
    pub offsets: usize,
    pub features: usize,
    pub depth: usize,
    pub rules: usize,
    pub files: usize,
    pub packets: usize,
    pub flows: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_seconds: 60,
            memory_bytes: 512 * 1024 * 1024,
            input_bytes: 32 * 1024 * 1024,
            output_bytes: 4 * 1024 * 1024,
            findings: 512,
            strings: 2048,
            string_bytes: 2048,
            match_bytes: 64,
            offsets: 256,
            features: 256,
            depth: 16,
            rules: 10000,
            files: 32,
            packets: 100000,
            flows: 4096,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.output_bytes < 4096 {
            return Err(
                "scanner output budget must reserve 4096 bytes for bounded status metadata",
            );
        }
        let hard = Self {
            timeout_seconds: 300,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            input_bytes: 128 * 1024 * 1024,
            output_bytes: 16 * 1024 * 1024,
            findings: 4096,
            strings: 8192,
            string_bytes: 4096,
            match_bytes: 256,
            offsets: 1024,
            features: 1024,
            depth: 24,
            rules: 50000,
            files: 64,
            packets: 1000000,
            flows: 16384,
        };
        macro_rules! check { ($($field:ident),+) => { $(if self.$field == 0 || self.$field > hard.$field { return Err("analysis limit is zero or exceeds its hard ceiling"); })+ }; }
        check!(
            timeout_seconds,
            memory_bytes,
            input_bytes,
            output_bytes,
            findings,
            strings,
            string_bytes,
            match_bytes,
            offsets,
            features,
            depth,
            rules,
            files,
            packets,
            flows
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    pub id: String,
    pub version: String,
    /// Guest-local file (YARA source, capa ZIP, or packet-rule JSON).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ScannerConfig {
    pub enabled: bool,
    pub executable: Option<String>,
    pub executable_sha256: Option<String>,
    pub rules: Option<RulePack>,
    pub user_rules: Option<RulePack>,
    pub limits: Limits,
}
impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            executable: None,
            executable_sha256: None,
            rules: None,
            user_rules: None,
            limits: Limits::default(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    pub schema_version: u32,
    pub yara: ScannerConfig,
    pub pe: ScannerConfig,
    pub capa: ScannerConfig,
    pub network: ScannerConfig,
    pub behavioral: bool,
    pub total_timeout_seconds: u64,
    pub max_capture_bytes: u64,
    pub max_total_output_bytes: u64,
}
impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            yara: ScannerConfig::default(),
            pe: ScannerConfig::default(),
            capa: ScannerConfig::default(),
            network: ScannerConfig::default(),
            behavioral: true,
            total_timeout_seconds: 180,
            max_capture_bytes: 64 * 1024 * 1024,
            max_total_output_bytes: 16 * 1024 * 1024,
        }
    }
}
impl DetectionConfig {
    pub fn stages(&self) -> [(&str, &ScannerConfig); 4] {
        [
            ("yara", &self.yara),
            ("pe", &self.pe),
            ("capa", &self.capa),
            ("network", &self.network),
        ]
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("unsupported analysis configuration version");
        }
        if !(1..=900).contains(&self.total_timeout_seconds)
            || !(1..=128 * 1024 * 1024).contains(&self.max_capture_bytes)
            || !(16384..=32 * 1024 * 1024).contains(&self.max_total_output_bytes)
        {
            return Err("invalid total analysis budget");
        }
        for (_, stage) in self.stages() {
            stage.limits.validate()?;
            if stage
                .rules
                .as_ref()
                .zip(stage.user_rules.as_ref())
                .is_some_and(|(a, b)| a.id == b.id)
            {
                return Err("built-in and user rule packs must have distinct identifiers");
            }
            match (&stage.executable, &stage.executable_sha256) {
                (None, None) => (),
                (Some(path), Some(hash))
                    if absolute_scanner_path(path) && super::validation::sha256(hash) => {}
                _ => {
                    return Err(
                        "scanner requires an absolute guest path and pinned executable SHA-256",
                    );
                }
            }
            for pack in [&stage.rules, &stage.user_rules].into_iter().flatten() {
                if !absolute_scanner_path(&pack.path)
                    || !super::validation::sha256(&pack.sha256)
                    || !super::validation::identifier(&pack.id)
                    || !super::validation::identifier(&pack.version)
                {
                    return Err("invalid rule-pack identity, path or hash");
                }
            }
        }
        if self.pe.user_rules.is_some()
            || self.network.user_rules.is_some()
            || self.capa.user_rules.is_some()
        {
            return Err("user rule packs are supported only for YARA");
        }
        Ok(())
    }
    /// Executable and pack paths are deployment details, never exported.
    pub fn public(&self) -> Self {
        let mut result = self.clone();
        for stage in [
            &mut result.yara,
            &mut result.pe,
            &mut result.capa,
            &mut result.network,
        ] {
            stage.executable = None;
            for pack in [&mut stage.rules, &mut stage.user_rules]
                .into_iter()
                .flatten()
            {
                pack.path.clear();
            }
        }
        result
    }
}
fn absolute_scanner_path(value: &str) -> bool {
    value.len() <= 1024
        && !value.chars().any(char::is_control)
        && !value
            .split(['/', '\\'])
            .any(|part| part == ".." || part == ".")
        && !value.starts_with("\\\\")
        && (Path::new(value).is_absolute()
            || (value.as_bytes().get(1) == Some(&b':') && value.as_bytes().get(2) == Some(&b'\\')))
}
