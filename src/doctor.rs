//! Read-only deployment checks. Guest readiness still requires a live smoke test.
use clap::{Args, ValueEnum};
use serde::Serialize;
use std::{error::Error, io::Read, path::PathBuf};

#[derive(Clone, Debug, Args)]
pub struct DoctorArgs {
    /// Emit one JSON document on stdout (diagnostics go to stderr)
    #[arg(long)]
    pub json: bool,
    /// Execution image, or FOXHOLE_HYPERV_BASE_IMAGE
    #[arg(long, alias = "hyperv-base-image")]
    pub base_image: Option<PathBuf>,
    /// Image manifest, or FOXHOLE_HYPERV_BASE_MANIFEST
    #[arg(long, alias = "hyperv-base-manifest")]
    pub base_manifest: Option<PathBuf>,
    /// Controlled gateway configuration, or FOXHOLE_HYPERV_GATEWAY_CONFIG
    #[arg(long, alias = "hyperv-gateway-config")]
    pub gateway_config: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "deny-all")]
    pub network_policy: DoctorNetwork,
    /// Validate the offline guest scanner configuration without launching scanners
    #[arg(long)]
    pub analysis_config: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum DoctorNetwork {
    DenyAll,
    HostServer,
    AllowInternet,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
    NotChecked,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    pub remedy: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub foxhole_version: &'static str,
    pub checks: Vec<Check>,
    pub ready: bool,
    pub scope: &'static str,
}
impl Default for DoctorReport {
    fn default() -> Self {
        Self {
            schema_version: 1,
            foxhole_version: env!("CARGO_PKG_VERSION"),
            checks: vec![],
            ready: true,
            scope: "host preflight only; guest telemetry and scanner readiness require a live smoke test",
        }
    }
}
impl DoctorReport {
    /// Appends a diagnostic, permanently clearing readiness when any check fails.
    /// Warnings and unchecked guest prerequisites remain visible without becoming failures.
    pub fn add(
        &mut self,
        id: &str,
        status: CheckStatus,
        message: impl Into<String>,
        remedy: Option<&str>,
    ) {
        if status == CheckStatus::Fail {
            self.ready = false;
        }
        self.checks.push(Check {
            id: id.into(),
            status,
            message: message.into(),
            remedy: remedy.map(str::to_owned),
        });
    }
}

/// Deserializes a configuration from a pinned local file capped at 64 KiB.
/// Schema and semantic validation remain the responsibility of the requested type/caller.
pub(crate) fn read_config<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
) -> Result<T, Box<dyn Error>> {
    let mut input = crate::host_file::open_pinned_input(path, 64 * 1024)?;
    let mut bytes = Vec::new();
    input
        .file
        .by_ref()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err("configuration exceeds 64 KiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Resolves image/gateway defaults, runs host preflight, and prints text or JSON diagnostics.
/// Returns an error for failed prerequisites; guest readiness still requires a live smoke test.
pub fn run(mut args: DoctorArgs) -> Result<(), Box<dyn Error>> {
    args.base_image = args.base_image.or_else(|| {
        std::env::var_os("FOXHOLE_HYPERV_BASE_IMAGE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    #[cfg(windows)]
    if args.base_image.is_none() {
        args.base_image = Some(
            std::env::var_os("ProgramData")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                .join("Foxhole/images/foxhole-base.vhdx"),
        );
    }
    args.base_manifest = args.base_manifest.or_else(|| {
        std::env::var_os("FOXHOLE_HYPERV_BASE_MANIFEST")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    args.base_manifest = args.base_manifest.or_else(|| {
        args.base_image
            .as_ref()
            .map(|p| p.with_extension("manifest.json"))
    });
    args.gateway_config = args.gateway_config.or_else(|| {
        std::env::var_os("FOXHOLE_HYPERV_GATEWAY_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    let mut report = crate::sandbox::hyperv::doctor::inspect(&args);
    if let Some(path) = &args.analysis_config {
        match read_config::<crate::detection::DetectionConfig>(path) {
            Ok(config) => match config.validate() {
                Ok(()) => {
                    report.add(
                        "scanner_config",
                        CheckStatus::Pass,
                        "Scanner schema, guest paths, hashes and budgets are valid",
                        None,
                    );
                    for (name, stage) in config.stages() {
                        let (status, message) = if !stage.enabled {
                            (CheckStatus::NotChecked, "disabled")
                        } else if stage.executable.is_none()
                            || (name != "pe" && stage.rules.is_none())
                        {
                            (
                                CheckStatus::Warning,
                                "enabled but interpreter or rule pack is not configured",
                            )
                        } else {
                            (
                                CheckStatus::Pass,
                                "configured; deployment and versions inside the guest are not yet verified",
                            )
                        };
                        report.add(&format!("scanner_{name}"), status, message, (status == CheckStatus::Warning).then_some("Build the guest scanner configuration with scripts/build_detection_config.py and provision the matching image."));
                    }
                }
                Err(error) => report.add(
                    "scanner_config",
                    CheckStatus::Fail,
                    error,
                    Some("Correct the scanner configuration and rerun doctor."),
                ),
            },
            Err(error) => report.add(
                "scanner_config",
                CheckStatus::Fail,
                error.to_string(),
                Some("Supply an accessible, bounded JSON file with --analysis-config."),
            ),
        }
    } else {
        report.add(
            "scanner_config",
            CheckStatus::Warning,
            "No scanner configuration supplied; guest scanners have not been checked",
            Some("Pass --analysis-config to validate scanner settings."),
        );
    }
    report.add(
        "guest_readiness",
        CheckStatus::NotChecked,
        "No VM was booted. Sysmon, WFP, scanner versions and collection need live verification",
        Some("Run scripts/Invoke-FoxholeSmokeTest.ps1 with the qualified execution image."),
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Foxhole doctor {} — read-only host preflight",
            report.foxhole_version
        );
        for check in &report.checks {
            println!(
                "[{:?}] {}: {}",
                check.status,
                check.id,
                crate::terminal_safe(&check.message)
            );
            if let Some(remedy) = &check.remedy {
                println!("       Fix: {}", crate::terminal_safe(remedy));
            }
        }
        println!(
            "Host checks: {}. Guest readiness: not checked.",
            if report.ready {
                "passed (review warnings)"
            } else {
                "failed"
            }
        );
    }
    if report.ready {
        Ok(())
    } else {
        Err("doctor found failed prerequisites; see checks and remedies above".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn warning_is_not_a_failure_and_later_pass_cannot_erase_failure() {
        let mut report = DoctorReport::default();
        report.add("optional", CheckStatus::Warning, "unverified", None);
        assert!(report.ready);
        report.add("image", CheckStatus::Fail, "bad hash", None);
        report.add("tools", CheckStatus::Pass, "present", None);
        assert!(!report.ready);
        assert_eq!(
            serde_json::to_value(report).unwrap()["checks"][1]["status"],
            "fail"
        );
    }
}
