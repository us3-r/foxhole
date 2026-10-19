mod correlation;
mod detection;
mod ioc;
mod loader;
mod model;
mod process_index;
mod publication;
pub mod stages;
mod telemetry;
mod verdict;
mod virustotal;
mod web;

pub use loader::{DiscoveredRun, discover_runs, load_run};
pub use model::*;
pub use verdict::VerdictConfig;

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_ANALYSIS_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct AnalysisOutputs {
    pub stages: PathBuf,
    pub detection: PathBuf,
    pub normalized: PathBuf,
    pub verdict: PathBuf,
    pub iocs: PathBuf,
    pub virustotal: PathBuf,
    pub web: PathBuf,
}

pub fn normalized_input_sha256(run: &NormalizedRun) -> io::Result<String> {
    let bytes = serde_json::to_vec(&publication::public_value(run)?).map_err(io::Error::other)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn analyze_run(run_root: &Path) -> io::Result<AnalysisOutputs> {
    analyze_run_with_config(run_root, &VerdictConfig::default())
}

pub fn analyze_run_with_config(
    run_root: &Path,
    config: &VerdictConfig,
) -> io::Result<AnalysisOutputs> {
    loader::require_windows_analysis()?;
    // Resolve an optional caller alias once, then keep the real directory ancestry pinned for all
    // reads and writes. Output subdirectories are independently pinned by secure_replace_in.
    let run_root = fs::canonicalize(run_root)?;
    let _run_pins = crate::artifact::pin_safe_directory_tree(&run_root, false)?;
    let normalized = load_run(&run_root)?;
    let normalized_hash = normalized_input_sha256(&normalized)?;
    let verdict = verdict::build_verdict(&normalized, &normalized_hash, config);
    let iocs = ioc::extract_iocs(&normalized, &normalized_hash);
    let virustotal = virustotal::not_queried(
        &normalized,
        "VirusTotal enrichment was not requested for this analysis",
    );

    write_outputs(&run_root, &normalized, &verdict, &iocs, &virustotal)
}

pub async fn analyze_run_with_virustotal_settings(
    run_root: &Path,
    settings_path: &Path,
) -> Result<AnalysisOutputs, Box<dyn std::error::Error>> {
    loader::require_windows_analysis()?;
    let run_root = fs::canonicalize(run_root)?;
    let _run_pins = crate::artifact::pin_safe_directory_tree(&run_root, false)?;
    let normalized = load_run(&run_root)?;
    let normalized_hash = normalized_input_sha256(&normalized)?;
    let verdict = verdict::build_verdict(&normalized, &normalized_hash, &VerdictConfig::default());
    let iocs = ioc::extract_iocs(&normalized, &normalized_hash);
    let settings = crate::utils::load_settings_path(settings_path)?;
    let virustotal = virustotal::collect(
        &normalized,
        &settings.run_settings.vt_api,
        &settings.trusted_engines,
    )
    .await;

    Ok(write_outputs(
        &run_root,
        &normalized,
        &verdict,
        &iocs,
        &virustotal,
    )?)
}

fn write_outputs(
    run_root: &Path,
    normalized: &NormalizedRun,
    verdict: &VerdictReport,
    iocs: &IocReport,
    virustotal: &VirusTotalReport,
) -> io::Result<AnalysisOutputs> {
    publication::validate(normalized, verdict, iocs)?;
    let stages_path = write_json_stable(
        run_root,
        Path::new("analysis/stages.json"),
        &stages::summarize(normalized),
    )?;
    let detection_path = write_json_stable(
        run_root,
        Path::new("analysis/detection.json"),
        &normalized.detection,
    )?;
    let normalized_path =
        write_json_stable(run_root, Path::new("analysis/normalized.json"), normalized)?;
    let verdict_path = write_json_stable(run_root, Path::new("analysis/verdict.json"), verdict)?;
    let iocs_path = write_json_stable(run_root, Path::new("analysis/iocs.json"), iocs)?;
    let virustotal_path =
        write_json_stable(run_root, Path::new("analysis/virustotal.json"), virustotal)?;
    let web = web::write_web_report(run_root, normalized, verdict, iocs, virustotal)?;
    Ok(AnalysisOutputs {
        stages: stages_path,
        detection: detection_path,
        normalized: normalized_path,
        verdict: verdict_path,
        iocs: iocs_path,
        virustotal: virustotal_path,
        web,
    })
}

fn write_json_stable(
    root: &Path,
    relative: &Path,
    value: &impl serde::Serialize,
) -> io::Result<PathBuf> {
    crate::artifact::secure_replace_in(root, relative, MAX_ANALYSIS_OUTPUT_BYTES, |writer| {
        serde_json::to_writer_pretty(&mut *writer, &publication::public_value(value)?)
            .map_err(io::Error::other)?;
        writer.write_all(b"\n")
    })
}
