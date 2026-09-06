mod ioc;
mod loader;
mod model;
mod verdict;
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
    pub normalized: PathBuf,
    pub verdict: PathBuf,
    pub iocs: PathBuf,
    pub web: PathBuf,
}

pub fn normalized_input_sha256(run: &NormalizedRun) -> io::Result<String> {
    let bytes = serde_json::to_vec(run).map_err(io::Error::other)?;
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

    let normalized_path = write_json_stable(
        &run_root,
        Path::new("analysis/normalized.json"),
        &normalized,
    )?;
    let verdict_path = write_json_stable(&run_root, Path::new("analysis/verdict.json"), &verdict)?;
    let iocs_path = write_json_stable(&run_root, Path::new("analysis/iocs.json"), &iocs)?;
    let web = web::write_web_report(&run_root, &normalized, &verdict, &iocs)?;
    Ok(AnalysisOutputs {
        normalized: normalized_path,
        verdict: verdict_path,
        iocs: iocs_path,
        web,
    })
}

fn write_json_stable(
    root: &Path,
    relative: &Path,
    value: &impl serde::Serialize,
) -> io::Result<PathBuf> {
    crate::artifact::secure_replace_in(root, relative, MAX_ANALYSIS_OUTPUT_BYTES, |writer| {
        serde_json::to_writer_pretty(&mut *writer, value).map_err(io::Error::other)?;
        writer.write_all(b"\n")
    })
}
