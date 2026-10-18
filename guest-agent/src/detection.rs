//! Only the guest executable links this launcher. No host CLI can invoke a sample scanner.
use crate::runner::{AgentError, AgentResult};
use foxhole::detection::{DetectionConfig, ScannerConfig, ScannerResult, Status};
use foxhole::sandbox::hyperv::guest_protocol::ArtifactManifestEntry;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const WORKER: &[u8] = include_bytes!("../assets/detection_worker.py");

pub struct Session {
    elapsed: Duration,
    bytes: u64,
    ordinal: usize,
    collected_bytes: u64,
    pub warnings: Vec<String>,
    executions: std::collections::BTreeSet<(String, String)>,
    pub artifacts: Vec<ArtifactManifestEntry>,
}
impl Session {
    /// Collect only target-written, regular files under the private guest work directory.
    /// Other guest paths remain telemetry observations, with an explicit coverage warning.
    pub fn collect_files(
        &mut self,
        config: &DetectionConfig,
        workspace: &crate::filesystem::GuestWorkspace,
        files: &[foxhole::structs::FileObservation],
    ) -> AgentResult<()> {
        let mut paths = files
            .iter()
            .filter(|f| {
                ["create", "write", "modify"]
                    .iter()
                    .any(|s| f.kind.contains(s))
            })
            .map(|f| f.relative_path.clone())
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        let maximum = config
            .stages()
            .iter()
            .map(|(_, s)| s.limits.files)
            .min()
            .unwrap_or(1);
        if paths.len() > maximum {
            self.warnings
                .push("detection collection file count limit exhausted".into());
        }
        for name in paths.into_iter().take(maximum) {
            if self.elapsed >= Duration::from_secs(config.total_timeout_seconds) {
                self.warnings
                    .push("detection collection stopped at total analysis timeout".into());
                break;
            }
            let path = Path::new(&name);
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                workspace.work.join(path)
            };
            if !path.starts_with(&workspace.work)
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                self.warnings.push(
                    "target-written file outside private collection directory was not scanned"
                        .into(),
                );
                continue;
            }
            let limit = config
                .pe
                .limits
                .input_bytes
                .min(config.yara.limits.input_bytes)
                .min(config.capa.limits.input_bytes);
            let Ok(input) = foxhole::host_file::open_pinned_input(&path, limit) else {
                self.warnings.push(
                    "target-written file unavailable, unsafe, or over collection size limit".into(),
                );
                continue;
            };
            let mut data = vec![];
            input
                .file
                .take(limit + 1)
                .read_to_end(&mut data)
                .map_err(|_| {
                    AgentError::new(
                        "detection",
                        "artifact_read_failed",
                        "target artifact could not be read",
                    )
                })?;
            if data.len() as u64 > limit {
                self.warnings
                    .push("target-written file exceeded collection size limit".into());
                continue;
            }
            let hash = format!("{:x}", Sha256::digest(&data));
            let extension = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("bin")
                .to_ascii_lowercase();
            let extension = if ["exe", "dll", "sys", "ps1", "bat", "cmd", "js", "vbs", "py"]
                .contains(&extension.as_str())
            {
                extension.as_str()
            } else if data.starts_with(b"MZ") {
                "exe"
            } else {
                continue;
            };
            let relative = format!("extracted-files/{hash}.{extension}");
            if self.artifacts.iter().any(|a| a.relative_path == relative) {
                continue;
            }
            if self.collected_bytes.saturating_add(data.len() as u64) > config.max_capture_bytes {
                self.warnings
                    .push("target file collection byte budget exhausted".into());
                break;
            }
            crate::security::prepare_broker_directory(&workspace.output.join("extracted-files"))?;
            crate::artifacts::write_atomic_bytes_new(
                &workspace.output.join(&relative),
                &data,
                limit,
            )?;
            self.artifacts.push(ArtifactManifestEntry {
                relative_path: relative.clone(),
                size_bytes: data.len() as u64,
                sha256: hash.clone(),
                kind: "target_created_file".into(),
            });
            self.collected_bytes += data.len() as u64;
            self.scan(
                config,
                workspace,
                &relative,
                &workspace.output.join(&relative),
                &hash,
                false,
            )?;
        }
        Ok(())
    }
    pub fn new() -> Self {
        Self {
            elapsed: Duration::ZERO,
            bytes: 0,
            ordinal: 0,
            collected_bytes: 0,
            warnings: vec![],
            executions: Default::default(),
            artifacts: vec![],
        }
    }
    pub fn scan(
        &mut self,
        config: &DetectionConfig,
        workspace: &crate::filesystem::GuestWorkspace,
        target: &str,
        path: &Path,
        hash: &str,
        capture: bool,
    ) -> AgentResult<()> {
        let worker = workspace.root.join("detection-worker.py");
        if !worker.exists() {
            crate::artifacts::write_atomic_bytes_new(&worker, WORKER, 128 * 1024)?;
        }
        for (name, stage) in config.stages() {
            if (name == "network") != capture {
                continue;
            }
            if self.executions.contains(&(name.into(), target.into())) {
                continue;
            }
            if self
                .executions
                .iter()
                .filter(|(scanner, _)| scanner == name)
                .count()
                >= stage.limits.files
            {
                self.warnings
                    .push(format!("detection {name} file count limit exhausted"));
                continue;
            }
            self.executions.insert((name.into(), target.into()));
            let remaining =
                Duration::from_secs(config.total_timeout_seconds).saturating_sub(self.elapsed);
            let stage_start = Instant::now();
            let fallback = |status, code| {
                let mut r =
                    ScannerResult::empty(name, target, hash, status, stage.limits.clone(), code);
                r.evidence_ids = vec![target.to_string()];
                r
            };
            let mut output = if !stage.enabled {
                serde_json::to_vec(&fallback(Status::Disabled, "stage_disabled"))
                    .unwrap_or_default()
            } else if remaining.is_zero() {
                serde_json::to_vec(&fallback(Status::TimedOut, "total_analysis_timeout"))
                    .unwrap_or_default()
            } else if stage.executable.is_none() {
                serde_json::to_vec(&fallback(Status::Unavailable, "scanner_not_configured"))
                    .unwrap_or_default()
            } else if capture
                && path
                    .metadata()
                    .map_or(true, |m| m.len() > config.max_capture_bytes)
            {
                serde_json::to_vec(&fallback(Status::Partial, "capture_input_limit"))
                    .unwrap_or_default()
            } else {
                let request = serde_json::json!({"stage": name,"config": stage,"target": target,"target_sha256":hash,"path":path});
                match execute(
                    stage,
                    &worker,
                    path,
                    &serde_json::to_vec(&request).unwrap_or_default(),
                    remaining,
                ) {
                    Ok(bytes) => bytes,
                    Err((status, code)) => {
                        serde_json::to_vec(&fallback(status, code)).unwrap_or_default()
                    }
                }
            };
            self.elapsed += stage_start.elapsed();
            if self.bytes.saturating_add(output.len() as u64) > config.max_total_output_bytes {
                output = serde_json::to_vec(&fallback(Status::Partial, "total_output_limit"))
                    .unwrap_or_default();
            }
            if self.bytes.saturating_add(output.len() as u64) > config.max_total_output_bytes {
                return Err(AgentError::new(
                    "detection",
                    "total_output_limit",
                    "analysis output budget exhausted",
                ));
            }
            let relative = format!("detection/{:04}-{name}.json", self.ordinal);
            let folder = workspace.output.join("detection");
            crate::security::prepare_broker_directory(&folder)?;
            crate::artifacts::write_atomic_bytes_new(
                &workspace.output.join(&relative),
                &output,
                stage.limits.output_bytes,
            )?;
            self.bytes += output.len() as u64;
            self.ordinal += 1;
            self.artifacts.push(ArtifactManifestEntry {
                relative_path: relative,
                size_bytes: output.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&output)),
                kind: format!("detection_{name}"),
            });
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn execute(
    _: &ScannerConfig,
    _: &Path,
    _: &Path,
    _: &[u8],
    _: Duration,
) -> Result<Vec<u8>, (Status, &'static str)> {
    Err((
        Status::Unavailable,
        "scanner_requires_disposable_windows_guest",
    ))
}

#[cfg(target_os = "windows")]
fn execute(
    config: &ScannerConfig,
    worker: &Path,
    target: &Path,
    input: &[u8],
    remaining: Duration,
) -> Result<Vec<u8>, (Status, &'static str)> {
    use std::os::windows::{io::AsRawHandle, process::CommandExt};
    use std::process::{Command, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::*;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(process: HANDLE) -> i32;
    }
    struct Job(HANDLE);
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                let _ = TerminateJobObject(self.0, 1);
                let _ = CloseHandle(self.0);
            }
        }
    }
    let failure = |code| (Status::Failed, code);
    let path = Path::new(
        config
            .executable
            .as_deref()
            .ok_or((Status::Unavailable, "scanner_not_configured"))?,
    );
    // Keep all input handles open without write/delete sharing until the worker terminates.
    let mut pinned = foxhole::host_file::open_pinned_input(path, 256 * 1024 * 1024)
        .map_err(|_| (Status::Unavailable, "scanner_unavailable"))?;
    let mut engine = Sha256::new();
    std::io::copy(&mut pinned.file, &mut HashWriter(&mut engine))
        .map_err(|_| failure("scanner_hash_failed"))?;
    if Some(format!("{:x}", engine.finalize()).as_str()) != config.executable_sha256.as_deref() {
        return Err(failure("scanner_integrity_mismatch"));
    }
    let _target_pin = foxhole::host_file::open_pinned_input(target, config.limits.input_bytes)
        .map_err(|_| (Status::Partial, "scanner_input_limit_or_unsafe_path"))?;
    let _worker_pin = foxhole::host_file::open_pinned_input(worker, 128 * 1024)
        .map_err(|_| failure("worker_path_unsafe"))?;
    let mut packs = vec![];
    for pack in [&config.rules, &config.user_rules].into_iter().flatten() {
        packs.push(
            foxhole::host_file::open_pinned_input(Path::new(&pack.path), 32 * 1024 * 1024)
                .map_err(|_| (Status::Unavailable, "rule_pack_unavailable_or_unsafe"))?,
        );
    }
    let job =
        Job(unsafe { CreateJobObjectW(None, None) }
            .map_err(|_| failure("scanner_job_unavailable"))?);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 4;
    limits.ProcessMemoryLimit = config.limits.memory_bytes as usize;
    limits.JobMemoryLimit = config.limits.memory_bytes as usize;
    unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of_val(&limits) as u32,
        )
    }
    .map_err(|_| failure("scanner_job_limits_failed"))?;
    let mut command = Command::new(path);
    command.args(["-I", "-B"]).arg(worker).env_clear();
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    // capa's Windows rule cache requires LOCALAPPDATA. Keep cache and temporary
    // files in the broker-owned guest workspace, never an inherited user profile.
    command
        .env("LOCALAPPDATA", worker.parent().unwrap_or(Path::new(".")))
        // Vivisect uses getpass.getuser() for workspace metadata. Supply a fixed
        // label rather than disclosing the broker's actual account name.
        .env("USERNAME", "FoxholeScanner")
        .env("TEMP", worker.parent().unwrap_or(Path::new(".")))
        .env("TMP", worker.parent().unwrap_or(Path::new(".")));
    let mut child = command
        .current_dir(worker.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x00000004 | 0x08000000)
        .spawn()
        .map_err(|_| (Status::Unavailable, "scanner_launch_failed"))?;
    let handle = HANDLE(child.as_raw_handle());
    if unsafe { AssignProcessToJobObject(job.0, handle) }.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(failure("scanner_job_assignment_failed"));
    }
    let over = Arc::new(AtomicBool::new(false));
    let read = |mut pipe: Box<dyn Read + Send>, max: usize, over: Arc<AtomicBool>| {
        std::thread::spawn(move || {
            let mut result = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if result.len().saturating_add(n) > max {
                            over.store(true, Ordering::SeqCst);
                        } else {
                            result.extend_from_slice(&buffer[..n]);
                        }
                    }
                    Err(_) => {
                        over.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            result
        })
    };
    let stdout = read(
        Box::new(child.stdout.take().ok_or(failure("missing_stdout"))?),
        config.limits.output_bytes as usize,
        over.clone(),
    );
    let stderr = read(
        Box::new(child.stderr.take().ok_or(failure("missing_stderr"))?),
        65536,
        over.clone(),
    );
    if unsafe { NtResumeProcess(handle) } < 0 {
        let _ = child.kill();
        return Err(failure("scanner_resume_failed"));
    }
    let mut stdin = child.stdin.take().ok_or(failure("missing_stdin"))?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let start = Instant::now();
    let timeout = remaining.min(Duration::from_secs(config.limits.timeout_seconds));
    let outcome = loop {
        if over.load(Ordering::SeqCst) {
            break Err((Status::Partial, "scanner_output_limit"));
        }
        if start.elapsed() >= timeout {
            break Err((Status::TimedOut, "scanner_timeout"));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break if status.success() {
                    Ok(())
                } else {
                    Err(failure("scanner_nonzero_exit"))
                };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break Err(failure("scanner_wait_failed")),
        }
    };
    // Terminate the entire job, including surviving descendants with inherited pipe handles.
    drop(job);
    let _ = child.wait();
    let _ = writer.join();
    let output = stdout
        .join()
        .map_err(|_| failure("scanner_output_reader_failed"))?;
    let _ = stderr.join();
    outcome?;
    if over.load(Ordering::SeqCst) {
        return Err((Status::Partial, "scanner_output_limit"));
    }
    Ok(output)
}
struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn real_capa_worker_completes_with_a_private_cache_in_the_isolated_job() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let python = std::env::var_os("FOXHOLE_TEST_PYTHON")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| repository.join("tmp/detection-venv/Scripts/python.exe"));
        assert!(
            python.exists(),
            "this regression needs the pinned scanner test runtime"
        );
        let root = std::env::temp_dir().join(format!(
            "foxhole-capa-job-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::security::prepare_broker_directory(&root).unwrap();
        let target = root.join("harmless.bin");
        // Hand-built inert fixture: it is parsed, never executed.
        let data = include_bytes!("../../tests/fixtures/detection/benign.pe.bin");
        std::fs::write(&target, data).unwrap();
        let worker = root.join("worker.py");
        std::fs::write(&worker, WORKER).unwrap();
        let rules = repository.join("rules/foxhole-capa-1.zip");
        let config = ScannerConfig {
            executable: Some(python.to_string_lossy().into()),
            executable_sha256: Some(format!(
                "{:x}",
                Sha256::digest(std::fs::read(&python).unwrap())
            )),
            rules: Some(foxhole::detection::RulePack {
                id: "foxhole-capa-1".into(),
                version: "1".into(),
                path: rules.to_string_lossy().into(),
                sha256: format!("{:x}", Sha256::digest(std::fs::read(&rules).unwrap())),
            }),
            ..Default::default()
        };
        let request = serde_json::json!({"stage":"capa", "config":config, "target":"primary", "target_sha256":format!("{:x}", Sha256::digest(data)), "path":target});
        let output = execute(
            &config,
            &worker,
            &target,
            &serde_json::to_vec(&request).unwrap(),
            Duration::from_secs(60),
        )
        .unwrap();
        let result: ScannerResult = serde_json::from_slice(&output).unwrap();
        assert_eq!(result.status, Status::Completed, "{:?}", result.warnings);
        assert_eq!(result.version, foxhole::detection::CAPA_VERSION);
        assert!(root.join("flare/capa/cache").is_dir());
        // Only this uniquely-created, broker-owned test workspace is removed.
        assert_eq!(root.parent(), Some(std::env::temp_dir().as_path()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn real_job_adapter_success_timeout_crash_output_and_argument_boundaries() {
        let python = std::env::var_os("FOXHOLE_TEST_PYTHON")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tmp/detection-venv/Scripts/python.exe")
            });
        if !python.exists() {
            eprintln!(
                "adapter integration needs FOXHOLE_TEST_PYTHON; CI supplies the pinned fixture runtime"
            );
            return;
        }
        let root =
            std::env::temp_dir().join(format!("foxhole-scanner-adapter-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("harmless $(never-execute) & marker.bin");
        std::fs::write(&target, b"harmless fixture").unwrap();
        let worker = root.join("adapter-test.py");
        let mut config = ScannerConfig {
            executable: Some(python.to_string_lossy().into()),
            executable_sha256: Some(format!(
                "{:x}",
                Sha256::digest(std::fs::read(&python).unwrap())
            )),
            ..Default::default()
        };
        config.limits.timeout_seconds = 1;
        config.limits.output_bytes = 4096;
        for (source, status) in [
            ("print('harmless')", None),
            ("import time; time.sleep(10)", Some(Status::TimedOut)),
            ("import sys; sys.exit(7)", Some(Status::Failed)),
            ("print('x'*1000000)", Some(Status::Partial)),
        ] {
            std::fs::write(&worker, source).unwrap();
            let result = execute(&config, &worker, &target, b"{}", Duration::from_secs(2));
            match status {
                Some(expected) => assert_eq!(result.unwrap_err().0, expected),
                None => assert!(result.unwrap().starts_with(b"harmless")),
            }
        }
        let mut missing = config.clone();
        missing.executable = Some(root.join("missing.exe").to_string_lossy().into());
        assert_eq!(
            execute(&missing, &worker, &target, b"{}", Duration::from_secs(2))
                .unwrap_err()
                .0,
            Status::Unavailable
        );
        config.executable_sha256 = Some("00".repeat(32));
        assert_eq!(
            execute(&config, &worker, &target, b"{}", Duration::from_secs(2))
                .unwrap_err()
                .1,
            "scanner_integrity_mismatch"
        );
        // Exact fixture cleanup only, no recursive traversal of an attacker-selected path.
        for path in [&target, &worker] {
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(&root).unwrap();
    }
}
