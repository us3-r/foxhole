use crate::artifact;
use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::data_disk::{self, RunDataDisk};
use crate::sandbox::hyperv::disk;
use crate::sandbox::hyperv::network::{self, NetworkOwnedResources};
use crate::sandbox::hyperv::powershell::{NativePowerShell, PowerShellExecutor};
use crate::sandbox::hyperv::vm::{self, VmHandle};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const CLEANUP_JOURNAL_SCHEMA_VERSION: u32 = 3;
const MAX_JOURNAL_SEQUENCE: u64 = 10_000;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CleanupPhase {
    Preparing,
    VmCreated,
    Running,
    Cleaning,
    Failed,
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedSwitch {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupJournal {
    pub schema_version: u32,
    pub sequence: u64,
    pub run_id: String,
    pub run_root: PathBuf,
    pub created_at_unix_ms: u64,
    pub phase: CleanupPhase,
    pub vm: Option<VmHandle>,
    pub os_disk: Option<PathBuf>,
    #[serde(default)]
    pub os_disk_identifier: Option<String>,
    pub data_disk: Option<RunDataDisk>,
    pub owned_switch: Option<OwnedSwitch>,
    #[serde(default)]
    pub network: Option<NetworkOwnedResources>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub leftover_resources: Vec<String>,
}

impl CleanupJournal {
    pub(crate) fn new(run_id: String, run_root: PathBuf) -> SandboxResult<Self> {
        validate_run_identity(&run_id, &run_root)?;
        Ok(Self {
            schema_version: CLEANUP_JOURNAL_SCHEMA_VERSION,
            sequence: 0,
            run_id,
            run_root,
            created_at_unix_ms: now_unix_ms(),
            phase: CleanupPhase::Preparing,
            vm: None,
            os_disk: None,
            os_disk_identifier: None,
            data_disk: None,
            owned_switch: None,
            network: None,
            warnings: Vec::new(),
            leftover_resources: Vec::new(),
        })
    }

    pub(crate) fn persist(&mut self) -> SandboxResult<PathBuf> {
        validate_journal(self)?;
        if self.sequence >= MAX_JOURNAL_SEQUENCE {
            return Err(SandboxError::new(
                "hyperv_cleanup_journal",
                "cleanup journal exceeded its bounded generation count",
            ));
        }
        self.sequence += 1;
        let path = self
            .run_root
            .join(format!("cleanup-journal-{:06}.json", self.sequence));
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            SandboxError::with_source("hyperv_cleanup_journal", "serialize cleanup journal", error)
        })?;
        if bytes.len() > 1024 * 1024 {
            return Err(SandboxError::new(
                "hyperv_cleanup_journal",
                "cleanup journal exceeds its size limit",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                SandboxError::with_source(
                    "hyperv_cleanup_journal",
                    "create an append-only cleanup journal generation",
                    error,
                )
            })?;
        file.write_all(&bytes).map_err(|error| {
            SandboxError::with_source("hyperv_cleanup_journal", "write cleanup journal", error)
        })?;
        file.write_all(b"\n").map_err(|error| {
            SandboxError::with_source("hyperv_cleanup_journal", "terminate cleanup journal", error)
        })?;
        file.sync_all().map_err(|error| {
            SandboxError::with_source(
                "hyperv_cleanup_journal",
                "durably flush cleanup journal",
                error,
            )
        })?;
        Ok(path)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupOutcome {
    pub attempted: bool,
    pub success: bool,
    pub warnings: Vec<String>,
    pub leftover_resources: Vec<String>,
    pub removed_resources: Vec<String>,
}

struct RecoveryRunGuard {
    run_root: PathBuf,
    _directory_pins: Vec<File>,
}

pub(crate) fn cleanup_resources(
    executor: &dyn PowerShellExecutor,
    journal: &mut CleanupJournal,
    shutdown_grace: Duration,
) -> CleanupOutcome {
    let mut outcome = CleanupOutcome {
        attempted: true,
        success: false,
        warnings: Vec::new(),
        leftover_resources: Vec::new(),
        removed_resources: Vec::new(),
    };
    let legacy_storage_identity = journal.schema_version == 1;
    if legacy_storage_identity {
        outcome.warnings.push(
            "schema-1 cleanup journal lacks authenticated VHD identities; VM reconciliation will proceed, but writable disks will be retained"
                .to_string(),
        );
    }
    let _resource_pins = match artifact::pin_safe_directory_tree(&journal.run_root, false) {
        Ok(pins) => pins,
        Err(error) => {
            outcome.warnings.push(format!(
                "refusing cleanup because the run directory could not be pinned without following links: {error}"
            ));
            outcome.leftover_resources.push(format!(
                "run_root:{}:retained_unverified_path",
                journal.run_root.display()
            ));
            return outcome;
        }
    };
    journal.phase = CleanupPhase::Cleaning;
    record_persist_error(journal, &mut outcome);

    let mut vm_removed = true;
    if let Some(vm) = journal.vm.clone() {
        match vm::query(executor, &vm.id) {
            Ok(status) if status.exists && !status.state.eq_ignore_ascii_case("off") => {
                match vm::stop(executor, &vm, false) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        if let Err(error) = vm::stop(executor, &vm, true) {
                            outcome
                                .warnings
                                .push(format!("force-stop disposable VM: {error}"));
                        }
                    }
                }
                match vm::wait_for_off(executor, &vm, shutdown_grace) {
                    Ok(true) => {}
                    Ok(false) => {
                        if let Err(error) = vm::stop(executor, &vm, true) {
                            outcome
                                .warnings
                                .push(format!("force-stop VM after grace period: {error}"));
                        }
                    }
                    Err(error) => outcome
                        .warnings
                        .push(format!("verify VM shutdown: {error}")),
                }
            }
            Ok(_) => {}
            Err(error) => outcome
                .warnings
                .push(format!("query VM before cleanup: {error}")),
        }

        if let Some(data) = journal.data_disk.as_ref()
            && let Err(error) = vm::detach_disk(executor, &vm, &data.path)
        {
            outcome
                .warnings
                .push(format!("detach run-data disk: {error}"));
        }
        if let Some(os_disk) = journal.os_disk.as_ref()
            && let Err(error) = vm::detach_disk(executor, &vm, os_disk)
        {
            outcome
                .warnings
                .push(format!("detach differencing OS disk: {error}"));
        }
        if let Err(error) = vm::remove(executor, &vm) {
            vm_removed = false;
            outcome
                .warnings
                .push(format!("remove disposable VM: {error}"));
            outcome
                .leftover_resources
                .push(format!("vm:{}:{}", vm.id, vm.name));
        } else {
            journal.vm = None;
        }
    } else if let Err(error) = vm::remove_planned(executor, &journal.run_id, &journal.run_root) {
        vm_removed = false;
        outcome
            .warnings
            .push(format!("reconcile partially-created VM: {error}"));
        outcome
            .leftover_resources
            .push(format!("vm_name:foxhole-{}", journal.run_id));
    }

    // Keep the scoped firewall policy and packet capture in place until the disposable VM is
    // proven stopped and removed. Removing containment first would create a brief fail-open window
    // during interrupted or timed-out runs.
    if vm_removed && let Some(resources) = journal.network.clone() {
        match network::cleanup_owned_resources(executor, &resources) {
            Ok(result) => {
                outcome.removed_resources.extend(result.removed);
                journal.network = None;
                record_persist_error(journal, &mut outcome);
            }
            Err(error) => {
                outcome
                    .warnings
                    .push(format!("remove run-owned network resources: {error}"));
                outcome
                    .leftover_resources
                    .push(format!("network_resources:{}", journal.run_id));
            }
        }
    } else if !vm_removed && journal.network.is_some() {
        outcome.leftover_resources.push(format!(
            "network_resources:{}:retained_because_vm_removal_failed",
            journal.run_id
        ));
    }

    // Never delete backing files or switches while VM removal is uncertain. Retaining exact
    // identifiers is safer than turning a cleanup failure into use-after-delete corruption.
    if vm_removed && legacy_storage_identity {
        if let Some(data_disk) = journal.data_disk.as_ref() {
            outcome.leftover_resources.push(format!(
                "data_disk:{}:retained_legacy_unverified_identity",
                data_disk.path.display()
            ));
        }
        if let Some(os_disk) = journal.os_disk.as_ref() {
            outcome.leftover_resources.push(format!(
                "os_disk:{}:retained_legacy_unverified_identity",
                os_disk.display()
            ));
        }
        if let Some(owned_switch) = journal.owned_switch.as_ref() {
            outcome.leftover_resources.push(format!(
                "switch:{}:{}:retained_legacy_unverified_ownership",
                owned_switch.id, owned_switch.name
            ));
        }
    } else if vm_removed {
        if let Some(data_disk) = journal.data_disk.as_mut() {
            // Reconcile actual VHD state even if a crash left the recorded state one generation
            // behind. The PowerShell operation is idempotent when the VHD is already detached.
            if let Err(error) = data_disk::dismount(executor, data_disk) {
                outcome
                    .warnings
                    .push(format!("dismount run-data disk: {error}"));
            }
            if let Err(error) = delete_verified_disk(
                executor,
                &data_disk.path,
                &journal.run_root,
                data_disk.vhd_identifier.as_deref(),
            ) {
                outcome
                    .warnings
                    .push(format!("delete run-data disk: {error}"));
                outcome
                    .leftover_resources
                    .push(format!("data_disk:{}", data_disk.path.display()));
            } else {
                journal.data_disk = None;
            }
        }

        if let Some(os_disk) = journal.os_disk.as_ref() {
            if let Err(error) = delete_verified_disk(
                executor,
                os_disk,
                &journal.run_root,
                journal.os_disk_identifier.as_deref(),
            ) {
                outcome
                    .warnings
                    .push(format!("delete differencing disk: {error}"));
                outcome
                    .leftover_resources
                    .push(format!("os_disk:{}", os_disk.display()));
            } else {
                journal.os_disk = None;
                journal.os_disk_identifier = None;
            }
        }

        if let Some(owned_switch) = journal.owned_switch.as_ref() {
            // Current Hyper-V network modes never provision a per-run switch, so a journal alone
            // is not ownership evidence. Deleting a host switch named by an attacker-authored or
            // corrupted journal would be a confused-deputy vulnerability. Retain it until a
            // future provisioning protocol can supply independently authenticated ownership.
            outcome.warnings.push(
                "refusing to remove a journal-supplied virtual switch without independently authenticated ownership"
                    .to_string(),
            );
            outcome.leftover_resources.push(format!(
                "switch:{}:{}:retained_unverified_ownership",
                owned_switch.id, owned_switch.name
            ));
        }
    } else {
        if let Some(data_disk) = journal.data_disk.as_ref() {
            outcome.leftover_resources.push(format!(
                "data_disk:{}:retained_because_vm_removal_failed",
                data_disk.path.display()
            ));
        }
        if let Some(os_disk) = journal.os_disk.as_ref() {
            outcome.leftover_resources.push(format!(
                "os_disk:{}:retained_because_vm_removal_failed",
                os_disk.display()
            ));
        }
        if let Some(owned_switch) = journal.owned_switch.as_ref() {
            outcome.leftover_resources.push(format!(
                "switch:{}:{}:retained_because_vm_removal_failed",
                owned_switch.id, owned_switch.name
            ));
        }
    }

    outcome.leftover_resources.sort();
    outcome.leftover_resources.dedup();
    journal.warnings.extend(outcome.warnings.clone());
    journal.leftover_resources = outcome.leftover_resources.clone();
    journal.phase = if outcome.leftover_resources.is_empty() && outcome.warnings.is_empty() {
        CleanupPhase::Finished
    } else {
        CleanupPhase::Failed
    };
    record_persist_error(journal, &mut outcome);
    outcome.success = outcome.leftover_resources.is_empty() && outcome.warnings.is_empty();
    outcome
}

pub fn recover_stale_run(
    run_root: &Path,
    shutdown_grace: Duration,
) -> SandboxResult<CleanupOutcome> {
    let artifact_root = artifact::artifact_root().map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_recovery",
            "resolve Foxhole's protected artifact root",
            error,
        )
    })?;
    recover_stale_run_from_root(&NativePowerShell, &artifact_root, run_root, shutdown_grace)
}

fn recover_stale_run_from_root(
    executor: &dyn PowerShellExecutor,
    artifact_root: &Path,
    run_root: &Path,
    shutdown_grace: Duration,
) -> SandboxResult<CleanupOutcome> {
    if shutdown_grace.is_zero() || shutdown_grace > Duration::from_secs(10 * 60) {
        return Err(SandboxError::new(
            "hyperv_cleanup_recovery",
            "cleanup recovery grace period must be between one second and ten minutes",
        ));
    }
    // Keep every directory in the trusted ancestry pinned for the complete reconciliation. On
    // Windows these handles deny delete sharing, preventing a checked directory from being
    // replaced by a junction while journal-supplied VM or disk paths are acted upon.
    let recovery_root = bind_recovery_run_root(artifact_root, run_root)?;
    let mut journal = latest_journal(&recovery_root.run_root)?.ok_or_else(|| {
        SandboxError::new(
            "hyperv_cleanup_recovery",
            "no valid cleanup journal exists for the requested run directory",
        )
    })?;
    if journal.phase == CleanupPhase::Finished
        && journal.vm.is_none()
        && journal.os_disk.is_none()
        && journal.data_disk.is_none()
        && journal.owned_switch.is_none()
        && journal.network.is_none()
    {
        return Ok(CleanupOutcome {
            attempted: false,
            success: true,
            warnings: Vec::new(),
            leftover_resources: Vec::new(),
            removed_resources: Vec::new(),
        });
    }
    Ok(cleanup_resources(executor, &mut journal, shutdown_grace))
}

fn bind_recovery_run_root(
    artifact_root: &Path,
    requested_run_root: &Path,
) -> SandboxResult<RecoveryRunGuard> {
    artifact::validate_absolute_local_path(artifact_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_recovery",
            "Foxhole's artifact root must be an absolute local path",
            error,
        )
    })?;
    let run_id = requested_run_root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            SandboxError::new(
                "hyperv_cleanup_recovery",
                "cleanup recovery path must end in a hexadecimal run identifier",
            )
        })?;
    validate_run_identity(run_id, requested_run_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_recovery",
            "cleanup recovery path has an invalid run identity",
            error,
        )
    })?;

    let protected_runs_root = artifact_root.join("hyperv").join("runs");
    let expected_run_root = protected_runs_root.join(run_id);
    if !same_run_root(requested_run_root, &expected_run_root) {
        return Err(SandboxError::new(
            "hyperv_cleanup_recovery",
            format!(
                "cleanup recovery is restricted to protected Foxhole runs below {}",
                protected_runs_root.display()
            ),
        ));
    }
    artifact::verify_local_fixed_volume(&expected_run_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_recovery",
            "cleanup recovery root must remain on Foxhole's fixed local artifact volume",
            error,
        )
    })?;
    let directory_pins =
        artifact::pin_safe_directory_tree(&expected_run_root, false).map_err(|error| {
            SandboxError::with_source(
                "hyperv_cleanup_recovery",
                "pin the protected Hyper-V run ancestry without following links or reparse points",
                error,
            )
        })?;
    artifact::harden_owned_directory_chain(artifact_root, &expected_run_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_recovery",
            "restore owner-only protection on the pinned Hyper-V run ancestry",
            error,
        )
    })?;

    Ok(RecoveryRunGuard {
        run_root: expected_run_root,
        _directory_pins: directory_pins,
    })
}

fn delete_verified_disk(
    executor: &dyn PowerShellExecutor,
    path: &Path,
    run_root: &Path,
    expected_identifier: Option<&str>,
) -> SandboxResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SandboxError::with_source(
                "hyperv_cleanup",
                "inspect a recorded VHDX before deletion",
                error,
            ));
        }
    }
    let expected_identifier = expected_identifier.ok_or_else(|| {
        SandboxError::new(
            "hyperv_cleanup",
            "refusing destructive recovery without a recorded VHD identity",
        )
    })?;
    disk::delete_owned_disk(executor, path, run_root, expected_identifier)
}

fn record_persist_error(journal: &mut CleanupJournal, outcome: &mut CleanupOutcome) {
    if let Err(error) = journal.persist() {
        outcome
            .warnings
            .push(format!("persist cleanup journal: {error}"));
        outcome
            .leftover_resources
            .push(format!("cleanup_journal:{}", journal.run_root.display()));
    }
}

fn validate_journal(journal: &CleanupJournal) -> SandboxResult<()> {
    let legacy_schema = journal.schema_version == 1;
    if (!(1..=CLEANUP_JOURNAL_SCHEMA_VERSION).contains(&journal.schema_version))
        || journal.created_at_unix_ms == 0
        || journal.sequence > MAX_JOURNAL_SEQUENCE
        || journal.warnings.len() > 512
        || journal.leftover_resources.len() > 128
        || journal
            .warnings
            .iter()
            .chain(journal.leftover_resources.iter())
            .any(|value| value.len() > 4_096 || value.contains('\0'))
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "cleanup journal schema, sequence, time, or diagnostic bounds are invalid",
        ));
    }
    validate_run_identity(&journal.run_id, &journal.run_root)?;
    if let Some(vm) = journal.vm.as_ref()
        && (vm.name != format!("foxhole-{}", journal.run_id)
            || vm.generation != 2
            || !artifact::path_is_within(&vm.configuration_path, &journal.run_root)
            || vm.configuration_path == journal.run_root
            || validate_resource_identifier(&vm.id).is_err())
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "cleanup journal VM identity is not owned by this run",
        ));
    }
    if let Some(path) = journal.os_disk.as_deref() {
        disk::validate_owned_path(path, &journal.run_root)?;
    }
    if (journal.os_disk.is_none() && journal.os_disk_identifier.is_some())
        || (journal.os_disk.is_some()
            && journal.os_disk_identifier.is_none()
            && !legacy_schema
            && journal.phase != CleanupPhase::Preparing)
        || journal
            .os_disk_identifier
            .as_deref()
            .is_some_and(|value| validate_resource_identifier(value).is_err())
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "cleanup journal OS-disk identity is invalid or incomplete",
        ));
    }
    if let Some(data) = journal.data_disk.as_ref() {
        disk::validate_owned_path(&data.path, &journal.run_root)?;
        let expected_label = format!(
            "FOXHOLE_{}",
            journal.run_id[..journal.run_id.len().min(12)].to_ascii_uppercase()
        );
        if data.path.file_name().and_then(|value| value.to_str()) != Some("run-data.vhdx")
            || !same_run_root(&data.mount_path, &journal.run_root.join("data-mount"))
            || data.label != expected_label
            || !(data_disk::MIN_DATA_DISK_BYTES..=data_disk::MAX_DATA_DISK_BYTES)
                .contains(&data.size_bytes)
            || data
                .disk_unique_id
                .as_deref()
                .is_some_and(|value| validate_resource_identifier(value).is_err())
            || data
                .vhd_identifier
                .as_deref()
                .is_some_and(|value| validate_resource_identifier(value).is_err())
            || (data.state != data_disk::DataDiskState::Planned
                && !legacy_schema
                && (data.disk_unique_id.is_none() || data.vhd_identifier.is_none()))
        {
            return Err(SandboxError::new(
                "hyperv_cleanup_journal",
                "cleanup journal run-data disk identity is invalid",
            ));
        }
    }
    if let Some(owned_switch) = journal.owned_switch.as_ref() {
        validate_resource_identifier(&owned_switch.id)?;
        if owned_switch.name.trim().is_empty()
            || owned_switch.name.len() > 80
            || owned_switch.name.eq_ignore_ascii_case("Default Switch")
            || owned_switch.name.chars().any(char::is_control)
        {
            return Err(SandboxError::new(
                "hyperv_cleanup_journal",
                "cleanup journal switch identity is invalid",
            ));
        }
    }
    if let Some(resources) = journal.network.as_ref() {
        network::validate_owned_resources(resources, &journal.run_id, &journal.run_root)?;
    }
    if journal.phase == CleanupPhase::Finished
        && (journal.vm.is_some()
            || journal.os_disk.is_some()
            || journal.os_disk_identifier.is_some()
            || journal.data_disk.is_some()
            || journal.owned_switch.is_some()
            || journal.network.is_some()
            || !journal.leftover_resources.is_empty())
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "finished cleanup journal still names live resources",
        ));
    }
    Ok(())
}

fn validate_run_identity(run_id: &str, run_root: &Path) -> SandboxResult<()> {
    if !(16..=64).contains(&run_id.len())
        || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !run_root.is_absolute()
        || run_root.file_name().and_then(|name| name.to_str()) != Some(run_id)
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "cleanup journal run identity or root is invalid",
        ));
    }
    artifact::validate_absolute_local_path(run_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_journal",
            "cleanup run root must be an absolute local path",
            error,
        )
    })
}

fn validate_resource_identifier(identifier: &str) -> SandboxResult<()> {
    if identifier.trim().is_empty()
        || identifier.len() > 128
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'{' | b'}'))
    {
        return Err(SandboxError::new(
            "hyperv_cleanup",
            "resource identifier contains unsafe characters",
        ));
    }
    Ok(())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub(crate) fn latest_journal(run_root: &Path) -> SandboxResult<Option<CleanupJournal>> {
    artifact::validate_absolute_local_path(run_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_journal",
            "cleanup recovery root must be an absolute local path",
            error,
        )
    })?;
    let _directory_pins = artifact::pin_safe_directory_tree(run_root, false).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_journal",
            "pin cleanup recovery directory without following reparse points",
            error,
        )
    })?;
    let mut latest: Option<CleanupJournal> = None;
    let mut entry_count = 0usize;
    for entry in fs::read_dir(run_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_cleanup_journal",
            "enumerate cleanup journals",
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            SandboxError::with_source(
                "hyperv_cleanup_journal",
                "read cleanup journal entry",
                error,
            )
        })?;
        entry_count += 1;
        if entry_count > MAX_JOURNAL_SEQUENCE as usize + 64 {
            return Err(SandboxError::new(
                "hyperv_cleanup_journal",
                "cleanup run directory contains too many entries",
            ));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(sequence) = journal_sequence_from_name(name) else {
            continue;
        };
        let path = entry.path();
        let Ok(mut file) = artifact::open_safe_regular_file(&path) else {
            continue;
        };
        let metadata = file.metadata().map_err(|error| {
            SandboxError::with_source("hyperv_cleanup_journal", "inspect cleanup journal", error)
        })?;
        if metadata.len() == 0 || metadata.len() > 1024 * 1024 {
            continue;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                SandboxError::with_source(
                    "hyperv_cleanup_journal",
                    "read cleanup journal generation",
                    error,
                )
            })?;
        if bytes.len() as u64 != metadata.len() {
            continue;
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let Ok(candidate) = CleanupJournal::deserialize(&mut deserializer) else {
            // A crash can leave the newest create-new generation truncated. Continue to the
            // preceding durable generation instead of making recovery impossible.
            continue;
        };
        if deserializer.end().is_err()
            || candidate.sequence != sequence
            || !same_run_root(&candidate.run_root, run_root)
            || validate_journal(&candidate).is_err()
        {
            continue;
        }
        if latest
            .as_ref()
            .is_none_or(|current| candidate.sequence > current.sequence)
        {
            latest = Some(candidate);
        }
    }
    Ok(latest)
}

fn journal_sequence_from_name(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix("cleanup-journal-")?
        .strip_suffix(".json")?;
    if digits.len() != 6 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    (sequence > 0 && sequence <= MAX_JOURNAL_SEQUENCE).then_some(sequence)
}

fn same_run_root(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        artifact::windows_paths_equal(left, right)
    }
    #[cfg(not(target_os = "windows"))]
    {
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::hyperv::powershell::PowerShellInvocation;
    use serde_json::Value;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct RecordingPowerShell {
        calls: Mutex<Vec<&'static str>>,
    }

    impl PowerShellExecutor for RecordingPowerShell {
        fn execute(&self, invocation: &PowerShellInvocation) -> SandboxResult<Value> {
            self.calls.lock().unwrap().push(invocation.operation);
            if invocation.operation == "reconcile planned disposable Hyper-V VM" {
                return Ok(serde_json::json!({ "removed": true }));
            }
            Err(SandboxError::new(
                "cleanup_test",
                format!(
                    "unexpected PowerShell operation during cleanup test: {}",
                    invocation.operation
                ),
            ))
        }
    }

    fn unique_test_root(description: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "foxhole-{description}-{}-{}",
            std::process::id(),
            now_unix_ms()
        ))
    }

    #[test]
    fn journals_require_exact_run_owned_paths() {
        let run_id = "0123456789abcdef";
        let root = std::env::temp_dir().join(run_id);
        let mut journal = CleanupJournal::new(run_id.into(), root.clone()).unwrap();
        assert!(validate_journal(&journal).is_ok());
        journal.os_disk = Some(root.join("os-diff.vhdx"));
        assert!(validate_journal(&journal).is_ok());
        journal.phase = CleanupPhase::Running;
        assert!(
            validate_journal(&journal).is_err(),
            "destructive recovery requires the provisioned VHD identity"
        );
        journal.os_disk_identifier = Some("11111111-1111-1111-1111-111111111111".into());
        assert!(validate_journal(&journal).is_ok());
        journal.os_disk = Some(std::env::temp_dir().join("escape.vhdx"));
        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn cleanup_outcome_defaults_to_not_attempted() {
        let outcome = CleanupOutcome::default();
        assert!(!outcome.attempted);
        assert!(!outcome.success);
    }

    #[test]
    fn recovery_uses_latest_valid_bound_generation_after_a_truncated_write() {
        let run_id = "0123456789abcdef";
        let parent = unique_test_root("cleanup-journal-test");
        let root = parent.join(run_id);
        fs::create_dir_all(&root).unwrap();
        let mut journal = CleanupJournal::new(run_id.into(), root.clone()).unwrap();
        journal.persist().unwrap();
        fs::write(root.join("cleanup-journal-000002.json"), b"{\"truncated\":").unwrap();

        let recovered = latest_journal(&root).unwrap().unwrap();
        assert_eq!(recovered.sequence, 1);
        assert_eq!(recovered.run_root, root);

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn recovery_recognizes_schema_one_journals_but_retains_unverified_disks() {
        let run_id = "0123456789abcdef";
        let parent = unique_test_root("legacy-cleanup-journal-test");
        let root = parent.join(run_id);
        fs::create_dir_all(&root).unwrap();
        let mut journal = CleanupJournal::new(run_id.into(), root.clone()).unwrap();
        journal.schema_version = 1;
        journal.sequence = 1;
        journal.phase = CleanupPhase::Running;
        journal.os_disk = Some(root.join("os-diff.vhdx"));
        let mut value = serde_json::to_value(&journal).unwrap();
        value.as_object_mut().unwrap().remove("os_disk_identifier");
        fs::write(
            root.join("cleanup-journal-000001.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        let recovered = latest_journal(&root).unwrap().unwrap();
        assert_eq!(recovered.schema_version, 1);
        assert!(recovered.os_disk_identifier.is_none());
        assert!(validate_journal(&recovered).is_ok());

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn recovery_rejects_hard_linked_cleanup_journals() {
        let run_id = "0123456789abcdef";
        let parent = unique_test_root("linked-cleanup-journal-test");
        let root = parent.join(run_id);
        fs::create_dir_all(&root).unwrap();
        let mut journal = CleanupJournal::new(run_id.into(), root.clone()).unwrap();
        journal.sequence = 1;
        let outside = parent.join("outside-journal.json");
        fs::write(&outside, serde_json::to_vec(&journal).unwrap()).unwrap();
        fs::hard_link(&outside, root.join("cleanup-journal-000001.json")).unwrap();

        assert!(latest_journal(&root).unwrap().is_none());

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn recovery_rejects_a_valid_but_external_crafted_run_journal() {
        let run_id = "0123456789abcdef";
        let parent = unique_test_root("external-recovery");
        let artifact_root = parent.join("protected-artifacts");
        let external_run_root = parent.join("attacker-controlled").join(run_id);
        fs::create_dir_all(artifact_root.join("hyperv").join("runs")).unwrap();
        fs::create_dir_all(&external_run_root).unwrap();
        let mut journal = CleanupJournal::new(run_id.into(), external_run_root.clone()).unwrap();
        journal.phase = CleanupPhase::Running;
        journal.persist().unwrap();
        let executor = RecordingPowerShell::default();

        let error = recover_stale_run_from_root(
            &executor,
            &artifact_root,
            &external_run_root,
            Duration::from_secs(15),
        )
        .expect_err("an external hexadecimal directory must not become a recovery authority");

        assert_eq!(error.stage, "hyperv_cleanup_recovery");
        assert!(error.to_string().contains("protected Foxhole runs"));
        assert!(executor.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn recovery_retains_journal_supplied_switches_without_invoking_switch_removal() {
        let run_id = "0123456789abcdef";
        let parent = unique_test_root("switch-recovery");
        let artifact_root = parent.join("protected-artifacts");
        let run_root = artifact_root.join("hyperv").join("runs").join(run_id);
        fs::create_dir_all(&run_root).unwrap();
        let mut journal = CleanupJournal::new(run_id.into(), run_root.clone()).unwrap();
        journal.phase = CleanupPhase::Running;
        journal.owned_switch = Some(OwnedSwitch {
            id: "11111111-1111-1111-1111-111111111111".into(),
            name: "Foxhole Crafted Switch".into(),
        });
        journal.persist().unwrap();
        let executor = RecordingPowerShell::default();

        let outcome = recover_stale_run_from_root(
            &executor,
            &artifact_root,
            &run_root,
            Duration::from_secs(15),
        )
        .unwrap();

        assert!(outcome.attempted);
        assert!(!outcome.success);
        assert!(
            outcome.warnings.iter().any(|warning| {
                warning.contains("without independently authenticated ownership")
            })
        );
        assert!(outcome.leftover_resources.iter().any(|leftover| {
            leftover
                == "switch:11111111-1111-1111-1111-111111111111:Foxhole Crafted Switch:retained_unverified_ownership"
        }));
        assert_eq!(
            *executor.calls.lock().unwrap(),
            ["reconcile planned disposable Hyper-V VM"]
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn journal_filenames_are_exact_and_bounded() {
        assert_eq!(
            journal_sequence_from_name("cleanup-journal-000001.json"),
            Some(1)
        );
        for invalid in [
            "cleanup-journal-000000.json",
            "cleanup-journal-10001.json",
            "cleanup-journal-000001.json.extra",
            "cleanup-journal-abcdef.json",
            "other-000001.json",
        ] {
            assert_eq!(journal_sequence_from_name(invalid), None);
        }
    }
}
