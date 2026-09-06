use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::disk::validate_owned_path;
use crate::sandbox::hyperv::guest_protocol::{self, GuestRunRequest, ProtocolState, StatusRecord};
use crate::sandbox::hyperv::powershell::{
    DEFAULT_MAX_OUTPUT_BYTES, PowerShellExecutor, PowerShellInvocation, command_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const MIN_DATA_DISK_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_DATA_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub(crate) const MAX_STAGED_TARGET_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const RUN_DIRECTORY_NAME: &str = "foxhole-run";
pub(crate) const TARGET_GUEST_PATH: &str = "input/target.bin";
pub(crate) const TARGET_GUEST_BATCH_PATH: &str = "input/target.bat";
pub(crate) const TARGET_GUEST_COMMAND_PATH: &str = "input/target.cmd";

pub(crate) fn guest_target_path(host_target: &Path) -> &'static str {
    match host_target.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("bat") => TARGET_GUEST_BATCH_PATH,
        Some(extension) if extension.eq_ignore_ascii_case("cmd") => TARGET_GUEST_COMMAND_PATH,
        _ => TARGET_GUEST_PATH,
    }
}

fn is_fixed_guest_target_path(path: &str) -> bool {
    matches!(
        path,
        TARGET_GUEST_PATH | TARGET_GUEST_BATCH_PATH | TARGET_GUEST_COMMAND_PATH
    )
}

pub(crate) const CREATE_AND_MOUNT_DATA_DISK_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$module = Get-Module -ListAvailable -Name Hyper-V |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $module) { throw 'Hyper-V PowerShell module was not found' }
    Import-Module -Name $module.Path -ErrorAction Stop
    $path = [string]$request.path
    $mountPath = [string]$request.mount_path
    if ([System.IO.File]::Exists($path) -or [System.IO.Directory]::Exists($path)) {
        throw 'The run-data disk destination already exists'
    }
    if (-not [System.IO.Directory]::Exists($mountPath)) {
        throw 'The protected run-data mount directory does not exist'
    }
    $null = New-VHD -Path $path -Dynamic -SizeBytes ([uint64]$request.size_bytes) -ErrorAction Stop
    $vhd = Mount-VHD -Path $path -NoDriveLetter -Passthru -ErrorAction Stop
    $disk = $vhd | Get-Disk -ErrorAction Stop
    if ([string]$disk.PartitionStyle -ne 'RAW') {
        throw 'A newly-created run-data disk was unexpectedly initialized'
    }
    $disk = Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru -ErrorAction Stop
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -ErrorAction Stop
    $null = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel ([string]$request.label) -Confirm:$false -ErrorAction Stop
    $accessPath = $mountPath.TrimEnd('\') + '\'
    $null = Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $accessPath -ErrorAction Stop
    $data = [ordered]@{
        path = $path
        mount_path = $accessPath
        disk_number = [uint32]$disk.Number
        partition_number = [uint32]$partition.PartitionNumber
        disk_unique_id = [string]$disk.UniqueId
        vhd_identifier = if ($null -eq $vhd.DiskIdentifier) { $null } else { [string]$vhd.DiskIdentifier }
        label = [string]$request.label
        attached = $true
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 6
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'data_disk_create_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const MOUNT_DATA_DISK_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$module = Get-Module -ListAvailable -Name Hyper-V |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $module) { throw 'Hyper-V PowerShell module was not found' }
    Import-Module -Name $module.Path -ErrorAction Stop
    $path = [string]$request.path
    $mountPath = ([string]$request.mount_path).TrimEnd('\') + '\'
    $existingVhd = Get-VHD -Path $path -ErrorAction Stop
    if ([string]$existingVhd.DiskIdentifier -ne [string]$request.expected_vhd_identifier) {
        throw 'The run-data VHD identity does not match the recorded run disk'
    }
    $vhd = Mount-VHD -Path $path -NoDriveLetter -Passthru -ErrorAction Stop
    $disk = $vhd | Get-Disk -ErrorAction Stop
    $partition = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
        Where-Object { $_.Type -ne 'Reserved' } |
        Select-Object -First 1
    if ($null -eq $partition) { throw 'The run-data disk has no data partition' }
    $volume = $partition | Get-Volume -ErrorAction Stop
    if ([string]$volume.FileSystemLabel -ne [string]$request.label) {
        throw 'The run-data disk label does not match this run'
    }
    if ([string]$disk.UniqueId -ne [string]$request.expected_disk_unique_id) {
        Dismount-VHD -Path $path -ErrorAction SilentlyContinue
        throw 'The run-data disk unique identity does not match this run'
    }
    $null = Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $mountPath -ErrorAction Stop
    $data = [ordered]@{
        path = $path
        mount_path = $mountPath
        disk_number = [uint32]$disk.Number
        partition_number = [uint32]$partition.PartitionNumber
        disk_unique_id = [string]$disk.UniqueId
        vhd_identifier = if ($null -eq $vhd.DiskIdentifier) { $null } else { [string]$vhd.DiskIdentifier }
        label = [string]$volume.FileSystemLabel
        attached = $true
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 6
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'data_disk_mount_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const DISMOUNT_DATA_DISK_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$module = Get-Module -ListAvailable -Name Hyper-V |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $module) { throw 'Hyper-V PowerShell module was not found' }
    Import-Module -Name $module.Path -ErrorAction Stop
    $path = [string]$request.path
    $mountPath = ([string]$request.mount_path).TrimEnd('\') + '\'
    $vhd = Get-VHD -Path $path -ErrorAction SilentlyContinue
    if ($null -ne $vhd -and [bool]$vhd.Attached) {
        if ([string]$vhd.DiskIdentifier -ne [string]$request.expected_vhd_identifier) {
            throw 'The run-data VHD identity does not match the recorded run disk'
        }
        try {
            $disk = $vhd | Get-Disk -ErrorAction Stop
            if ([string]$disk.UniqueId -ne [string]$request.expected_disk_unique_id) {
                throw 'The run-data disk unique identity does not match this run'
            }
            $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop
            foreach ($partition in $partitions) {
                $paths = @($partition.AccessPaths)
                if ($paths -contains $mountPath) {
                    Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $mountPath -ErrorAction Stop
                }
            }
        } finally {
            Dismount-VHD -Path $path -ErrorAction Stop
        }
    }
    $data = [ordered]@{ dismounted = $true }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 4
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'data_disk_dismount_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunDataDiskSpec {
    pub run_id: String,
    pub run_root: PathBuf,
    pub path: PathBuf,
    pub mount_path: PathBuf,
    pub size_bytes: u64,
}

impl RunDataDiskSpec {
    pub(crate) fn label(&self) -> SandboxResult<String> {
        validate_run_id(&self.run_id)?;
        Ok(format!(
            "FOXHOLE_{}",
            self.run_id[..self.run_id.len().min(12)].to_ascii_uppercase()
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DataDiskMount {
    pub path: String,
    pub mount_path: String,
    pub disk_number: u32,
    pub partition_number: u32,
    pub disk_unique_id: String,
    pub vhd_identifier: String,
    pub label: String,
    pub attached: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DataDiskState {
    Planned,
    Mounted,
    Detached,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunDataDisk {
    pub path: PathBuf,
    pub mount_path: PathBuf,
    pub size_bytes: u64,
    pub label: String,
    pub disk_unique_id: Option<String>,
    #[serde(default)]
    pub vhd_identifier: Option<String>,
    pub state: DataDiskState,
}

pub(crate) fn create_and_mount(
    executor: &dyn PowerShellExecutor,
    spec: &RunDataDiskSpec,
) -> SandboxResult<RunDataDisk> {
    validate_spec(spec)?;
    let label = spec.label()?;
    let invocation = PowerShellInvocation {
        operation: "create and mount Hyper-V run-data disk",
        script: CREATE_AND_MOUNT_DATA_DISK_SCRIPT,
        input: serde_json::json!({
            "path": command_path(&spec.path, "run-data disk path")?,
            "mount_path": command_path(&spec.mount_path, "run-data mount path")?,
            "size_bytes": spec.size_bytes,
            "label": label,
        }),
        timeout: Duration::from_secs(5 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let mount: DataDiskMount =
        serde_json::from_value(executor.execute(&invocation)?).map_err(|error| {
            SandboxError::with_source("hyperv_data_disk", "decode data-disk mount metadata", error)
        })?;
    validate_mount(spec, &mount, &label)?;
    Ok(RunDataDisk {
        path: spec.path.clone(),
        mount_path: spec.mount_path.clone(),
        size_bytes: spec.size_bytes,
        label,
        disk_unique_id: Some(mount.disk_unique_id),
        vhd_identifier: Some(mount.vhd_identifier),
        state: DataDiskState::Mounted,
    })
}

pub(crate) fn mount_existing(
    executor: &dyn PowerShellExecutor,
    disk: &mut RunDataDisk,
) -> SandboxResult<()> {
    if disk.state == DataDiskState::Mounted {
        return Ok(());
    }
    let expected_disk_unique_id = disk.disk_unique_id.as_deref().ok_or_else(|| {
        SandboxError::new(
            "hyperv_data_disk",
            "refusing to mount a run-data disk without its recorded disk identity",
        )
    })?;
    let expected_vhd_identifier = disk.vhd_identifier.as_deref().ok_or_else(|| {
        SandboxError::new(
            "hyperv_data_disk",
            "refusing to mount a run-data VHD without its recorded VHD identity",
        )
    })?;
    let _disk_pin = crate::artifact::open_safe_regular_file(&disk.path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_data_disk",
            "open the recorded run-data VHD without following links",
            error,
        )
    })?;
    let invocation = PowerShellInvocation {
        operation: "mount existing Hyper-V run-data disk",
        script: MOUNT_DATA_DISK_SCRIPT,
        input: serde_json::json!({
            "path": command_path(&disk.path, "run-data disk path")?,
            "mount_path": command_path(&disk.mount_path, "run-data mount path")?,
            "label": disk.label,
            "expected_disk_unique_id": expected_disk_unique_id,
            "expected_vhd_identifier": expected_vhd_identifier,
        }),
        timeout: Duration::from_secs(2 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let mount: DataDiskMount =
        serde_json::from_value(executor.execute(&invocation)?).map_err(|error| {
            SandboxError::with_source("hyperv_data_disk", "decode data-disk mount metadata", error)
        })?;
    if !mount.attached
        || mount.label != disk.label
        || !paths_equal(Path::new(&mount.path), &disk.path)
        || !paths_equal_normalized(Path::new(&mount.mount_path), &disk.mount_path)
        || disk
            .disk_unique_id
            .as_deref()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&mount.disk_unique_id))
        || disk
            .vhd_identifier
            .as_deref()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&mount.vhd_identifier))
    {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "mounted data disk does not match the recorded run disk",
        ));
    }
    disk.disk_unique_id = Some(mount.disk_unique_id);
    disk.vhd_identifier = Some(mount.vhd_identifier);
    disk.state = DataDiskState::Mounted;
    Ok(())
}

pub(crate) fn dismount(
    executor: &dyn PowerShellExecutor,
    disk: &mut RunDataDisk,
) -> SandboxResult<()> {
    if disk.state == DataDiskState::Detached {
        return Ok(());
    }
    let expected_disk_unique_id = disk.disk_unique_id.as_deref().ok_or_else(|| {
        SandboxError::new(
            "hyperv_data_disk",
            "refusing to dismount a run-data disk without its recorded disk identity",
        )
    })?;
    let expected_vhd_identifier = disk.vhd_identifier.as_deref().ok_or_else(|| {
        SandboxError::new(
            "hyperv_data_disk",
            "refusing to dismount a run-data VHD without its recorded VHD identity",
        )
    })?;
    // An attached VHDX is locked against path replacement by Hyper-V. The script below verifies
    // both recorded identities before dismounting; opening the attached backing file here would
    // reject legitimate runs on hosts where VMMS does not share raw-file read access.
    let invocation = PowerShellInvocation {
        operation: "dismount Hyper-V run-data disk",
        script: DISMOUNT_DATA_DISK_SCRIPT,
        input: serde_json::json!({
            "path": command_path(&disk.path, "run-data disk path")?,
            "mount_path": command_path(&disk.mount_path, "run-data mount path")?,
            "expected_disk_unique_id": expected_disk_unique_id,
            "expected_vhd_identifier": expected_vhd_identifier,
        }),
        timeout: Duration::from_secs(2 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let response = executor.execute(&invocation)?;
    if response.get("dismounted").and_then(|value| value.as_bool()) != Some(true) {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "PowerShell did not confirm data-disk dismount",
        ));
    }
    disk.state = DataDiskState::Detached;
    Ok(())
}

pub(crate) fn stage_package(
    mount_root: &Path,
    request: &GuestRunRequest,
    target: &mut File,
) -> SandboxResult<String> {
    request
        .validate()
        .map_err(|error| SandboxError::new("hyperv_data_disk", error.to_string()))?;
    validate_run_id(&request.run_id)?;
    if !is_fixed_guest_target_path(&request.target) {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "guest request target does not match an approved fixed staging path",
        ));
    }
    let metadata = target.metadata().map_err(|error| {
        SandboxError::with_source("hyperv_data_disk", "query pinned target size", error)
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_STAGED_TARGET_BYTES {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "pinned target is empty, non-regular, or exceeds the staging limit",
        ));
    }

    let run_root = mount_root.join(RUN_DIRECTORY_NAME);
    create_new_directory(&run_root)?;
    for relative in ["input", "output", "status"] {
        create_new_directory(&run_root.join(relative))?;
    }
    let request_bytes = serde_json::to_vec(request).map_err(|error| {
        SandboxError::with_source("hyperv_data_disk", "serialize guest request", error)
    })?;
    if request_bytes.len() as u64 > guest_protocol::MAX_REQUEST_BYTES {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "serialized guest request exceeds the protocol size limit",
        ));
    }
    let request_sha256 = format!("{:x}", Sha256::digest(&request_bytes));
    guest_protocol::write_atomic_json_new(
        &run_root.join("request.json"),
        request,
        guest_protocol::MAX_REQUEST_BYTES,
    )
    .map_err(|error| SandboxError::new("hyperv_data_disk", error.to_string()))?;

    target.seek(SeekFrom::Start(0)).map_err(|error| {
        SandboxError::with_source("hyperv_data_disk", "rewind pinned target", error)
    })?;
    let target_path = run_root.join(&request.target);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target_path)
        .map_err(|error| {
            SandboxError::with_source("hyperv_data_disk", "create staged target", error)
        })?;
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = target.read(&mut buffer).map_err(|error| {
            let _ = fs::remove_file(&target_path);
            SandboxError::with_source("hyperv_data_disk", "read pinned target", error)
        })?;
        if read == 0 {
            break;
        }
        copied = copied.saturating_add(read as u64);
        if copied > MAX_STAGED_TARGET_BYTES {
            drop(output);
            let _ = fs::remove_file(&target_path);
            return Err(SandboxError::new(
                "hyperv_data_disk",
                "pinned target exceeded the staging limit while copying",
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(|error| {
            let _ = fs::remove_file(&target_path);
            SandboxError::with_source("hyperv_data_disk", "write staged target", error)
        })?;
    }
    if copied != metadata.len() || copied > MAX_STAGED_TARGET_BYTES {
        drop(output);
        let _ = fs::remove_file(&target_path);
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "pinned target changed size or exceeded the staging limit while copying",
        ));
    }
    output.sync_all().map_err(|error| {
        SandboxError::with_source("hyperv_data_disk", "flush staged target", error)
    })?;
    let staged_sha256 = format!("{:x}", hasher.finalize());
    let expected_target_sha256 = request.target_sha256.as_deref().ok_or_else(|| {
        SandboxError::new(
            "hyperv_data_disk",
            "guest request must bind the staged target with a SHA-256 digest",
        )
    })?;
    if !staged_sha256.eq_ignore_ascii_case(expected_target_sha256) {
        drop(output);
        let _ = fs::remove_file(&target_path);
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "staged target bytes do not match the request integrity digest",
        ));
    }
    let status_root = run_root.join("status");
    for (sequence, state) in [
        (1, ProtocolState::HostReady),
        (2, ProtocolState::RequestWritten),
        (3, ProtocolState::StartAllowed),
    ] {
        let mut status = StatusRecord::new(&request.run_id, sequence, state);
        status.request_sha256 = Some(request_sha256.clone());
        status
            .validate()
            .map_err(|error| SandboxError::new("hyperv_data_disk", error.to_string()))?;
        guest_protocol::write_atomic_json_new(
            &status_root.join(state.file_name()),
            &status,
            guest_protocol::MAX_STATUS_BYTES,
        )
        .map_err(|error| SandboxError::new("hyperv_data_disk", error.to_string()))?;
    }
    Ok(request_sha256)
}

fn validate_spec(spec: &RunDataDiskSpec) -> SandboxResult<()> {
    validate_run_id(&spec.run_id)?;
    validate_owned_path(&spec.path, &spec.run_root)?;
    if spec.path.file_name().and_then(|value| value.to_str()) != Some("run-data.vhdx")
        || !spec.mount_path.is_absolute()
        || !paths_equal_normalized(&spec.mount_path, &spec.run_root.join("data-mount"))
        || !(MIN_DATA_DISK_BYTES..=MAX_DATA_DISK_BYTES).contains(&spec.size_bytes)
    {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "run-data disk path, mount path, or size is invalid",
        ));
    }
    Ok(())
}

fn validate_mount(spec: &RunDataDiskSpec, mount: &DataDiskMount, label: &str) -> SandboxResult<()> {
    if !mount.attached
        || mount.label != label
        || mount.vhd_identifier.trim().is_empty()
        || mount.disk_unique_id.trim().is_empty()
        || mount.disk_number == u32::MAX
        || mount.partition_number == 0
        || !paths_equal(Path::new(&mount.path), &spec.path)
        || !paths_equal_normalized(Path::new(&mount.mount_path), &spec.mount_path)
    {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "mounted run-data disk does not match the requested disk",
        ));
    }
    Ok(())
}

fn validate_run_id(run_id: &str) -> SandboxResult<()> {
    if !(16..=64).contains(&run_id.len()) || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SandboxError::new(
            "hyperv_data_disk",
            "run identifier must contain 16 to 64 hexadecimal characters",
        ));
    }
    Ok(())
}

fn create_new_directory(path: &Path) -> SandboxResult<()> {
    fs::create_dir(path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_data_disk",
            format!("create new data-disk directory {}", path.display()),
            error,
        )
    })
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::artifact::windows_paths_equal(left, right)
    }
    #[cfg(not(target_os = "windows"))]
    {
        left == right
    }
}

fn paths_equal_normalized(left: &Path, right: &Path) -> bool {
    let normalize = |path: &Path| {
        let text = path.display().to_string();
        text.trim_end_matches(['/', '\\']).to_string()
    };
    #[cfg(target_os = "windows")]
    {
        normalize(left).eq_ignore_ascii_case(&normalize(right))
    }
    #[cfg(not(target_os = "windows"))]
    {
        normalize(left) == normalize(right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_and_run_ids_are_strict() {
        assert!(validate_run_id("0123456789abcdef").is_ok());
        for invalid in ["short", "../escape0123456789", "gggggggggggggggg"] {
            assert!(validate_run_id(invalid).is_err());
        }
        let root = std::env::temp_dir().join("foxhole-data-spec");
        let spec = RunDataDiskSpec {
            run_id: "0123456789abcdef".into(),
            path: root.join("run-data.vhdx"),
            mount_path: root.join("data-mount"),
            run_root: root,
            size_bytes: MIN_DATA_DISK_BYTES,
        };
        assert!(validate_spec(&spec).is_ok());
    }

    #[test]
    fn remount_and_dismount_scripts_require_both_recorded_disk_identities() {
        for script in [MOUNT_DATA_DISK_SCRIPT, DISMOUNT_DATA_DISK_SCRIPT] {
            assert!(script.contains("expected_vhd_identifier"));
            assert!(script.contains("expected_disk_unique_id"));
            assert!(script.contains("DiskIdentifier"));
            assert!(script.contains("UniqueId"));
        }
    }

    #[test]
    fn fixed_target_path_is_guest_relative() {
        assert_eq!(TARGET_GUEST_PATH, "input/target.bin");
        assert!(!Path::new(TARGET_GUEST_PATH).is_absolute());
        assert_eq!(
            guest_target_path(Path::new(r"C:\samples\script.BAT")),
            TARGET_GUEST_BATCH_PATH
        );
        assert_eq!(
            guest_target_path(Path::new(r"C:\samples\script.cmd")),
            TARGET_GUEST_COMMAND_PATH
        );
        assert_eq!(
            guest_target_path(Path::new(r"C:\samples\program.exe")),
            TARGET_GUEST_PATH
        );
    }
}
