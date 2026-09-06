use crate::artifact;
use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::powershell::{
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT, PowerShellExecutor, PowerShellInvocation,
    command_path,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const CREATE_DIFFERENCING_DISK_SCRIPT: &str = r#"
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
    $parent = [string]$request.parent_path
    if ([System.IO.File]::Exists($path) -or [System.IO.Directory]::Exists($path)) {
        throw 'The differencing-disk destination already exists'
    }
    $null = New-VHD -Path $path -ParentPath $parent -Differencing -ErrorAction Stop
    $vhd = Get-VHD -Path $path -ErrorAction Stop
    $data = [ordered]@{
        path = [string]$vhd.Path
        vhd_format = [string]$vhd.VhdFormat
        vhd_type = [string]$vhd.VhdType
        attached = [bool]$vhd.Attached
        parent_path = if ([string]::IsNullOrWhiteSpace([string]$vhd.ParentPath)) { $null } else { [string]$vhd.ParentPath }
        size_bytes = [uint64]$vhd.Size
        logical_sector_size = [uint32]$vhd.LogicalSectorSize
        disk_identifier = if ($null -eq $vhd.DiskIdentifier) { $null } else { [string]$vhd.DiskIdentifier }
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 6
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'differencing_disk_create_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const INSPECT_VHD_SCRIPT: &str = r#"
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
    $vhd = Get-VHD -Path ([string]$request.path) -ErrorAction Stop
    $data = [ordered]@{
        path = [string]$vhd.Path
        vhd_format = [string]$vhd.VhdFormat
        vhd_type = [string]$vhd.VhdType
        attached = [bool]$vhd.Attached
        parent_path = if ([string]::IsNullOrWhiteSpace([string]$vhd.ParentPath)) { $null } else { [string]$vhd.ParentPath }
        size_bytes = [uint64]$vhd.Size
        logical_sector_size = [uint32]$vhd.LogicalSectorSize
        disk_identifier = if ($null -eq $vhd.DiskIdentifier) { $null } else { [string]$vhd.DiskIdentifier }
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 6
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vhd_inspection_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VhdInfo {
    pub path: String,
    pub vhd_format: String,
    pub vhd_type: String,
    pub attached: bool,
    pub parent_path: Option<String>,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub disk_identifier: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DifferencingDiskSpec {
    pub run_root: PathBuf,
    pub path: PathBuf,
    pub parent_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DifferencingDisk {
    pub path: PathBuf,
    pub parent_path: PathBuf,
    pub disk_identifier: Option<String>,
    pub size_bytes: u64,
}

pub(crate) fn create_differencing_disk(
    executor: &dyn PowerShellExecutor,
    spec: &DifferencingDiskSpec,
) -> SandboxResult<DifferencingDisk> {
    validate_spec(spec)?;
    if spec.path.exists() {
        return Err(SandboxError::new(
            "hyperv_disk",
            "differencing-disk destination already exists",
        ));
    }
    let path = command_path(&spec.path, "differencing-disk path")?;
    let parent = command_path(&spec.parent_path, "base-image parent path")?;
    let invocation = PowerShellInvocation {
        operation: "create Hyper-V differencing disk",
        script: CREATE_DIFFERENCING_DISK_SCRIPT,
        input: serde_json::json!({ "path": path, "parent_path": parent }),
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let info: VhdInfo =
        serde_json::from_value(executor.execute(&invocation)?).map_err(|error| {
            SandboxError::with_source("hyperv_disk", "decode differencing-disk metadata", error)
        })?;
    validate_created_disk(spec, &info)?;
    Ok(DifferencingDisk {
        path: spec.path.clone(),
        parent_path: spec.parent_path.clone(),
        disk_identifier: info.disk_identifier,
        size_bytes: info.size_bytes,
    })
}

pub(crate) fn inspect_vhd(
    executor: &dyn PowerShellExecutor,
    path: &Path,
) -> SandboxResult<VhdInfo> {
    let invocation = PowerShellInvocation {
        operation: "inspect Hyper-V disk",
        script: INSPECT_VHD_SCRIPT,
        input: serde_json::json!({ "path": command_path(path, "VHDX path")? }),
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    serde_json::from_value(executor.execute(&invocation)?)
        .map_err(|error| SandboxError::with_source("hyperv_disk", "decode VHDX metadata", error))
}

pub(crate) fn delete_owned_disk(
    executor: &dyn PowerShellExecutor,
    path: &Path,
    run_root: &Path,
    expected_identifier: &str,
) -> SandboxResult<()> {
    validate_owned_path(path, run_root)?;
    if expected_identifier.trim().is_empty() {
        return Err(SandboxError::new(
            "hyperv_disk_cleanup",
            "refusing to delete a VHDX without its recorded disk identifier",
        ));
    }
    let inspected_file =
        artifact::open_safe_regular_file_for_external_inspection(path).map_err(|error| {
            SandboxError::with_source(
                "hyperv_disk_cleanup",
                "open the owned VHDX for identity-preserving inspection",
                error,
            )
        })?;
    let info = inspect_vhd(executor, path)?;
    let file = artifact::open_safe_regular_file_for_delete_matching(path, &inspected_file)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_disk_cleanup",
                "reopen the inspected VHDX for deletion without an identity change",
                error,
            )
        })?;
    if info.attached
        || !info.vhd_format.eq_ignore_ascii_case("vhdx")
        || !paths_equal_lexically(Path::new(&info.path), path)
        || !info
            .disk_identifier
            .as_deref()
            .is_some_and(|observed| observed.eq_ignore_ascii_case(expected_identifier))
    {
        return Err(SandboxError::new(
            "hyperv_disk_cleanup",
            "refusing to delete a VHDX whose path, attachment state, or disk identity does not match the recorded run resource",
        ));
    }
    artifact::delete_open_file(&file, path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_disk_cleanup",
            format!("delete owned disk by verified handle {}", path.display()),
            error,
        )
    })
}

pub(crate) fn validate_owned_path(path: &Path, run_root: &Path) -> SandboxResult<()> {
    let direct_parent = path
        .parent()
        .is_some_and(|parent| paths_equal_lexically(parent, run_root));
    let expected_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("os-diff.vhdx") || name.eq_ignore_ascii_case("run-data.vhdx")
        });
    if !path.is_absolute()
        || !run_root.is_absolute()
        || path == run_root
        || !artifact::path_is_within(path, run_root)
        || !direct_parent
        || !expected_name
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SandboxError::new(
            "hyperv_disk",
            "owned disk path is not an exact direct VHDX child of the per-run root",
        ));
    }
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("vhdx"))
    {
        return Err(SandboxError::new(
            "hyperv_disk",
            "owned disk must use a .vhdx extension",
        ));
    }
    Ok(())
}

fn validate_spec(spec: &DifferencingDiskSpec) -> SandboxResult<()> {
    validate_owned_path(&spec.path, &spec.run_root)?;
    if !spec.parent_path.is_absolute()
        || spec.parent_path == spec.path
        || artifact::path_is_within(&spec.parent_path, &spec.run_root)
    {
        return Err(SandboxError::new(
            "hyperv_disk",
            "base-image parent must be an absolute path outside the per-run root",
        ));
    }
    Ok(())
}

fn validate_created_disk(spec: &DifferencingDiskSpec, info: &VhdInfo) -> SandboxResult<()> {
    let reported = Path::new(&info.path);
    let reported_parent = info.parent_path.as_deref().map(Path::new);
    if !info.vhd_format.eq_ignore_ascii_case("vhdx")
        || !info.vhd_type.eq_ignore_ascii_case("differencing")
        || info.attached
        || info.size_bytes == 0
        || info.logical_sector_size == 0
        || !paths_equal_lexically(reported, &spec.path)
        || !reported_parent.is_some_and(|parent| paths_equal_lexically(parent, &spec.parent_path))
    {
        return Err(SandboxError::new(
            "hyperv_disk",
            "created VHDX does not match the requested differencing disk and parent",
        ));
    }
    Ok(())
}

fn paths_equal_lexically(left: &Path, right: &Path) -> bool {
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

    #[derive(Debug)]
    struct InspectingPowerShell {
        path: String,
        disk_identifier: String,
    }

    impl PowerShellExecutor for InspectingPowerShell {
        fn execute(&self, _invocation: &PowerShellInvocation) -> SandboxResult<serde_json::Value> {
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::OpenOptionsExt;

                // Model Get-VHD opening the pathname without sharing a pre-existing DELETE
                // request. The cleanup code must not hold DELETE access during this callback.
                std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0x0000_0001 | 0x0000_0002)
                    .open(&self.path)
                    .map_err(|error| {
                        SandboxError::with_source(
                            "test_vhd_inspection",
                            "reopen VHDX while the cleanup inspection pin is held",
                            error,
                        )
                    })?;
            }
            Ok(serde_json::json!({
                "path": self.path,
                "vhd_format": "VHDX",
                "vhd_type": "Dynamic",
                "attached": false,
                "parent_path": null,
                "size_bytes": 1,
                "logical_sector_size": 512,
                "disk_identifier": self.disk_identifier,
            }))
        }
    }

    #[test]
    fn owned_paths_must_be_contained_vhdx_files() {
        let root = std::env::temp_dir().join("foxhole-disk-test");
        assert!(validate_owned_path(&root.join("os-diff.vhdx"), &root).is_ok());
        assert!(validate_owned_path(&root.join("run-data.vhdx"), &root).is_ok());
        assert!(validate_owned_path(&root, &root).is_err());
        assert!(validate_owned_path(&root.join("../escape.vhdx"), &root).is_err());
        assert!(validate_owned_path(&root.join("disk.avhdx"), &root).is_err());
        assert!(validate_owned_path(&root.join("nested/os-diff.vhdx"), &root).is_err());
    }

    #[test]
    fn created_disk_metadata_must_match_exactly() {
        let root = std::env::temp_dir().join("foxhole-disk-metadata");
        let spec = DifferencingDiskSpec {
            path: root.join("os-diff.vhdx"),
            parent_path: std::env::temp_dir().join("base.vhdx"),
            run_root: root,
        };
        let mut info = VhdInfo {
            path: spec.path.display().to_string(),
            vhd_format: "VHDX".into(),
            vhd_type: "Differencing".into(),
            attached: false,
            parent_path: Some(spec.parent_path.display().to_string()),
            size_bytes: 1,
            logical_sector_size: 512,
            disk_identifier: Some("id".into()),
        };
        assert!(validate_created_disk(&spec, &info).is_ok());
        info.attached = true;
        assert!(validate_created_disk(&spec, &info).is_err());
    }

    #[test]
    fn deletion_preserves_a_vhdx_when_the_recorded_identity_does_not_match() {
        let root =
            std::env::temp_dir().join(format!("foxhole-disk-delete-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let path = root.join("os-diff.vhdx");
        std::fs::write(&path, b"sentinel").unwrap();
        let executor = InspectingPowerShell {
            path: path.display().to_string(),
            disk_identifier: "observed-identifier".into(),
        };

        assert!(delete_owned_disk(&executor, &path, &root, "recorded-identifier").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"sentinel");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn deletion_does_not_self_lock_vhd_inspection() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-disk-self-lock-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let path = root.join("run-data.vhdx");
        std::fs::write(&path, b"sentinel").unwrap();
        let executor = InspectingPowerShell {
            path: path.display().to_string(),
            disk_identifier: "recorded-identifier".into(),
        };

        delete_owned_disk(&executor, &path, &root, "recorded-identifier")
            .expect("inspection must complete before the delete-access handle is opened");
        assert!(!path.exists());

        std::fs::remove_dir_all(root).unwrap();
    }
}
