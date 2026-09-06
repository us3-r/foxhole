use crate::artifact;
use crate::host_file::{self, PinnedInputFile};
use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::powershell::{
    DEFAULT_MAX_OUTPUT_BYTES, PowerShellExecutor, PowerShellInvocation, command_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const BASE_IMAGE_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub(crate) const SUPPORTED_GUEST_PROTOCOL_VERSION: u32 = 2;
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub(crate) const DEFAULT_MAX_BASE_IMAGE_BYTES: u64 = 256 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_VIRTUAL_IMAGE_BYTES: u64 = 128 * 1024 * 1024 * 1024;

pub(crate) const INSPECT_BASE_IMAGE_SCRIPT: &str = r#"
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
    [Console]::Error.WriteLine(('[hyperv/base_image debug] inspecting path: ' + $path))
    [Console]::Error.WriteLine('[hyperv/base_image debug] Test-VHD starting')
    $valid = Test-VHD -Path $path -ErrorAction Stop
    [Console]::Error.WriteLine('[hyperv/base_image debug] Get-VHD starting')
    $vhd = Get-VHD -Path $path -ErrorAction Stop
    [Console]::Error.WriteLine(('[hyperv/base_image debug] Hyper-V parent path: ' + [string]$vhd.ParentPath))
    [Console]::Error.WriteLine('[hyperv/base_image debug] Get-FileHash starting')
    $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
    $data = [ordered]@{
        valid = [bool]$valid
        path = [string]$vhd.Path
        vhd_format = [string]$vhd.VhdFormat
        vhd_type = [string]$vhd.VhdType
        attached = [bool]$vhd.Attached
        parent_path = if ([string]::IsNullOrWhiteSpace([string]$vhd.ParentPath)) { $null } else { [string]$vhd.ParentPath }
        size_bytes = [uint64]$vhd.Size
        logical_sector_size = [uint32]$vhd.LogicalSectorSize
        disk_identifier = if ($null -eq $vhd.DiskIdentifier) { $null } else { [string]$vhd.DiskIdentifier }
        sha256 = ([string]$hash.Hash).ToLowerInvariant()
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 6
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'base_image_inspection_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaseImageManifest {
    pub schema_version: u32,
    pub image_version: String,
    pub guest_protocol_version: u32,
    pub vm_generation: u8,
    pub secure_boot_template: String,
    pub sha256: String,
    pub built_at_unix_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BaseImageConfig {
    pub image_path: PathBuf,
    pub manifest_path: PathBuf,
    pub maximum_image_bytes: u64,
    pub maximum_virtual_size_bytes: u64,
    pub required_guest_protocol_version: u32,
}

impl BaseImageConfig {
    pub(crate) fn new(image_path: PathBuf, manifest_path: PathBuf) -> Self {
        Self {
            image_path,
            manifest_path,
            maximum_image_bytes: DEFAULT_MAX_BASE_IMAGE_BYTES,
            maximum_virtual_size_bytes: DEFAULT_MAX_VIRTUAL_IMAGE_BYTES,
            required_guest_protocol_version: SUPPORTED_GUEST_PROTOCOL_VERSION,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaseImageProbe {
    pub valid: bool,
    pub path: String,
    pub vhd_format: String,
    pub vhd_type: String,
    pub attached: bool,
    pub parent_path: Option<String>,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub disk_identifier: Option<String>,
    pub sha256: String,
}

#[derive(Debug)]
pub(crate) struct ValidatedBaseImage {
    pub path: PathBuf,
    pub manifest: BaseImageManifest,
    _probe: BaseImageProbe,
    _pin: PinnedInputFile,
    _directory_pins: Vec<File>,
}

pub(crate) fn inspect(
    executor: &dyn PowerShellExecutor,
    path: &Path,
) -> SandboxResult<BaseImageProbe> {
    let path = command_path(path, "base-image path")?;
    let invocation = PowerShellInvocation {
        operation: "inspect Hyper-V base image",
        script: INSPECT_BASE_IMAGE_SCRIPT,
        input: serde_json::json!({ "path": path }),
        timeout: Duration::from_secs(15 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    serde_json::from_value(executor.execute(&invocation)?).map_err(|error| {
        SandboxError::with_source("hyperv_base_image", "decode base-image inspection", error)
    })
}

pub(crate) fn validate(
    executor: &dyn PowerShellExecutor,
    config: &BaseImageConfig,
) -> SandboxResult<ValidatedBaseImage> {
    validate_config(config)?;
    artifact::validate_absolute_local_path(&config.image_path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "base image must be on an absolute local path",
            error,
        )
    })?;
    artifact::verify_local_fixed_volume(&config.image_path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "base image must be on a fixed local volume",
            error,
        )
    })?;
    let parent = config.image_path.parent().ok_or_else(|| {
        SandboxError::new("hyperv_base_image", "base image has no parent directory")
    })?;
    // Hyper-V must reopen the image by pathname. Pin every ancestor before resolving or
    // inspecting that pathname, then retain those handles for the complete VM lifetime.
    let directory_pins = artifact::pin_safe_directory_tree(parent, false).map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "pin the base-image directory tree",
            error,
        )
    })?;
    println!(
        "[hyperv/base_image debug] opening and pinning base image (limit={} bytes)",
        config.maximum_image_bytes
    );
    let mut pin = host_file::open_pinned_input(&config.image_path, config.maximum_image_bytes)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_base_image",
                format!(
                    "base image is missing or unsafe; provision it at {}",
                    config.image_path.display()
                ),
                error,
            )
        })?;
    let canonical_image = pinned_path(&pin.file, &config.image_path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "resolve the pinned base-image path",
            error,
        )
    })?;
    require_read_only_parent(&pin.file).map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "base image must be marked read-only before it can be used as a parent",
            error,
        )
    })?;
    println!(
        "[hyperv/base_image debug] hashing base image ({} bytes)",
        pin.len
    );
    let pinned_sha256 = hash_pinned_file(&mut pin.file, pin.len).map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "hash the pinned base-image bytes",
            error,
        )
    })?;

    println!("[hyperv/base_image debug] reading and validating manifest");
    let mut manifest_pin = host_file::open_pinned_input(&config.manifest_path, MAX_MANIFEST_BYTES)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_base_image",
                format!(
                    "base-image manifest is missing; provision it at {}",
                    config.manifest_path.display()
                ),
                error,
            )
        })?;
    let mut manifest_bytes = Vec::with_capacity(manifest_pin.len as usize);
    Read::by_ref(&mut manifest_pin.file)
        .take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut manifest_bytes)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_base_image",
                "read the pinned base-image manifest",
                error,
            )
        })?;
    if manifest_bytes.len() as u64 != manifest_pin.len
        || manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES
    {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base-image manifest changed while it was read or exceeded its size limit",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&manifest_bytes);
    let manifest = BaseImageManifest::deserialize(&mut deserializer).map_err(|error| {
        SandboxError::with_source("hyperv_base_image", "parse the base-image manifest", error)
    })?;
    deserializer.end().map_err(|error| {
        SandboxError::with_source(
            "hyperv_base_image",
            "reject trailing base-image manifest data",
            error,
        )
    })?;
    validate_manifest(&manifest, config.required_guest_protocol_version)?;
    if !pinned_sha256.eq_ignore_ascii_case(&manifest.sha256) {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "the pinned base-image bytes do not match the protected manifest hash",
        ));
    }

    // Inspect only after the exact file and every directory component have been pinned.
    println!(
        "[hyperv/base_image debug] invoking Hyper-V VHD inspection for path: {}",
        canonical_image.display()
    );
    let probe = inspect(executor, &canonical_image)?;
    println!("[hyperv/base_image debug] validating Hyper-V VHD inspection result");
    validate_probe(
        &canonical_image,
        &manifest,
        &probe,
        pin.len,
        &pinned_sha256,
        config.maximum_virtual_size_bytes,
    )?;

    Ok(ValidatedBaseImage {
        path: canonical_image,
        manifest,
        _probe: probe,
        _pin: pin,
        _directory_pins: directory_pins,
    })
}

fn pinned_path(file: &File, requested: &Path) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let _ = requested;
        artifact::final_path_by_handle(file)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = file;
        requested.canonicalize()
    }
}

fn hash_pinned_file(file: &mut File, expected_len: u64) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut reader = file.take(expected_len.saturating_add(1));
    let copied = std::io::copy(&mut reader, &mut hasher)?;
    if copied != expected_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "base image changed while it was hashed",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn require_read_only_parent(file: &File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        if metadata.file_attributes() & FILE_ATTRIBUTE_READONLY == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the VHDX read-only file attribute is not set",
            ));
        }
    }
    #[cfg(not(target_os = "windows"))]
    if !metadata.permissions().readonly() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the VHDX file permissions are writable",
        ));
    }
    Ok(())
}

fn paths_refer_to_same_location(left: &Path, right: &Path) -> SandboxResult<bool> {
    #[cfg(target_os = "windows")]
    {
        Ok(artifact::windows_paths_equal(left, right))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let reported = left.canonicalize().map_err(|error| {
            SandboxError::with_source(
                "hyperv_base_image",
                "canonicalize the path reported by Hyper-V",
                error,
            )
        })?;
        Ok(reported == right)
    }
}

fn validate_config(config: &BaseImageConfig) -> SandboxResult<()> {
    if config.maximum_image_bytes == 0
        || config.maximum_virtual_size_bytes == 0
        || config.required_guest_protocol_version == 0
    {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base-image limits and guest protocol version must be non-zero",
        ));
    }
    if !config.image_path.is_absolute() || !config.manifest_path.is_absolute() {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base-image and manifest paths must be absolute",
        ));
    }
    if !config
        .image_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("vhdx"))
    {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base image must use the VHDX format",
        ));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &BaseImageManifest,
    required_guest_protocol_version: u32,
) -> SandboxResult<()> {
    if manifest.schema_version != BASE_IMAGE_MANIFEST_SCHEMA_VERSION {
        return Err(SandboxError::new(
            "hyperv_base_image",
            format!(
                "unsupported base-image manifest schema {}",
                manifest.schema_version
            ),
        ));
    }
    if manifest.guest_protocol_version != required_guest_protocol_version {
        return Err(SandboxError::new(
            "hyperv_base_image",
            format!(
                "base image guest protocol {} is incompatible with required protocol {}",
                manifest.guest_protocol_version, required_guest_protocol_version
            ),
        ));
    }
    if manifest.vm_generation != 2 {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base image must target a Generation 2 VM",
        ));
    }
    if manifest.image_version.trim().is_empty()
        || manifest.secure_boot_template != "MicrosoftWindows"
        || !is_sha256(&manifest.sha256)
        || manifest.built_at_unix_secs == 0
    {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base-image manifest has invalid version, Secure Boot, hash, or build metadata",
        ));
    }
    Ok(())
}

fn validate_probe(
    canonical_image: &Path,
    manifest: &BaseImageManifest,
    probe: &BaseImageProbe,
    file_size: u64,
    pinned_sha256: &str,
    maximum_virtual_size_bytes: u64,
) -> SandboxResult<()> {
    let valid_geometry = probe.valid
        && probe.vhd_format.eq_ignore_ascii_case("vhdx")
        && matches!(
            probe.vhd_type.to_ascii_lowercase().as_str(),
            "fixed" | "dynamic"
        )
        && !probe.attached
        && probe.parent_path.is_none()
        && probe.size_bytes != 0
        && probe.size_bytes <= maximum_virtual_size_bytes
        && probe.logical_sector_size != 0
        && probe.sha256.eq_ignore_ascii_case(&manifest.sha256)
        && probe.sha256.eq_ignore_ascii_case(pinned_sha256);
    if !valid_geometry {
        println!(
            "[hyperv/base_image debug] probe mismatch: valid={} format={} type={} attached={} parent_present={} size={} sector={} probe_hash_match_manifest={} probe_hash_match_pinned={}",
            probe.valid,
            probe.vhd_format,
            probe.vhd_type,
            probe.attached,
            probe.parent_path.is_some(),
            probe.size_bytes,
            probe.logical_sector_size,
            probe.sha256.eq_ignore_ascii_case(&manifest.sha256),
            probe.sha256.eq_ignore_ascii_case(pinned_sha256),
        );
        return Err(SandboxError::new(
            "hyperv_base_image",
            "base image failed VHDX type, attachment, parent, geometry, or hash validation",
        ));
    }
    if !paths_refer_to_same_location(Path::new(&probe.path), canonical_image)? || file_size == 0 {
        return Err(SandboxError::new(
            "hyperv_base_image",
            "Hyper-V inspected a different or empty base-image file",
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> BaseImageManifest {
        BaseImageManifest {
            schema_version: 1,
            image_version: "1.0.0".into(),
            guest_protocol_version: 1,
            vm_generation: 2,
            secure_boot_template: "MicrosoftWindows".into(),
            sha256: "a".repeat(64),
            built_at_unix_secs: 1,
        }
    }

    #[test]
    fn manifest_validation_fails_closed() {
        let mut manifest = valid_manifest();
        assert!(validate_manifest(&manifest, 1).is_ok());
        manifest.vm_generation = 1;
        assert!(validate_manifest(&manifest, 1).is_err());
        manifest = valid_manifest();
        manifest.guest_protocol_version = 2;
        assert!(validate_manifest(&manifest, 1).is_err());
        manifest = valid_manifest();
        manifest.sha256 = "../not-a-hash".into();
        assert!(validate_manifest(&manifest, 1).is_err());

        let mut value = serde_json::to_value(valid_manifest()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BaseImageManifest>(value).is_err());
    }

    #[test]
    fn config_requires_absolute_vhdx_paths() {
        let config = BaseImageConfig::new("base.vhdx".into(), "base.json".into());
        assert!(validate_config(&config).is_err());
        let config = BaseImageConfig::new(
            std::env::temp_dir().join("base.vhd"),
            std::env::temp_dir().join("base.json"),
        );
        assert!(validate_config(&config).is_err());
    }
}
