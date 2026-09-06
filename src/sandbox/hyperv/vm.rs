use crate::artifact;
use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::powershell::{
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT, PowerShellExecutor, PowerShellInvocation,
    command_path,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const MIN_STARTUP_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_STARTUP_MEMORY_BYTES: u64 = 32 * 1024 * 1024 * 1024;
pub(crate) const MAX_PROCESSOR_COUNT: u16 = 64;

pub(crate) const CREATE_VM_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$vm = $null
$created = $false
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $module = Get-Module -ListAvailable -Name Hyper-V |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $module) { throw 'Hyper-V PowerShell module was not found' }
    Import-Module -Name $module.Path -ErrorAction Stop
    if ($null -ne (Get-VM -Name ([string]$request.name) -ErrorAction SilentlyContinue)) {
        throw 'A VM with the disposable run name already exists'
    }
    $vm = New-VM -Name ([string]$request.name) -Generation 2 -MemoryStartupBytes ([uint64]$request.startup_memory_bytes) -NoVHD -Path ([string]$request.configuration_path) -ErrorAction Stop
    $created = $true
    $expectedConfigurationRoot = [System.IO.Path]::GetFullPath([string]$request.configuration_path).TrimEnd('\') + '\'
    $actualConfiguration = [System.IO.Path]::GetFullPath([string]$vm.ConfigurationLocation)
    if (-not $actualConfiguration.StartsWith($expectedConfigurationRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Hyper-V created the VM outside the requested run-owned configuration directory'
    }
    Set-VMProcessor -VM $vm -Count ([uint16]$request.processor_count) -EnableHostResourceProtection $true -ExposeVirtualizationExtensions $false -CompatibilityForMigrationEnabled $false -CompatibilityForOlderOperatingSystemsEnabled $false -ErrorAction Stop
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes ([uint64]$request.startup_memory_bytes) -ErrorAction Stop
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType Disabled -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -ErrorAction Stop
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate ([string]$request.secure_boot_template) -ErrorAction Stop
    Get-VMDvdDrive -VM $vm -ErrorAction Stop | Remove-VMDvdDrive -ErrorAction Stop
    $integrationServices = @(Get-VMIntegrationService -VM $vm -ErrorAction Stop)
    foreach ($service in $integrationServices) {
        if ([string]$service.Name -ne 'Heartbeat' -and [bool]$service.Enabled) {
            Disable-VMIntegrationService -VMIntegrationService $service -ErrorAction Stop
        }
    }
    $processor = Get-VMProcessor -VM $vm -ErrorAction Stop
    if (-not [bool]$processor.EnableHostResourceProtection -or [bool]$processor.ExposeVirtualizationExtensions) {
        throw 'Disposable VM processor isolation settings were not applied'
    }
    if (@(Get-VMDvdDrive -VM $vm -ErrorAction Stop).Count -ne 0) {
        throw 'Disposable VM retained an unnecessary virtual DVD drive'
    }
    $enabledIntegrationServices = @(Get-VMIntegrationService -VM $vm -ErrorAction Stop | Where-Object { [bool]$_.Enabled })
    if ($enabledIntegrationServices.Count -ne 1 -or [string]$enabledIntegrationServices[0].Name -ne 'Heartbeat') {
        throw 'Disposable VM retained an unnecessary host integration channel'
    }
    $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    if ($snapshots.Count -ne 0) { throw 'A newly-created disposable VM has unexpected checkpoints' }
    $data = [ordered]@{
        id = [string]$vm.Id
        name = [string]$vm.Name
        generation = [uint16]$vm.Generation
        state = [string]$vm.State
        configuration_path = $actualConfiguration
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 5
} catch {
    $message = $_.Exception.Message
    if ($created -and $null -ne $vm) {
        try {
            if ([string]$vm.State -ne 'Off') {
                Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop
            }
            Remove-VM -VM $vm -Force -ErrorAction Stop
        } catch {
            $message = $message + '; exact partial-VM rollback failed: ' + $_.Exception.Message
        }
    }
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_create_failed'; message = $message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const ATTACH_VM_DISK_SCRIPT: &str = r#"
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
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction Stop
    if ([string]$vm.State -ne 'Off') { throw 'Disks may be attached only while the disposable VM is off' }
    $occupied = @(Get-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber ([uint32]$request.controller_number) -ControllerLocation ([uint32]$request.controller_location) -ErrorAction SilentlyContinue)
    if ($occupied.Count -ne 0) { throw 'The requested SCSI controller location is already occupied' }
    Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber ([uint32]$request.controller_number) -ControllerLocation ([uint32]$request.controller_location) -Path ([string]$request.path) -ErrorAction Stop
    $drive = Get-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber ([uint32]$request.controller_number) -ControllerLocation ([uint32]$request.controller_location) -ErrorAction Stop
    if ([string]$drive.Path -ne [string]$request.path) { throw 'Hyper-V attached a different disk path' }
    $data = [ordered]@{
        path = [string]$drive.Path
        controller_number = [uint32]$drive.ControllerNumber
        controller_location = [uint32]$drive.ControllerLocation
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 5
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_disk_attach_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const START_VM_SCRIPT: &str = r#"
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
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction Stop
    if ([string]$vm.State -ne 'Off') { throw 'Disposable VM must be off before start' }
    if ([bool]$vm.AutomaticCheckpointsEnabled -or [string]$vm.CheckpointType -ne 'Disabled') {
        throw 'Disposable VM checkpoint policy is not disabled'
    }
    $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    if ($snapshots.Count -ne 0) {
        throw 'Disposable VM has a checkpoint before start'
    }
    $vm = Start-VM -VM $vm -PassThru -ErrorAction Stop
    $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $data = [ordered]@{
        exists = $true
        id = [string]$vm.Id
        name = [string]$vm.Name
        state = [string]$vm.State
        snapshot_count = [uint32]$snapshots.Count
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 5
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_start_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const QUERY_VM_SCRIPT: &str = r#"
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
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    if ($null -eq $vm) {
        $data = [ordered]@{
            exists = $false
            id = [string]$request.vm_id
            name = $null
            state = 'Missing'
            snapshot_count = 0
            cpu_usage_percent = 0
            memory_assigned_bytes = 0
            uptime_ms = 0
            health = 'Missing'
            heartbeat_enabled = $false
            heartbeat_primary_status = 'Missing'
            heartbeat_secondary_status = 'Missing'
        }
    } else {
        $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
        $heartbeat = Get-VMIntegrationService -VM $vm -Name 'Heartbeat' -ErrorAction SilentlyContinue
        $data = [ordered]@{
            exists = $true
            id = [string]$vm.Id
            name = [string]$vm.Name
            state = [string]$vm.State
            snapshot_count = [uint32]$snapshots.Count
            cpu_usage_percent = [uint16]$vm.CPUUsage
            memory_assigned_bytes = [uint64]$vm.MemoryAssigned
            uptime_ms = [uint64]$vm.Uptime.TotalMilliseconds
            health = [string]$vm.Status
            heartbeat_enabled = if ($null -eq $heartbeat) { $false } else { [bool]$heartbeat.Enabled }
            heartbeat_primary_status = if ($null -eq $heartbeat) { 'Missing' } else { [string]$heartbeat.PrimaryStatusDescription }
            heartbeat_secondary_status = if ($null -eq $heartbeat) { 'Missing' } else { [string]$heartbeat.SecondaryStatusDescription }
        }
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 5
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_query_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const STOP_VM_SCRIPT: &str = r#"
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
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    if ($null -ne $vm) {
        if ([string]$vm.Name -ne [string]$request.expected_name -or [uint16]$vm.Generation -ne 2) {
            throw 'VM identifier resolves to a different VM identity'
        }
        $expectedRoot = [System.IO.Path]::GetFullPath([string]$request.expected_configuration_root).TrimEnd('\')
        $configuration = [System.IO.Path]::GetFullPath([string]$vm.ConfigurationLocation)
        if (-not $configuration.Equals($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not $configuration.StartsWith($expectedRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'VM identifier resolves outside the recorded run directory'
        }
    }
    if ($null -ne $vm -and [string]$vm.State -ne 'Off') {
        if ([bool]$request.force) {
            Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop
        } else {
            Stop-VM -VM $vm -ErrorAction Stop
        }
    }
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    $state = if ($null -eq $vm) { 'Missing' } else { [string]$vm.State }
    $data = [ordered]@{ stopped = ($state -eq 'Off' -or $state -eq 'Missing'); state = $state }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 4
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_stop_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const DETACH_VM_DISK_SCRIPT: &str = r#"
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
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    $removed = 0
    if ($null -ne $vm) {
        if ([string]$vm.Name -ne [string]$request.expected_name -or [uint16]$vm.Generation -ne 2) {
            throw 'VM identifier resolves to a different VM identity'
        }
        $expectedRoot = [System.IO.Path]::GetFullPath([string]$request.expected_configuration_root).TrimEnd('\')
        $configuration = [System.IO.Path]::GetFullPath([string]$vm.ConfigurationLocation)
        if (-not $configuration.Equals($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not $configuration.StartsWith($expectedRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'VM identifier resolves outside the recorded run directory'
        }
        if ([string]$vm.State -ne 'Off') { throw 'VM disks may be detached only while the VM is off' }
        $drives = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | Where-Object { [string]$_.Path -eq [string]$request.path })
        foreach ($drive in $drives) {
            Remove-VMHardDiskDrive -VMHardDiskDrive $drive -ErrorAction Stop
            $removed++
        }
        if (@(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | Where-Object { [string]$_.Path -eq [string]$request.path }).Count -ne 0) {
            throw 'VM disk remained attached after removal'
        }
    }
    $data = [ordered]@{ detached = $true; removed = [uint32]$removed }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 4
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_disk_detach_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const REMOVE_VM_SCRIPT: &str = r#"
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
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    if ($null -ne $vm) {
        if ([string]$vm.Name -ne [string]$request.expected_name -or [uint16]$vm.Generation -ne 2) {
            throw 'VM identifier resolves to a different VM identity'
        }
        $expectedRoot = [System.IO.Path]::GetFullPath([string]$request.expected_configuration_root).TrimEnd('\')
        $configuration = [System.IO.Path]::GetFullPath([string]$vm.ConfigurationLocation)
        if (-not $configuration.Equals($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not $configuration.StartsWith($expectedRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'VM identifier resolves outside the recorded run directory'
        }
        if ([string]$vm.State -ne 'Off') {
            Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop
        }
        $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
        foreach ($snapshot in $snapshots) {
            Remove-VMSnapshot -VMSnapshot $snapshot -IncludeAllChildSnapshots -Confirm:$false -ErrorAction Stop
        }
        Remove-VM -VM $vm -Force -ErrorAction Stop
    }
    $remaining = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    if ($null -ne $remaining) { throw 'Disposable VM still exists after removal' }
    $data = [ordered]@{ removed = $true }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 4
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'vm_remove_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const REMOVE_PLANNED_VM_SCRIPT: &str = r#"
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
    $name = [string]$request.expected_name
    $runRoot = [System.IO.Path]::GetFullPath([string]$request.run_root).TrimEnd('\') + '\'
    $vms = @(Get-VM -Name $name -ErrorAction SilentlyContinue)
    if ($vms.Count -gt 1) { throw 'Disposable VM name unexpectedly resolved to multiple VMs' }
    foreach ($vm in $vms) {
        if ([string]$vm.Name -ne $name -or [uint16]$vm.Generation -ne 2) {
            throw 'VM lookup returned a different VM identity'
        }
        $configuration = [System.IO.Path]::GetFullPath([string]$vm.ConfigurationLocation)
        if (-not $configuration.StartsWith($runRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a same-named VM outside the recorded run directory'
        }
        if ([string]$vm.State -ne 'Off') {
            Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop
        }
        $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
        foreach ($snapshot in $snapshots) {
            Remove-VMSnapshot -VMSnapshot $snapshot -IncludeAllChildSnapshots -Confirm:$false -ErrorAction Stop
        }
        Remove-VM -VM $vm -Force -ErrorAction Stop
    }
    if ($null -ne (Get-VM -Name $name -ErrorAction SilentlyContinue)) {
        throw 'Planned disposable VM still exists after removal'
    }
    $data = [ordered]@{ removed = $true }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 4
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{ code = 'planned_vm_remove_failed'; message = $_.Exception.Message }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VmSpec {
    pub run_id: String,
    pub name: String,
    pub run_root: PathBuf,
    pub configuration_path: PathBuf,
    pub processor_count: u16,
    pub startup_memory_bytes: u64,
    pub secure_boot_template: String,
}

impl VmSpec {
    pub(crate) fn new(
        run_id: String,
        run_root: PathBuf,
        processor_count: u16,
        startup_memory_bytes: u64,
    ) -> Self {
        let name = format!("foxhole-{run_id}");
        let configuration_path = run_root.join("vm");
        Self {
            run_id,
            name,
            run_root,
            configuration_path,
            processor_count,
            startup_memory_bytes,
            secure_boot_template: "MicrosoftWindows".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmHandle {
    pub id: String,
    pub name: String,
    pub generation: u16,
    pub state: String,
    pub configuration_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmStatus {
    pub exists: bool,
    pub id: String,
    pub name: Option<String>,
    pub state: String,
    pub snapshot_count: u32,
    #[serde(default)]
    pub cpu_usage_percent: u16,
    #[serde(default)]
    pub memory_assigned_bytes: u64,
    #[serde(default)]
    pub uptime_ms: u64,
    #[serde(default)]
    pub health: String,
    #[serde(default)]
    pub heartbeat_enabled: bool,
    #[serde(default)]
    pub heartbeat_primary_status: String,
    #[serde(default)]
    pub heartbeat_secondary_status: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiskRole {
    OperatingSystem,
    RunData,
}

impl DiskRole {
    pub(crate) fn controller_location(self) -> u32 {
        match self {
            Self::OperatingSystem => 0,
            Self::RunData => 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiskAttachment {
    pub path: String,
    pub controller_number: u32,
    pub controller_location: u32,
}

pub(crate) fn create(executor: &dyn PowerShellExecutor, spec: &VmSpec) -> SandboxResult<VmHandle> {
    validate_spec(spec)?;
    std::fs::create_dir(&spec.configuration_path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_vm",
            "create the disposable VM configuration directory",
            error,
        )
    })?;
    let invocation = PowerShellInvocation {
        operation: "create disposable Hyper-V VM",
        script: CREATE_VM_SCRIPT,
        input: serde_json::json!({
            "name": spec.name,
            "configuration_path": command_path(&spec.configuration_path, "VM configuration path")?,
            "processor_count": spec.processor_count,
            "startup_memory_bytes": spec.startup_memory_bytes,
            "secure_boot_template": spec.secure_boot_template,
        }),
        timeout: Duration::from_secs(2 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let handle: VmHandle =
        serde_json::from_value(executor.execute(&invocation)?).map_err(|error| {
            SandboxError::with_source("hyperv_vm", "decode disposable VM identity", error)
        })?;
    if handle.name != spec.name
        || handle.generation != 2
        || !handle.state.eq_ignore_ascii_case("off")
        || !artifact::path_is_within(&handle.configuration_path, &spec.configuration_path)
    {
        return Err(SandboxError::new(
            "hyperv_vm",
            "created VM does not match its Generation 2 disposable specification",
        ));
    }
    validate_vm_id(&handle.id)?;
    Ok(handle)
}

pub(crate) fn attach_disk(
    executor: &dyn PowerShellExecutor,
    vm: &VmHandle,
    path: &Path,
    role: DiskRole,
) -> SandboxResult<DiskAttachment> {
    validate_vm_id(&vm.id)?;
    let invocation = PowerShellInvocation {
        operation: "attach disposable VM disk",
        script: ATTACH_VM_DISK_SCRIPT,
        input: serde_json::json!({
            "vm_id": vm.id,
            "expected_name": vm.name,
            "expected_configuration_root": command_path(
                &vm.configuration_path,
                "VM configuration root",
            )?,
            "path": command_path(path, "VM disk path")?,
            "controller_number": 0,
            "controller_location": role.controller_location(),
        }),
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let attachment: DiskAttachment = serde_json::from_value(executor.execute(&invocation)?)
        .map_err(|error| {
            SandboxError::with_source("hyperv_vm", "decode VM disk attachment", error)
        })?;
    if attachment.controller_number != 0
        || attachment.controller_location != role.controller_location()
        || !paths_equal(Path::new(&attachment.path), path)
    {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM disk was attached at an unexpected path or controller location",
        ));
    }
    Ok(attachment)
}

pub(crate) fn start(executor: &dyn PowerShellExecutor, vm: &VmHandle) -> SandboxResult<VmStatus> {
    validate_vm_id(&vm.id)?;
    let invocation = PowerShellInvocation {
        operation: "start disposable Hyper-V VM",
        script: START_VM_SCRIPT,
        input: serde_json::json!({ "vm_id": vm.id }),
        timeout: Duration::from_secs(2 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let status: VmStatus = serde_json::from_value(executor.execute(&invocation)?)
        .map_err(|error| SandboxError::with_source("hyperv_vm", "decode VM start state", error))?;
    validate_status(vm, &status)?;
    if status.snapshot_count != 0 || status.state.eq_ignore_ascii_case("off") {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM did not enter a running state without checkpoints",
        ));
    }
    Ok(status)
}

pub(crate) fn query(executor: &dyn PowerShellExecutor, vm_id: &str) -> SandboxResult<VmStatus> {
    validate_vm_id(vm_id)?;
    let invocation = PowerShellInvocation {
        operation: "query disposable Hyper-V VM",
        script: QUERY_VM_SCRIPT,
        input: serde_json::json!({ "vm_id": vm_id }),
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let status: VmStatus = serde_json::from_value(executor.execute(&invocation)?)
        .map_err(|error| SandboxError::with_source("hyperv_vm", "decode VM state", error))?;
    if status.id != vm_id {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM query returned a different identifier",
        ));
    }
    Ok(status)
}

pub(crate) fn wait_for_off(
    executor: &dyn PowerShellExecutor,
    vm: &VmHandle,
    timeout: Duration,
) -> SandboxResult<bool> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        let status = query(executor, &vm.id)?;
        if !status.exists || status.state.eq_ignore_ascii_case("off") {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

pub(crate) fn stop(
    executor: &dyn PowerShellExecutor,
    vm: &VmHandle,
    force: bool,
) -> SandboxResult<bool> {
    validate_vm_id(&vm.id)?;
    let invocation = PowerShellInvocation {
        operation: if force {
            "force-stop disposable Hyper-V VM"
        } else {
            "request disposable Hyper-V VM shutdown"
        },
        script: STOP_VM_SCRIPT,
        input: serde_json::json!({
            "vm_id": vm.id,
            "expected_name": vm.name,
            "expected_configuration_root": command_path(
                &vm.configuration_path,
                "VM configuration root",
            )?,
            "force": force,
        }),
        timeout: if force {
            DEFAULT_TIMEOUT
        } else {
            Duration::from_secs(2 * 60)
        },
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let response = executor.execute(&invocation)?;
    response
        .get("stopped")
        .and_then(|value| value.as_bool())
        .ok_or_else(|| {
            SandboxError::new(
                "hyperv_vm",
                "VM stop operation omitted its completion state",
            )
        })
}

pub(crate) fn detach_disk(
    executor: &dyn PowerShellExecutor,
    vm: &VmHandle,
    path: &Path,
) -> SandboxResult<()> {
    validate_vm_id(&vm.id)?;
    let invocation = PowerShellInvocation {
        operation: "detach disposable VM disk",
        script: DETACH_VM_DISK_SCRIPT,
        input: serde_json::json!({
            "vm_id": vm.id,
            "expected_name": vm.name,
            "expected_configuration_root": command_path(
                &vm.configuration_path,
                "VM configuration root",
            )?,
            "path": command_path(path, "VM disk path")?,
        }),
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let response = executor.execute(&invocation)?;
    if response.get("detached").and_then(|value| value.as_bool()) != Some(true) {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM disk detach was not confirmed",
        ));
    }
    Ok(())
}

pub(crate) fn remove(executor: &dyn PowerShellExecutor, vm: &VmHandle) -> SandboxResult<()> {
    validate_vm_id(&vm.id)?;
    let invocation = PowerShellInvocation {
        operation: "remove disposable Hyper-V VM",
        script: REMOVE_VM_SCRIPT,
        input: serde_json::json!({
            "vm_id": vm.id,
            "expected_name": vm.name,
            "expected_configuration_root": command_path(&vm.configuration_path, "VM configuration root")?,
        }),
        timeout: Duration::from_secs(2 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let response = executor.execute(&invocation)?;
    if response.get("removed").and_then(|value| value.as_bool()) != Some(true) {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM removal was not confirmed",
        ));
    }
    Ok(())
}

pub(crate) fn remove_planned(
    executor: &dyn PowerShellExecutor,
    run_id: &str,
    run_root: &Path,
) -> SandboxResult<()> {
    if !(16..=64).contains(&run_id.len()) || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SandboxError::new(
            "hyperv_vm",
            "planned VM run identifier is malformed",
        ));
    }
    if !run_root.is_absolute()
        || run_root.file_name().and_then(|value| value.to_str()) != Some(run_id)
    {
        return Err(SandboxError::new(
            "hyperv_vm",
            "planned VM run root does not match the run identifier",
        ));
    }
    let expected_name = format!("foxhole-{run_id}");
    let invocation = PowerShellInvocation {
        operation: "reconcile planned disposable Hyper-V VM",
        script: REMOVE_PLANNED_VM_SCRIPT,
        input: serde_json::json!({
            "expected_name": expected_name,
            "run_root": command_path(run_root, "planned VM run root")?,
        }),
        timeout: Duration::from_secs(2 * 60),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let response = executor.execute(&invocation)?;
    if response.get("removed").and_then(|value| value.as_bool()) != Some(true) {
        return Err(SandboxError::new(
            "hyperv_vm",
            "planned VM reconciliation was not confirmed",
        ));
    }
    Ok(())
}

fn validate_spec(spec: &VmSpec) -> SandboxResult<()> {
    if !(16..=64).contains(&spec.run_id.len())
        || !spec.run_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || spec.name != format!("foxhole-{}", spec.run_id)
        || spec.name.len() > 80
        || !spec.run_root.is_absolute()
        || !spec.configuration_path.is_absolute()
        || !artifact::path_is_within(&spec.configuration_path, &spec.run_root)
        || !(1..=MAX_PROCESSOR_COUNT).contains(&spec.processor_count)
        || !(MIN_STARTUP_MEMORY_BYTES..=MAX_STARTUP_MEMORY_BYTES)
            .contains(&spec.startup_memory_bytes)
        || !spec.startup_memory_bytes.is_multiple_of(1024 * 1024)
        || spec.secure_boot_template != "MicrosoftWindows"
    {
        return Err(SandboxError::new(
            "hyperv_vm",
            "disposable VM specification violates name, path, CPU, memory, or firmware policy",
        ));
    }
    Ok(())
}

fn validate_vm_id(id: &str) -> SandboxResult<()> {
    if id.len() > 64
        || id.trim().is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b'-' | b'{' | b'}'))
    {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM identifier is empty or malformed",
        ));
    }
    Ok(())
}

fn validate_status(vm: &VmHandle, status: &VmStatus) -> SandboxResult<()> {
    if !status.exists || status.id != vm.id || status.name.as_deref() != Some(vm.name.as_str()) {
        return Err(SandboxError::new(
            "hyperv_vm",
            "VM state refers to a missing or different disposable VM",
        ));
    }
    Ok(())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
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
    use serde_json::Value;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct CapturingPowerShell {
        input: Mutex<Option<Value>>,
    }

    impl PowerShellExecutor for CapturingPowerShell {
        fn execute(&self, invocation: &PowerShellInvocation) -> SandboxResult<Value> {
            *self.input.lock().unwrap() = Some(invocation.input.clone());
            Ok(serde_json::json!({ "stopped": true, "detached": true }))
        }
    }

    #[test]
    fn vm_spec_is_generation_two_and_resource_bounded() {
        let root = std::env::temp_dir().join("foxhole-vm-spec");
        let mut spec = VmSpec::new("0123456789abcdef".into(), root, 2, MIN_STARTUP_MEMORY_BYTES);
        assert!(validate_spec(&spec).is_ok());
        spec.processor_count = 0;
        assert!(validate_spec(&spec).is_err());
        spec.processor_count = 2;
        spec.startup_memory_bytes = MIN_STARTUP_MEMORY_BYTES - 1;
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn disk_roles_have_fixed_non_overlapping_scsi_slots() {
        assert_eq!(DiskRole::OperatingSystem.controller_location(), 0);
        assert_eq!(DiskRole::RunData.controller_location(), 1);
    }

    #[test]
    fn vm_identifier_validation_rejects_command_text() {
        assert!(validate_vm_id("11111111-1111-1111-1111-111111111111").is_ok());
        assert!(validate_vm_id("'; Remove-VM *").is_err());
    }

    #[test]
    fn disposable_vm_script_minimizes_host_integration_and_nested_attack_surface() {
        for required in [
            "-EnableHostResourceProtection $true",
            "-ExposeVirtualizationExtensions $false",
            "Remove-VMDvdDrive",
            "Disable-VMIntegrationService",
            "-EnableSecureBoot On",
            "-CheckpointType Disabled",
        ] {
            assert!(CREATE_VM_SCRIPT.contains(required), "missing {required}");
        }
        assert!(CREATE_VM_SCRIPT.contains("Name -ne 'Heartbeat'"));
    }

    #[test]
    fn stop_binds_the_live_vm_to_recorded_name_generation_and_location() {
        let executor = CapturingPowerShell::default();
        let vm = VmHandle {
            id: "11111111-1111-1111-1111-111111111111".into(),
            name: "foxhole-0123456789abcdef".into(),
            generation: 2,
            state: "Running".into(),
            configuration_path: std::env::temp_dir().join("foxhole-vm-stop/vm"),
        };
        assert!(stop(&executor, &vm, true).unwrap());
        let input = executor.input.lock().unwrap().clone().unwrap();
        assert_eq!(input["vm_id"], vm.id);
        assert_eq!(input["expected_name"], vm.name);
        assert!(input["expected_configuration_root"].is_string());
        for script in [STOP_VM_SCRIPT, DETACH_VM_DISK_SCRIPT] {
            assert!(script.contains("expected_name"));
            assert!(script.contains("expected_configuration_root"));
            assert!(script.contains("Generation"));
            assert!(script.contains("ConfigurationLocation"));
        }
        for script in [REMOVE_VM_SCRIPT, REMOVE_PLANNED_VM_SCRIPT] {
            assert!(script.contains("Generation"));
        }

        let disk = std::env::temp_dir().join("foxhole-vm-stop/run-data.vhdx");
        detach_disk(&executor, &vm, &disk).unwrap();
        let input = executor.input.lock().unwrap().clone().unwrap();
        assert_eq!(input["vm_id"], vm.id);
        assert_eq!(input["expected_name"], vm.name);
        assert!(input["expected_configuration_root"].is_string());
        assert!(input["path"].is_string());
    }
}
