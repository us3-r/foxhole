use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::powershell::{PowerShellExecutor, PowerShellInvocation};
use serde::{Deserialize, Serialize};

pub(crate) const REQUIRED_CMDLETS: &[&str] = &[
    "Get-VMHost",
    "Get-VM",
    "New-VM",
    "Set-VM",
    "Set-VMProcessor",
    "Set-VMMemory",
    "Set-VMFirmware",
    "Start-VM",
    "Stop-VM",
    "Remove-VM",
    "Get-VHD",
    "New-VHD",
    "Mount-VHD",
    "Dismount-VHD",
    "Add-VMHardDiskDrive",
    "Remove-VMHardDiskDrive",
    "Get-VMHardDiskDrive",
    "Get-VMNetworkAdapter",
    "Get-VMIntegrationService",
    "Add-VMNetworkAdapter",
    "Remove-VMNetworkAdapter",
    "Get-VMSwitch",
    "Get-VMSnapshot",
    "Remove-VMSnapshot",
    "Get-Disk",
    "Initialize-Disk",
    "Get-Partition",
    "New-Partition",
    "Add-PartitionAccessPath",
    "Remove-PartitionAccessPath",
    "Format-Volume",
    "Get-Volume",
];

/// Additional, narrowly-scoped commands needed only when controlled networking is requested.
/// Keeping these separate preserves the historical deny-all capability boundary.
pub(crate) const CONTROLLED_NETWORK_CMDLETS: &[&str] = &[
    "Get-NetAdapter",
    "Get-NetAdapterBinding",
    "Get-NetIPAddress",
    "Get-NetNat",
    "Get-NetNatStaticMapping",
    "Get-NetRoute",
    "Get-NetTCPConnection",
    "Get-NetFirewallRule",
    "New-NetFirewallRule",
    "Remove-NetFirewallRule",
    "Get-NetFirewallAddressFilter",
    "Get-NetFirewallPortFilter",
    "Get-NetFirewallInterfaceFilter",
    "Get-VMNetworkAdapterExtendedAcl",
    "Add-VMNetworkAdapterExtendedAcl",
    "Remove-VMNetworkAdapterExtendedAcl",
    "Get-NetEventSession",
    "New-NetEventSession",
    "Add-NetEventPacketCaptureProvider",
    "Get-NetEventPacketCaptureProvider",
    "Start-NetEventSession",
    "Stop-NetEventSession",
    "Remove-NetEventSession",
];

pub(crate) const DETECT_CAPABILITY_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $null = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $issues = New-Object System.Collections.Generic.List[object]
    $featureEnabled = $false
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
        $featureEnabled = $feature.State -eq 'Enabled'
        if (-not $featureEnabled) {
            $issues.Add([ordered]@{ code = 'feature_disabled'; message = 'Microsoft-Hyper-V-All is not enabled' })
        }
    } catch {
        $issues.Add([ordered]@{ code = 'feature_probe_failed'; message = $_.Exception.Message })
    }

    $vmmsRunning = $false
    try {
        $service = Get-Service -Name vmms -ErrorAction Stop
        $vmmsRunning = $service.Status -eq 'Running'
        if (-not $vmmsRunning) {
            $issues.Add([ordered]@{ code = 'service_not_running'; message = 'Hyper-V Virtual Machine Management is not running' })
        }
    } catch {
        $issues.Add([ordered]@{ code = 'service_missing'; message = $_.Exception.Message })
    }

    $hypervisorPresent = $false
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hypervisorPresent = [bool]$computer.HypervisorPresent
        if (-not $hypervisorPresent) {
            $issues.Add([ordered]@{ code = 'hypervisor_absent'; message = 'Windows does not report an active hypervisor' })
        }
    } catch {
        $issues.Add([ordered]@{ code = 'hypervisor_probe_failed'; message = $_.Exception.Message })
    }

    $moduleVersion = $null
    $missing = New-Object System.Collections.Generic.List[string]
    $networkMissing = New-Object System.Collections.Generic.List[string]
    $managementAccess = $false
    try {
        $module = Get-Module -ListAvailable -Name Hyper-V |
            Sort-Object Version -Descending |
            Select-Object -First 1
        if ($null -eq $module) {
            throw 'Hyper-V PowerShell module was not found'
        }
        Import-Module -Name $module.Path -PassThru -ErrorAction Stop | Out-Null
        $moduleVersion = [string]$module.Version
        $required = @(
            'Get-VMHost','Get-VM','New-VM','Set-VM','Set-VMProcessor','Set-VMMemory',
            'Set-VMFirmware','Start-VM','Stop-VM','Remove-VM',
            'Get-VHD','New-VHD','Mount-VHD','Dismount-VHD','Add-VMHardDiskDrive',
            'Remove-VMHardDiskDrive','Get-VMHardDiskDrive','Get-VMNetworkAdapter','Get-VMIntegrationService',
            'Add-VMNetworkAdapter','Remove-VMNetworkAdapter','Get-VMSwitch',
            'Get-VMSnapshot','Remove-VMSnapshot','Get-Disk','Initialize-Disk','Get-Partition',
            'New-Partition','Add-PartitionAccessPath','Remove-PartitionAccessPath',
            'Format-Volume','Get-Volume'
        )
        foreach ($name in $required) {
            if ($null -eq (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
                $missing.Add($name)
            }
        }
        if ($missing.Count -gt 0) {
            $issues.Add([ordered]@{ code = 'cmdlets_missing'; message = ('Missing Hyper-V cmdlets: ' + ($missing -join ', ')) })
        }
        $networkRequired = @(
            'Get-NetAdapter','Get-NetAdapterBinding','Get-NetIPAddress','Get-NetNat','Get-NetNatStaticMapping','Get-NetRoute','Get-NetTCPConnection',
            'Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Get-NetFirewallAddressFilter',
            'Get-NetFirewallPortFilter','Get-NetFirewallInterfaceFilter',
            'Get-VMNetworkAdapterExtendedAcl','Add-VMNetworkAdapterExtendedAcl','Remove-VMNetworkAdapterExtendedAcl',
            'Get-NetEventSession','New-NetEventSession','Add-NetEventPacketCaptureProvider','Get-NetEventPacketCaptureProvider',
            'Start-NetEventSession','Stop-NetEventSession','Remove-NetEventSession'
        )
        foreach ($name in $networkRequired) {
            if ($null -eq (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
                $networkMissing.Add($name)
            }
        }
        try {
            $null = Get-VMHost -ErrorAction Stop
            $managementAccess = $true
        } catch {
            $issues.Add([ordered]@{ code = 'management_access_denied'; message = $_.Exception.Message })
        }
    } catch {
        $issues.Add([ordered]@{ code = 'module_unavailable'; message = $_.Exception.Message })
    }

    $available = $featureEnabled -and $vmmsRunning -and $hypervisorPresent -and
        $managementAccess -and ($missing.Count -eq 0)
    $data = [ordered]@{
        available = [bool]$available
        platform_supported = $true
        hypervisor_present = [bool]$hypervisorPresent
        feature_enabled = [bool]$featureEnabled
        vmms_running = [bool]$vmmsRunning
        management_access = [bool]$managementAccess
        module_version = $moduleVersion
        missing_cmdlets = @($missing.ToArray())
        network_missing_cmdlets = @($networkMissing.ToArray())
        issues = @($issues.ToArray())
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } |
        ConvertTo-Json -Compress -Depth 8
} catch {
    [ordered]@{
        schema_version = 1
        ok = $false
        error = [ordered]@{
            code = 'capability_probe_failed'
            message = ('{0} at line {1}: {2}' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.PositionMessage)
        }
    } | ConvertTo-Json -Compress -Depth 5
}
"#;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityIssue {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    pub available: bool,
    pub platform_supported: bool,
    pub hypervisor_present: bool,
    pub feature_enabled: bool,
    pub vmms_running: bool,
    pub management_access: bool,
    pub module_version: Option<String>,
    #[serde(default)]
    pub missing_cmdlets: Vec<String>,
    #[serde(default)]
    pub network_missing_cmdlets: Vec<String>,
    #[serde(default)]
    pub issues: Vec<CapabilityIssue>,
}

impl CapabilityReport {
    pub fn unsupported_platform() -> Self {
        Self {
            available: false,
            platform_supported: false,
            hypervisor_present: false,
            feature_enabled: false,
            vmms_running: false,
            management_access: false,
            module_version: None,
            missing_cmdlets: REQUIRED_CMDLETS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            network_missing_cmdlets: CONTROLLED_NETWORK_CMDLETS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            issues: vec![CapabilityIssue {
                code: "unsupported_platform".to_string(),
                message: "Hyper-V is supported only on Windows hosts".to_string(),
            }],
        }
    }

    pub fn require_available(&self) -> SandboxResult<()> {
        if self.available
            && self.platform_supported
            && self.hypervisor_present
            && self.feature_enabled
            && self.vmms_running
            && self.management_access
            && self.missing_cmdlets.is_empty()
        {
            return Ok(());
        }
        let details = if self.issues.is_empty() {
            "the capability report is internally inconsistent".to_string()
        } else {
            self.issues
                .iter()
                .map(|issue| format!("{}: {}", issue.code, issue.message))
                .collect::<Vec<_>>()
                .join("; ")
        };
        Err(SandboxError::new(
            "hyperv_capability",
            format!("Hyper-V is unavailable: {details}"),
        ))
    }

    pub fn require_controlled_network_available(&self) -> SandboxResult<()> {
        self.require_available()?;
        if self.network_missing_cmdlets.is_empty() {
            return Ok(());
        }
        Err(SandboxError::new(
            "hyperv_network_capability",
            format!(
                "controlled Hyper-V networking is unavailable because required commands are missing: {}",
                self.network_missing_cmdlets.join(", ")
            ),
        ))
    }
}

pub(crate) fn detect(executor: &dyn PowerShellExecutor) -> SandboxResult<CapabilityReport> {
    let invocation = PowerShellInvocation::new(
        "detect Hyper-V capability",
        DETECT_CAPABILITY_SCRIPT,
        serde_json::json!({}),
    );
    let value = executor.execute(&invocation)?;
    let report: CapabilityReport = serde_json::from_value(value).map_err(|error| {
        SandboxError::with_source(
            "hyperv_capability",
            "decode the Hyper-V capability report",
            error,
        )
    })?;
    if report.missing_cmdlets.iter().any(|missing| {
        !REQUIRED_CMDLETS
            .iter()
            .any(|required| required == &missing.as_str())
    }) {
        return Err(SandboxError::new(
            "hyperv_capability",
            "capability report contains an unexpected cmdlet name",
        ));
    }
    if report.network_missing_cmdlets.iter().any(|missing| {
        !CONTROLLED_NETWORK_CMDLETS
            .iter()
            .any(|required| required == &missing.as_str())
    }) {
        return Err(SandboxError::new(
            "hyperv_capability",
            "capability report contains an unexpected controlled-network cmdlet name",
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconsistent_or_failed_reports_fail_closed() {
        let mut report = CapabilityReport {
            available: true,
            platform_supported: true,
            hypervisor_present: true,
            feature_enabled: true,
            vmms_running: true,
            management_access: true,
            module_version: Some("1.0".into()),
            missing_cmdlets: Vec::new(),
            network_missing_cmdlets: Vec::new(),
            issues: Vec::new(),
        };
        assert!(report.require_available().is_ok());
        report.vmms_running = false;
        assert!(report.require_available().is_err());
    }

    #[test]
    fn unsupported_platform_names_every_missing_control() {
        let report = CapabilityReport::unsupported_platform();
        assert!(!report.available);
        assert!(!report.platform_supported);
        assert_eq!(report.missing_cmdlets.len(), REQUIRED_CMDLETS.len());
        assert!(report.require_available().is_err());
    }

    #[test]
    fn native_probe_checks_every_cmdlet_used_by_the_host_modules() {
        for required in REQUIRED_CMDLETS
            .iter()
            .chain(CONTROLLED_NETWORK_CMDLETS.iter())
        {
            assert!(
                DETECT_CAPABILITY_SCRIPT.contains(&format!("'{required}'")),
                "capability script omitted {required}"
            );
        }
    }
}
