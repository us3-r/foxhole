use crate::artifact;
use crate::sandbox::backend::{
    HyperVNetworkMetadata, HyperVNetworkVerification, NetworkPolicy, SandboxError, SandboxResult,
};
use crate::sandbox::hyperv::guest_protocol::GuestNetworkAttestation;
use crate::sandbox::hyperv::powershell::{
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT, PowerShellExecutor, PowerShellInvocation,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub(crate) const CONFIGURE_DENY_ALL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $module = Get-Module -ListAvailable -Name Hyper-V | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $module) { throw 'Hyper-V PowerShell module was not found' }
    Import-Module -Name $module.Path -ErrorAction Stop
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction Stop
    if ([bool]$request.configure) {
        @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop) | ForEach-Object {
            Remove-VMNetworkAdapter -VMNetworkAdapter $_ -ErrorAction Stop
        }
    }
    $remaining = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    if ($remaining.Count -ne 0) { throw 'DenyAll requires zero virtual network adapters' }
    $data = [ordered]@{
        adapter_count = 0; switch_id = $null; switch_type = $null; host_adapter_id = $null
        host_ipv4 = $null; guest_ipv4 = $null; nat_enabled = $false; firewall_rule_ids = @()
        capture_active = $false; ipv6_disabled = $true; no_unexpected_routes = $true; warnings = @()
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } | ConvertTo-Json -Compress -Depth 6
} catch {
    [ordered]@{ schema_version = 1; ok = $false; error = [ordered]@{
        code = 'network_deny_all_failed'; message = $_.Exception.Message
    }} | ConvertTo-Json -Compress -Depth 5
}
"#;

pub(crate) const CONTROLLED_NETWORK_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function Require-Command([string]$Name) {
    if ($null -eq (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { throw "Required command is unavailable: $Name" }
}
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    foreach ($name in @('Get-VM','Get-VMSwitch','Get-VMNetworkAdapter','Add-VMNetworkAdapter','Remove-VMNetworkAdapter',
        'Get-VMNetworkAdapterExtendedAcl','Add-VMNetworkAdapterExtendedAcl','Remove-VMNetworkAdapterExtendedAcl',
        'Get-NetAdapter','Get-NetAdapterBinding','Get-NetIPAddress','Get-NetNat','Get-NetNatStaticMapping','Get-NetRoute',
        'Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Get-NetFirewallAddressFilter',
        'Get-NetFirewallPortFilter','Get-NetFirewallInterfaceFilter')) { Require-Command $name }
    $module = Get-Module -ListAvailable -Name Hyper-V | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $module) { throw 'Hyper-V PowerShell module was not found' }
    Import-Module -Name $module.Path -ErrorAction Stop
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction Stop
    $switch = Get-VMSwitch -Name ([string]$request.switch_name) -ErrorAction Stop
    if ([string]$switch.Id -ne [string]$request.switch_id -or [string]$switch.SwitchType -ne [string]$request.switch_type -or
        [string]$switch.SwitchType -eq 'External' -or [string]$switch.Name -eq 'Default Switch') {
        throw 'Switch identity or type does not match the controlled plan'
    }
    if ([bool]$request.configure_adapter) {
        @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop) | ForEach-Object {
            Remove-VMNetworkAdapter -VMNetworkAdapter $_ -ErrorAction Stop
        }
        Add-VMNetworkAdapter -VM $vm -Name 'Foxhole Controlled Adapter' -SwitchName ([string]$switch.Name) -ErrorAction Stop
    }
    $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    if ($adapters.Count -ne 1 -or [string]$adapters[0].SwitchId -ne [string]$switch.Id) {
        throw 'Exactly one VM adapter on the expected switch was not observed'
    }
    $hostAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
        ([string]$_.InterfaceGuid).Trim('{}') -eq ([string]$request.host_adapter_id).Trim('{}')
    })
    if ($hostAdapters.Count -ne 1) { throw 'Configured host adapter identity was not observed exactly once' }
    $hostAdapter = $hostAdapters[0]
    if ([string]$hostAdapter.Name -ne ('vEthernet (' + [string]$switch.Name + ')') -or [string]$hostAdapter.Status -ne 'Up') {
        throw 'Configured host adapter is not the active host-side adapter for the controlled switch'
    }
    $allHostAddresses = @(Get-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
    $hostAddresses = @($allHostAddresses | Where-Object {
        [string]$_.IPAddress -eq [string]$request.host_ipv4 -and [uint32]$_.PrefixLength -eq [uint32]$request.prefix_length
    })
    if ($hostAddresses.Count -ne 1 -or $allHostAddresses.Count -ne 1) { throw 'Host virtual adapter fixed address is missing, wrong, or accompanied by another IPv4 address' }
    $hostIpv6Binding = Get-NetAdapterBinding -InterfaceDescription ([string]$hostAdapter.InterfaceDescription) -ComponentID 'ms_tcpip6' -ErrorAction Stop
    if ([bool]$hostIpv6Binding.Enabled) { throw 'IPv6 is enabled on the controlled host adapter' }
    $matchingNat = @(Get-NetNat -ErrorAction Stop | Where-Object {
        [string]$_.InternalIPInterfaceAddressPrefix -eq [string]$request.subnet_prefix
    })
    if ([bool]$request.nat_enabled) {
        if ($matchingNat.Count -ne 1 -or [string]$matchingNat[0].Name -ne [string]$request.gateway_id -or -not [bool]$matchingNat[0].Active) {
            throw 'Configured active NAT was not observed on the controlled subnet'
        }
        $natStaticMappings = @(Get-NetNatStaticMapping -ErrorAction SilentlyContinue | Where-Object {
            [string]$_.NatName -eq [string]$request.gateway_id
        })
        if ($natStaticMappings.Count -ne 0) {
            throw 'External mode refuses NAT static mappings that could admit unsolicited inbound traffic'
        }
    } elseif ($matchingNat.Count -ne 0) { throw 'Host-server mode requires NAT to be absent' }
    $routes = @(Get-NetRoute -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
    if (@($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).Count -ne 0) {
        throw 'The controlled host adapter has an unexpected default route'
    }
    $firewallScope = [string]$adapters[0].Id
    if ([string]::IsNullOrWhiteSpace($firewallScope)) { throw 'The exact VM adapter firewall scope is missing' }
    if ($null -ne $request.firewall_scope_id -and [string]$request.firewall_scope_id -ne $firewallScope) {
        throw 'VM adapter firewall scope changed after it was journaled'
    }
    if ([bool]$request.prepare_only) {
        [ordered]@{ schema_version = 1; ok = $true; data = [ordered]@{
            firewall_scope_id = [string]$firewallScope
        }} | ConvertTo-Json -Compress -Depth 5
        return
    }
    if ([bool]$request.configure) {
        $preexisting = @(Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $adapters[0] -ErrorAction Stop)
        if ($preexisting.Count -ne 0) { throw 'Pre-existing VM adapter ACLs make policy unverifiable' }
        foreach ($rule in @($request.firewall_rules)) {
            $parameters = @{
                VMNetworkAdapter = $adapters[0]
                Direction = [string]$rule.direction; Action = [string]$rule.action; Protocol = [string]$rule.protocol
                Weight = [int32]$rule.priority; Stateful = [bool]$rule.stateful; ErrorAction = 'Stop'
            }
            if (@($rule.local_addresses).Count -ne 1 -or @($rule.remote_addresses).Count -ne 1 -or @($rule.remote_ports).Count -gt 1) {
                throw 'VM adapter ACL rule is not a single exact tuple'
            }
            $parameters.LocalIPAddress = [string]$rule.local_addresses[0]
            if ([string]$rule.remote_addresses[0] -ne 'Any') { $parameters.RemoteIPAddress = [string]$rule.remote_addresses[0] }
            if (@($rule.remote_ports).Count -eq 1) { $parameters.RemotePort = [string]$rule.remote_ports[0] }
            if ([string]$rule.protocol -eq 'Any') { $parameters.Remove('Protocol') }
            try {
                Add-VMNetworkAdapterExtendedAcl @parameters | Out-Null
            } catch {
                throw ('Failed to install VM adapter ACL ' + [string]$rule.name + ': ' + $_.Exception.Message)
            }
        }
    }
    $rules = @(Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $adapters[0] -ErrorAction Stop)
    $expectedNames = @($request.firewall_rules | ForEach-Object { [string]$_.name })
    if ($rules.Count -ne $expectedNames.Count) {
        throw 'Required firewall rules are missing or an overly broad rule exists'
    }
    foreach ($expected in @($request.firewall_rules)) {
        $expectedRemote = if ([string]$expected.remote_addresses[0] -eq 'Any') { 'ANY' } else { [string]$expected.remote_addresses[0] }
        $expectedPort = if (@($expected.remote_ports).Count -eq 0) { 'ANY' } else { [string]$expected.remote_ports[0] }
        $expectedProtocol = if ([string]$expected.protocol -eq 'Any') { 'ANY' } else { [string]$expected.protocol }
        $actual = @($rules | Where-Object {
            [string]$_.Direction -eq [string]$expected.direction -and [string]$_.Action -eq [string]$expected.action -and
            [int32]$_.Weight -eq [int32]$expected.priority -and [bool]$_.Stateful -eq [bool]$expected.stateful -and
            [string]$_.LocalIPAddress -eq [string]$expected.local_addresses[0] -and
            [string]$_.RemoteIPAddress -eq $expectedRemote -and [string]$_.RemotePort -eq $expectedPort -and
            [string]$_.Protocol -eq $expectedProtocol
        })
        if ($actual.Count -ne 1) {
            throw "VM adapter ACL tuple is missing, duplicated, or drifted: $($expected.name)"
        }
    }
    $reportedNames = @($expectedNames)
    if ([string]$request.mode -eq 'host_server') {
        $hostRuleId = [string]$request.host_firewall_rule_id
        if ([string]::IsNullOrWhiteSpace($hostRuleId) -or -not $hostRuleId.StartsWith('Foxhole-', [System.StringComparison]::Ordinal)) {
            throw 'Host-server mode omitted its run-owned host firewall rule identifier'
        }
        if ([bool]$request.configure) {
            if (@(Get-NetFirewallRule -Name $hostRuleId -ErrorAction SilentlyContinue).Count -ne 0) {
                throw 'The run-owned host firewall rule identifier already exists'
            }
            New-NetFirewallRule -Name $hostRuleId -DisplayName $hostRuleId -Group 'Foxhole Controlled Networking' `
                -Description ('Foxhole run ' + [string]$request.vm_id + ' adapter ' + [string]$firewallScope) `
                -Enabled True -Profile Any -Direction Inbound -Action Allow -EdgeTraversalPolicy Block `
                -Protocol TCP -LocalAddress ([string]$request.host_ipv4) -RemoteAddress ([string]$request.guest_ipv4) `
                -LocalPort ([uint16]$request.host_service_port) -InterfaceAlias ([string]$hostAdapter.Name) -ErrorAction Stop | Out-Null
        }
        $hostRules = @(Get-NetFirewallRule -Name $hostRuleId -PolicyStore ActiveStore -ErrorAction Stop)
        if ($hostRules.Count -ne 1 -or [string]$hostRules[0].DisplayName -ne $hostRuleId -or
            [string]$hostRules[0].DisplayGroup -ne 'Foxhole Controlled Networking' -or
            [string]$hostRules[0].Enabled -ne 'True' -or [string]$hostRules[0].Direction -ne 'Inbound' -or
            [string]$hostRules[0].Action -ne 'Allow' -or [string]$hostRules[0].EdgeTraversalPolicy -ne 'Block') {
            throw 'Run-owned host firewall rule is missing, disabled, or broader than expected'
        }
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $hostRules[0] -ErrorAction Stop
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $hostRules[0] -ErrorAction Stop
        $interfaceFilter = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $hostRules[0] -ErrorAction Stop
        if ([string]$addressFilter.LocalAddress -ne [string]$request.host_ipv4 -or
            [string]$addressFilter.RemoteAddress -ne [string]$request.guest_ipv4 -or
            [string]$portFilter.Protocol -ne 'TCP' -or [string]$portFilter.LocalPort -ne [string]$request.host_service_port -or
            [string]$portFilter.RemotePort -ne 'Any' -or [string]$interfaceFilter.InterfaceAlias -ne [string]$hostAdapter.Name) {
            throw 'Run-owned host firewall filters do not match the exact guest/service tuple'
        }
        $sameRunRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
            ([string]$_.Name).StartsWith(([string]$hostRuleId).Substring(0, ([string]$hostRuleId).Length - 'host-inbound'.Length), [System.StringComparison]::Ordinal)
        })
        if ($sameRunRules.Count -ne 1) { throw 'An unexpected broader host firewall rule exists for this run' }
        $reportedNames += $hostRuleId
        Require-Command 'Get-NetTCPConnection'
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort ([uint16]$request.host_service_port) -ErrorAction Stop)
        if (@($listeners | Where-Object { [string]$_.LocalAddress -eq [string]$request.host_ipv4 }).Count -ne 1 -or
            @($listeners | Where-Object { [string]$_.LocalAddress -in @('0.0.0.0','::') }).Count -ne 0) {
            throw 'The HTTP service is not bound exclusively to the configured host address'
        }
    }
    $captureActive = $false
    if ([bool]$request.capture_required) {
        foreach ($name in @('Get-NetEventSession','New-NetEventSession','Add-NetEventPacketCaptureProvider','Get-NetEventPacketCaptureProvider','Start-NetEventSession')) { Require-Command $name }
        if ([bool]$request.configure) {
            if (@(Get-NetEventSession -ErrorAction SilentlyContinue).Count -ne 0) { throw 'An existing capture session prevents exact capture attestation' }
            New-NetEventSession -Name ([string]$request.capture_session) -LocalFilePath ([string]$request.capture_file) -CaptureMode SaveToFile -MaxFileSize 128 -ErrorAction Stop | Out-Null
            Add-NetEventPacketCaptureProvider -SessionName ([string]$request.capture_session) -CaptureType Switch -IpAddresses @([string]$request.guest_ipv4) -EtherType @(0x0800) -VmCaptureDirection IngressAndEgress -TruncationLength 0 -ErrorAction Stop | Out-Null
            Start-NetEventSession -Name ([string]$request.capture_session) -ErrorAction Stop | Out-Null
        }
        $capture = Get-NetEventSession -Name ([string]$request.capture_session) -ErrorAction Stop
        $captureActive = [string]$capture.CaptureMode -eq 'SaveToFile' -and [string]$capture.LocalFilePath -eq [string]$request.capture_file -and [string]$capture.SessionStatus -eq 'Running'
        $provider = Get-NetEventPacketCaptureProvider -SessionName ([string]$request.capture_session) -ErrorAction Stop
        $providerAddresses = @($provider.IpAddresses | ForEach-Object { [string]$_ })
        $captureActive = $captureActive -and $providerAddresses.Count -eq 1 -and $providerAddresses[0] -eq [string]$request.guest_ipv4 -and
            [string]$provider.CaptureType -eq 'Switch' -and [string]$provider.VmCaptureDirection -eq 'IngressAndEgress' -and
            @($provider.EtherType) -contains 2048 -and [uint16]$provider.TruncationLength -eq 0
        if (-not $captureActive) { throw 'Required external-network capture is not active' }
    }
    $guestSeen = $null
    if (@($adapters[0].IPAddresses) -contains [string]$request.guest_ipv4) { $guestSeen = [string]$request.guest_ipv4 }
    $ipv6Seen = @(@($adapters[0].IPAddresses) | Where-Object { $_ -like '*:*' }).Count -ne 0
    $data = [ordered]@{
        adapter_count = [uint32]$adapters.Count; switch_id = [string]$adapters[0].SwitchId
        switch_type = [string]$switch.SwitchType; host_adapter_id = [string]$hostAdapter.InterfaceGuid
        firewall_scope_id = [string]$firewallScope
        host_ipv4 = [string]$request.host_ipv4; guest_ipv4 = $guestSeen
        nat_enabled = [bool]($matchingNat.Count -eq 1)
        firewall_rule_ids = @($reportedNames | Sort-Object)
        capture_active = [bool]$captureActive; ipv6_disabled = [bool](-not $ipv6Seen -and -not [bool]$hostIpv6Binding.Enabled)
        no_unexpected_routes = $true; warnings = @()
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } | ConvertTo-Json -Compress -Depth 8
} catch {
    [ordered]@{ schema_version = 1; ok = $false; error = [ordered]@{
        code = 'controlled_network_failed'; message = $_.Exception.Message
    }} | ConvertTo-Json -Compress -Depth 6
}
"#;

pub(crate) const CLEANUP_CONTROLLED_NETWORK_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $removed = New-Object System.Collections.Generic.List[string]
    if ($null -ne $request.capture_session) {
        $session = Get-NetEventSession -Name ([string]$request.capture_session) -ErrorAction SilentlyContinue
        if ($null -ne $session) {
            if ([string]$session.LocalFilePath -ne [string]$request.capture_file) { throw 'Capture session path no longer proves run ownership' }
            if ([string]$session.SessionStatus -eq 'Running') { Stop-NetEventSession -Name ([string]$request.capture_session) -ErrorAction Stop | Out-Null }
            Remove-NetEventSession -Name ([string]$request.capture_session) -ErrorAction Stop
            $removed.Add('capture:' + [string]$request.capture_session)
        }
    }
    foreach ($name in @($request.firewall_rule_ids)) {
        if (-not ([string]$name).StartsWith([string]$request.rule_prefix, [System.StringComparison]::Ordinal)) { throw 'Rule is outside the run-owned prefix' }
    }
    if ($null -ne $request.host_firewall_rule_id) {
        $hostRuleId = [string]$request.host_firewall_rule_id
        if (-not $hostRuleId.StartsWith([string]$request.rule_prefix, [System.StringComparison]::Ordinal)) {
            throw 'Host firewall rule is outside the run-owned prefix'
        }
        $hostRules = @(Get-NetFirewallRule -Name $hostRuleId -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($hostRules.Count -ne 1 -or [string]$hostRules[0].DisplayName -ne $hostRuleId -or
            [string]$hostRules[0].DisplayGroup -ne 'Foxhole Controlled Networking' -or
            [string]$hostRules[0].Description -ne ('Foxhole run ' + [string]$request.vm_id + ' adapter ' + [string]$request.firewall_scope_id) -or
            [string]$hostRules[0].Direction -ne 'Inbound' -or [string]$hostRules[0].Action -ne 'Allow') {
            throw 'Host firewall rule no longer proves exact run ownership'
        }
        $hostAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
            ([string]$_.InterfaceGuid).Trim('{}') -eq ([string]$request.host_adapter_id).Trim('{}')
        })
        if ($hostAdapters.Count -ne 1) { throw 'Run-owned host firewall adapter identity drifted before cleanup' }
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $hostRules[0] -ErrorAction Stop
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $hostRules[0] -ErrorAction Stop
        $interfaceFilter = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $hostRules[0] -ErrorAction Stop
        if ([string]$addressFilter.LocalAddress -ne [string]$request.host_ipv4 -or
            [string]$addressFilter.RemoteAddress -ne [string]$request.guest_ipv4 -or
            [string]$portFilter.Protocol -ne 'TCP' -or [string]$portFilter.LocalPort -ne [string]$request.host_service_port -or
            [string]$portFilter.RemotePort -ne 'Any' -or [string]$interfaceFilter.InterfaceAlias -ne [string]$hostAdapters[0].Name) {
            throw 'Host firewall filters drifted before cleanup'
        }
        Remove-NetFirewallRule -Name $hostRuleId -ErrorAction Stop
        if ($null -ne (Get-NetFirewallRule -Name $hostRuleId -ErrorAction SilentlyContinue)) {
            throw 'Run-owned host firewall rule remained after cleanup'
        }
        $removed.Add('firewall:' + $hostRuleId)
    }
    $vm = Get-VM -Id ([guid][string]$request.vm_id) -ErrorAction SilentlyContinue
    if ($null -ne $vm) {
        $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
            [string]$_.Id -eq [string]$request.firewall_scope_id
        })
        if ($adapters.Count -ne 1) { throw 'Run-owned VM adapter scope was not observed exactly once during ACL cleanup' }
        $acls = @(Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $adapters[0] -ErrorAction Stop)
        if ($acls.Count -ne @($request.firewall_rule_ids).Count) { throw 'VM adapter ACL count drifted before cleanup' }
        $acls | Remove-VMNetworkAdapterExtendedAcl -ErrorAction Stop
    }
    foreach ($name in @($request.firewall_rule_ids)) {
        $removed.Add('firewall:' + [string]$name)
    }
    [ordered]@{ schema_version = 1; ok = $true; data = [ordered]@{ removed = @($removed.ToArray()) }} | ConvertTo-Json -Compress -Depth 5
} catch {
    [ordered]@{ schema_version = 1; ok = $false; error = [ordered]@{
        code = 'network_cleanup_failed'; message = $_.Exception.Message
    }} | ConvertTo-Json -Compress -Depth 5
}
"#;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlledSwitchType {
    Private,
    Internal,
    External,
}

impl ControlledSwitchType {
    fn powershell_name(self) -> &'static str {
        match self {
            Self::Private => "Private",
            Self::Internal => "Internal",
            Self::External => "External",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlledGatewayConfig {
    pub switch_name: String,
    pub switch_id: String,
    pub switch_type: ControlledSwitchType,
    pub gateway_id: String,
    pub host_ipv4: Ipv4Addr,
    pub prefix_length: u8,
    pub host_service_port: Option<u16>,
    pub host_adapter_id: String,
    pub guest_address_start: Ipv4Addr,
    pub guest_address_end: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub allocation_directory: PathBuf,
    pub firewall_enforced: bool,
    pub packet_capture_enabled: bool,
    pub host_private_ranges_blocked: bool,
    pub nat_enabled: bool,
    #[serde(default)]
    pub owned_by_run: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlledNetworkMode {
    HostServer,
    External,
}

impl ControlledNetworkMode {
    fn name(self) -> &'static str {
        match self {
            Self::HostServer => "host_server",
            Self::External => "allow_internet",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirewallRuleSpec {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub priority: u16,
    pub stateful: bool,
    pub local_addresses: Vec<String>,
    pub remote_addresses: Vec<String>,
    pub remote_ports: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum HyperVNetworkPlan {
    DenyAll,
    Controlled {
        network_mode: ControlledNetworkMode,
        switch_name: String,
        switch_id: String,
        switch_type: ControlledSwitchType,
        gateway_id: String,
        host_ipv4: Ipv4Addr,
        prefix_length: u8,
        host_service_port: Option<u16>,
        host_adapter_id: String,
        guest_address_start: Ipv4Addr,
        guest_address_end: Ipv4Addr,
        dns_servers: Vec<Ipv4Addr>,
        gateway_ipv4: Option<Ipv4Addr>,
        allocation_directory: PathBuf,
        nat_enabled: bool,
        guest_ipv4: Option<Ipv4Addr>,
        lease_path: Option<PathBuf>,
        firewall_rules: Vec<FirewallRuleSpec>,
        host_firewall_rule_id: Option<String>,
        capture_session: Option<String>,
        capture_file: Option<PathBuf>,
        firewall_scope_id: Option<String>,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkAttachment {
    pub adapter_count: u32,
    pub switch_id: Option<String>,
    #[serde(default)]
    pub switch_type: Option<String>,
    #[serde(default)]
    pub host_adapter_id: Option<String>,
    #[serde(default)]
    pub firewall_scope_id: Option<String>,
    #[serde(default)]
    pub host_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub guest_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub nat_enabled: bool,
    #[serde(default)]
    pub firewall_rule_ids: Vec<String>,
    #[serde(default)]
    pub capture_active: bool,
    #[serde(default)]
    pub ipv6_disabled: bool,
    #[serde(default)]
    pub no_unexpected_routes: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FirewallScopeDiscovery {
    firewall_scope_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestAddressLease {
    pub run_id: String,
    pub address: Ipv4Addr,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkOwnedResources {
    pub vm_id: String,
    pub firewall_scope_id: String,
    pub rule_prefix: String,
    pub firewall_rule_ids: Vec<String>,
    pub firewall_rules: Vec<FirewallRuleSpec>,
    #[serde(default)]
    pub host_firewall_rule_id: Option<String>,
    #[serde(default)]
    pub host_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub host_service_port: Option<u16>,
    #[serde(default)]
    pub host_adapter_id: Option<String>,
    pub capture_session: Option<String>,
    pub capture_file: Option<PathBuf>,
    pub guest_lease: Option<GuestAddressLease>,
    #[serde(default)]
    pub nat_mapping_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkCleanupResult {
    pub removed: Vec<String>,
}

pub(crate) fn plan(
    policy: &NetworkPolicy,
    gateway: Option<&ControlledGatewayConfig>,
) -> SandboxResult<HyperVNetworkPlan> {
    if matches!(policy, NetworkPolicy::DenyAll) {
        return Ok(HyperVNetworkPlan::DenyAll);
    }
    let gateway = gateway.ok_or_else(|| {
        SandboxError::new(
            "hyperv_network",
            "networked Hyper-V modes require --hyperv-gateway-config or FOXHOLE_HYPERV_GATEWAY_CONFIG",
        )
    })?;
    validate_gateway(gateway)?;
    let network_mode = match policy {
        NetworkPolicy::HostServer => ControlledNetworkMode::HostServer,
        NetworkPolicy::AllowInternet => ControlledNetworkMode::External,
        NetworkPolicy::AllowList(_) | NetworkPolicy::CaptureOnly => {
            return Err(SandboxError::new(
                "hyperv_network",
                "Hyper-V supports deny_all, host_server, and allow_internet; this policy has no attested host enforcement",
            ));
        }
        NetworkPolicy::DenyAll => unreachable!(),
    };
    validate_mode(gateway, network_mode)?;
    Ok(HyperVNetworkPlan::Controlled {
        network_mode,
        switch_name: gateway.switch_name.clone(),
        switch_id: gateway.switch_id.clone(),
        switch_type: gateway.switch_type,
        gateway_id: gateway.gateway_id.clone(),
        host_ipv4: gateway.host_ipv4,
        prefix_length: gateway.prefix_length,
        host_service_port: gateway.host_service_port,
        host_adapter_id: gateway.host_adapter_id.clone(),
        guest_address_start: gateway.guest_address_start,
        guest_address_end: gateway.guest_address_end,
        dns_servers: gateway.dns_servers.clone(),
        gateway_ipv4: gateway.gateway_ipv4,
        allocation_directory: gateway.allocation_directory.clone(),
        nat_enabled: gateway.nat_enabled,
        guest_ipv4: None,
        lease_path: None,
        firewall_rules: Vec::new(),
        host_firewall_rule_id: None,
        capture_session: None,
        capture_file: None,
        firewall_scope_id: None,
    })
}

pub(crate) fn activate(
    plan: &mut HyperVNetworkPlan,
    run_id: &str,
    run_root: &Path,
) -> SandboxResult<Option<GuestAddressLease>> {
    validate_run_id(run_id)?;
    let HyperVNetworkPlan::Controlled {
        network_mode,
        guest_address_start,
        guest_address_end,
        allocation_directory,
        guest_ipv4,
        lease_path,
        firewall_rules,
        host_firewall_rule_id,
        capture_session,
        capture_file,
        host_ipv4,
        host_service_port,
        dns_servers,
        ..
    } = plan
    else {
        return Ok(None);
    };
    if guest_ipv4.is_some() || lease_path.is_some() {
        return Err(SandboxError::new(
            "hyperv_network",
            "network plan was activated twice",
        ));
    }
    let lease = allocate_guest_address(
        allocation_directory,
        *guest_address_start,
        *guest_address_end,
        run_id,
    )?;
    *guest_ipv4 = Some(lease.address);
    *lease_path = Some(lease.path.clone());
    let rule_prefix = format!("Foxhole-{run_id}-");
    let local = lease.address.to_string();
    let mut rules = Vec::new();
    match network_mode {
        ControlledNetworkMode::HostServer => {
            *host_firewall_rule_id = Some(format!("{rule_prefix}host-inbound"));
            rules.push(firewall_rule(
                &format!("{rule_prefix}host-service"),
                "Outbound",
                "Allow",
                "TCP",
                300,
                true,
                &local,
                &host_ipv4.to_string(),
                Some(&host_service_port.expect("validated host port").to_string()),
            ));
            rules.push(firewall_rule(
                &format!("{rule_prefix}host-service-reply"),
                "Inbound",
                "Allow",
                "TCP",
                300,
                false,
                &local,
                &host_ipv4.to_string(),
                Some(&host_service_port.expect("validated host port").to_string()),
            ));
        }
        ControlledNetworkMode::External => {
            for (index, resolver) in dns_servers.iter().enumerate() {
                let weight = 60_000 - u16::try_from(index).expect("validated DNS resolver bound");
                rules.push(firewall_rule(
                    &format!("{rule_prefix}dns-{index}"),
                    "Outbound",
                    "Allow",
                    "Any",
                    weight,
                    false,
                    &local,
                    &resolver.to_string(),
                    Some("53"),
                ));
                rules.push(firewall_rule(
                    &format!("{rule_prefix}dns-reply-{index}"),
                    "Inbound",
                    "Allow",
                    "Any",
                    weight,
                    false,
                    &local,
                    &resolver.to_string(),
                    Some("53"),
                ));
            }
            rules.push(firewall_rule(
                &format!("{rule_prefix}block-other-dns"),
                "Outbound",
                "Deny",
                "Any",
                50_000,
                false,
                &local,
                "Any",
                Some("53"),
            ));
            for (index, cidr) in forbidden_ipv4_cidrs().iter().enumerate() {
                let weight = 40_000 - u16::try_from(index).expect("bounded forbidden CIDR list");
                rules.push(firewall_rule(
                    &format!("{rule_prefix}block-local-{index:03}"),
                    "Outbound",
                    "Deny",
                    "Any",
                    weight,
                    false,
                    &local,
                    cidr,
                    None,
                ));
            }
            for (index, cidr) in public_ipv4_cidrs().iter().enumerate() {
                let weight = 20_000 - u16::try_from(index).expect("bounded public CIDR list");
                rules.push(firewall_rule(
                    &format!("{rule_prefix}public-ipv4-{index:03}"),
                    "Outbound",
                    "Allow",
                    "TCP",
                    weight,
                    true,
                    &local,
                    cidr,
                    None,
                ));
            }
        }
    }
    rules.push(firewall_rule(
        &format!("{rule_prefix}block-outbound"),
        "Outbound",
        "Deny",
        "Any",
        1,
        false,
        &local,
        "Any",
        None,
    ));
    rules.push(firewall_rule(
        &format!("{rule_prefix}block-inbound"),
        "Inbound",
        "Deny",
        "Any",
        1,
        false,
        &local,
        "Any",
        None,
    ));
    *firewall_rules = rules;
    if matches!(network_mode, ControlledNetworkMode::External) {
        *capture_session = Some(format!("FoxholeNet-{run_id}"));
        *capture_file = Some(run_root.join("network-capture.etl"));
    }
    Ok(Some(lease))
}

#[allow(clippy::too_many_arguments)]
fn firewall_rule(
    name: &str,
    direction: &str,
    action: &str,
    protocol: &str,
    priority: u16,
    stateful: bool,
    local_address: &str,
    remote_address: &str,
    remote_port: Option<&str>,
) -> FirewallRuleSpec {
    FirewallRuleSpec {
        name: name.to_string(),
        direction: direction.to_string(),
        action: action.to_string(),
        protocol: protocol.to_string(),
        priority,
        stateful,
        local_addresses: vec![local_address.to_string()],
        remote_addresses: vec![remote_address.to_string()],
        remote_ports: remote_port.into_iter().map(str::to_string).collect(),
    }
}

pub(crate) fn configure(
    executor: &dyn PowerShellExecutor,
    vm_id: &str,
    plan: &HyperVNetworkPlan,
) -> SandboxResult<NetworkAttachment> {
    run_attestation(executor, vm_id, plan, true, false)
}

pub(crate) fn prepare_controlled_adapter(
    executor: &dyn PowerShellExecutor,
    vm_id: &str,
    plan: &mut HyperVNetworkPlan,
) -> SandboxResult<()> {
    if matches!(plan, HyperVNetworkPlan::DenyAll) {
        return Ok(());
    }
    validate_identifier(vm_id, "VM identifier")?;
    let mut input = controlled_input(vm_id, plan, false)?;
    input["configure_adapter"] = serde_json::Value::Bool(true);
    input["prepare_only"] = serde_json::Value::Bool(true);
    let invocation = PowerShellInvocation {
        operation: "attach controlled adapter and discover its exact firewall scope",
        script: CONTROLLED_NETWORK_SCRIPT,
        input,
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let discovery: FirewallScopeDiscovery = serde_json::from_value(executor.execute(&invocation)?)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_network",
                "decode controlled adapter firewall scope",
                error,
            )
        })?;
    let attachment = NetworkAttachment {
        firewall_scope_id: Some(discovery.firewall_scope_id),
        ..NetworkAttachment::default()
    };
    record_firewall_scope(plan, &attachment)
}

pub(crate) fn verify(
    executor: &dyn PowerShellExecutor,
    vm_id: &str,
    plan: &HyperVNetworkPlan,
) -> SandboxResult<NetworkAttachment> {
    run_attestation(executor, vm_id, plan, false, false)
}

pub(crate) fn verify_after_execution(
    executor: &dyn PowerShellExecutor,
    vm_id: &str,
    plan: &HyperVNetworkPlan,
) -> SandboxResult<NetworkAttachment> {
    // A powered-off VM no longer exposes learned IP addresses through
    // Get-VMNetworkAdapter. The authenticated guest result is bound to this independent host
    // attestation after collection, while every host-side control is still checked here.
    run_attestation(executor, vm_id, plan, false, false)
}

pub(crate) fn bind_guest_attestation(
    plan: &HyperVNetworkPlan,
    attachment: &mut NetworkAttachment,
    attestation: Option<&GuestNetworkAttestation>,
) -> SandboxResult<()> {
    match plan {
        HyperVNetworkPlan::DenyAll => {
            if attestation.is_some() {
                return Err(SandboxError::new(
                    "hyperv_network",
                    "deny-all guest result unexpectedly carried a NIC attestation",
                ));
            }
            Ok(())
        }
        HyperVNetworkPlan::Controlled {
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
            dns_servers,
            ..
        } => {
            let attestation = attestation.ok_or_else(|| {
                SandboxError::new(
                    "hyperv_network",
                    "controlled guest result omitted its trusted NIC attestation",
                )
            })?;
            attestation.validate().map_err(|error| {
                SandboxError::new(
                    "hyperv_network",
                    format!("guest NIC attestation is invalid: {error}"),
                )
            })?;
            if Some(attestation.guest_ipv4) != *guest_ipv4
                || attestation.prefix_length != *prefix_length
                || attestation.gateway_ipv4 != *gateway_ipv4
                || attestation.dns_servers != *dns_servers
                || !attestation.ipv6_disabled
                || !attestation.no_unexpected_routes
            {
                return Err(SandboxError::new(
                    "hyperv_network",
                    "guest NIC address, prefix, route, DNS, or IPv6 attestation contradicts the controlled plan",
                ));
            }
            attachment.guest_ipv4 = Some(attestation.guest_ipv4);
            verify_attachment(plan, attachment, true)
        }
    }
}

fn run_attestation(
    executor: &dyn PowerShellExecutor,
    vm_id: &str,
    plan: &HyperVNetworkPlan,
    configure: bool,
    require_guest_address: bool,
) -> SandboxResult<NetworkAttachment> {
    validate_identifier(vm_id, "VM identifier")?;
    let (script, input, operation) = match plan {
        HyperVNetworkPlan::DenyAll => (
            CONFIGURE_DENY_ALL_SCRIPT,
            serde_json::json!({ "vm_id": vm_id, "configure": configure }),
            if configure {
                "remove every Hyper-V network adapter"
            } else {
                "verify deny-all Hyper-V networking"
            },
        ),
        HyperVNetworkPlan::Controlled { .. } => (
            CONTROLLED_NETWORK_SCRIPT,
            controlled_input(vm_id, plan, configure)?,
            if configure {
                "provision and attest controlled Hyper-V networking"
            } else {
                "verify complete Hyper-V network containment"
            },
        ),
    };
    let invocation = PowerShellInvocation {
        operation,
        script,
        input,
        timeout: DEFAULT_TIMEOUT,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    };
    let attachment: NetworkAttachment = serde_json::from_value(executor.execute(&invocation)?)
        .map_err(|error| {
            SandboxError::with_source("hyperv_network", "decode network attestation", error)
        })?;
    verify_attachment(plan, &attachment, require_guest_address)?;
    Ok(attachment)
}

fn verify_attachment(
    plan: &HyperVNetworkPlan,
    attachment: &NetworkAttachment,
    require_guest_address: bool,
) -> SandboxResult<()> {
    let valid = match plan {
        HyperVNetworkPlan::DenyAll => {
            attachment.adapter_count == 0
                && attachment.switch_id.is_none()
                && attachment.firewall_rule_ids.is_empty()
                && !attachment.capture_active
        }
        HyperVNetworkPlan::Controlled {
            switch_id,
            switch_type,
            host_adapter_id,
            host_ipv4,
            guest_ipv4,
            nat_enabled,
            firewall_rules,
            host_firewall_rule_id,
            capture_session,
            firewall_scope_id,
            ..
        } => {
            let mut actual_rules = attachment.firewall_rule_ids.clone();
            actual_rules.sort();
            let mut expected_rules = firewall_rules
                .iter()
                .map(|rule| rule.name.clone())
                .collect::<Vec<_>>();
            expected_rules.extend(host_firewall_rule_id.iter().cloned());
            expected_rules.sort();
            attachment.adapter_count == 1
                && attachment.switch_id.as_deref() == Some(switch_id.as_str())
                && attachment.switch_type.as_deref() == Some(switch_type.powershell_name())
                && attachment
                    .host_adapter_id
                    .as_deref()
                    .is_some_and(|observed| {
                        observed
                            .trim_matches(['{', '}'])
                            .eq_ignore_ascii_case(host_adapter_id.trim_matches(['{', '}']))
                    })
                && attachment.host_ipv4 == Some(*host_ipv4)
                && (!require_guest_address || attachment.guest_ipv4 == *guest_ipv4)
                && attachment.nat_enabled == *nat_enabled
                && actual_rules == expected_rules
                && attachment
                    .firewall_scope_id
                    .as_deref()
                    .is_some_and(|observed| {
                        firewall_scope_id.as_deref().is_none_or(|expected| {
                            observed
                                .trim_matches(['{', '}'])
                                .eq_ignore_ascii_case(expected.trim_matches(['{', '}']))
                        })
                    })
                && attachment.capture_active == capture_session.is_some()
                && attachment.ipv6_disabled
                && attachment.no_unexpected_routes
        }
    };
    if valid {
        Ok(())
    } else {
        Err(SandboxError::new(
            "hyperv_network",
            "observed switch, adapter, addressing, NAT, firewall, capture, IPv6, or route state does not match the fail-closed plan",
        ))
    }
}

fn controlled_input(
    vm_id: &str,
    plan: &HyperVNetworkPlan,
    configure: bool,
) -> SandboxResult<serde_json::Value> {
    let HyperVNetworkPlan::Controlled {
        network_mode,
        switch_name,
        switch_id,
        switch_type,
        gateway_id,
        host_ipv4,
        prefix_length,
        host_service_port,
        host_adapter_id,
        guest_ipv4,
        dns_servers,
        gateway_ipv4,
        nat_enabled,
        firewall_rules,
        host_firewall_rule_id,
        capture_session,
        capture_file,
        firewall_scope_id,
        ..
    } = plan
    else {
        return Err(SandboxError::new(
            "hyperv_network",
            "controlled input requested for deny-all",
        ));
    };
    let guest_ipv4 = guest_ipv4.ok_or_else(|| {
        SandboxError::new(
            "hyperv_network",
            "controlled plan has no allocated guest address",
        )
    })?;
    Ok(serde_json::json!({
        "vm_id": vm_id,
        "configure": configure,
        "configure_adapter": false,
        "prepare_only": false,
        "mode": match network_mode { ControlledNetworkMode::HostServer => "host_server", ControlledNetworkMode::External => "external" },
        "switch_name": switch_name,
        "switch_id": switch_id,
        "switch_type": switch_type.powershell_name(),
        "gateway_id": gateway_id,
        "host_ipv4": host_ipv4,
        "prefix_length": prefix_length,
        "subnet_prefix": format!("{}/{}", network_address(*host_ipv4, *prefix_length), prefix_length),
        "host_service_port": host_service_port,
        "host_adapter_id": host_adapter_id,
        "guest_ipv4": guest_ipv4,
        "dns_servers": dns_servers,
        "gateway_ipv4": gateway_ipv4,
        "nat_enabled": nat_enabled,
        "firewall_rules": firewall_rules,
        "host_firewall_rule_id": host_firewall_rule_id,
        "capture_required": capture_session.is_some(),
        "capture_session": capture_session,
        "capture_file": capture_file,
        "firewall_scope_id": firewall_scope_id,
    }))
}

pub(crate) fn record_firewall_scope(
    plan: &mut HyperVNetworkPlan,
    attachment: &NetworkAttachment,
) -> SandboxResult<()> {
    let HyperVNetworkPlan::Controlled {
        firewall_scope_id, ..
    } = plan
    else {
        return Ok(());
    };
    let observed = attachment.firewall_scope_id.as_deref().ok_or_else(|| {
        SandboxError::new(
            "hyperv_network",
            "network attestation omitted the exact Hyper-V firewall scope",
        )
    })?;
    validate_identifier(observed, "Hyper-V firewall scope identifier")?;
    if firewall_scope_id
        .as_deref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(observed))
    {
        return Err(SandboxError::new(
            "hyperv_network",
            "Hyper-V firewall scope changed during provisioning",
        ));
    }
    *firewall_scope_id = Some(observed.to_string());
    Ok(())
}

pub(crate) fn owned_resources(
    vm_id: &str,
    run_id: &str,
    plan: &HyperVNetworkPlan,
) -> SandboxResult<NetworkOwnedResources> {
    let HyperVNetworkPlan::Controlled {
        guest_ipv4,
        lease_path,
        firewall_rules,
        host_firewall_rule_id,
        capture_session,
        capture_file,
        firewall_scope_id,
        host_ipv4,
        host_service_port,
        host_adapter_id,
        ..
    } = plan
    else {
        return Ok(NetworkOwnedResources::default());
    };
    validate_run_id(run_id)?;
    validate_identifier(vm_id, "network cleanup VM identifier")?;
    let firewall_scope_id = firewall_scope_id.clone().ok_or_else(|| {
        SandboxError::new(
            "hyperv_network",
            "cannot journal controlled firewall rules without an attested scope",
        )
    })?;
    validate_identifier(&firewall_scope_id, "Hyper-V firewall scope identifier")?;
    let guest_lease = match (guest_ipv4, lease_path) {
        (Some(address), Some(path)) => Some(GuestAddressLease {
            run_id: run_id.to_string(),
            address: *address,
            path: path.clone(),
        }),
        _ => None,
    };
    Ok(NetworkOwnedResources {
        vm_id: vm_id.to_string(),
        firewall_scope_id,
        rule_prefix: format!("Foxhole-{run_id}-"),
        firewall_rule_ids: firewall_rules
            .iter()
            .map(|rule| rule.name.clone())
            .collect(),
        firewall_rules: firewall_rules.clone(),
        host_firewall_rule_id: host_firewall_rule_id.clone(),
        host_ipv4: host_firewall_rule_id.as_ref().map(|_| *host_ipv4),
        host_service_port: *host_service_port,
        host_adapter_id: host_firewall_rule_id
            .as_ref()
            .map(|_| host_adapter_id.clone()),
        capture_session: capture_session.clone(),
        capture_file: capture_file.clone(),
        guest_lease,
        nat_mapping_ids: Vec::new(),
    })
}

pub(crate) fn cleanup_owned_resources(
    executor: &dyn PowerShellExecutor,
    resources: &NetworkOwnedResources,
) -> SandboxResult<NetworkCleanupResult> {
    if resources.firewall_rule_ids.is_empty()
        && resources.host_firewall_rule_id.is_none()
        && resources.host_ipv4.is_none()
        && resources.host_service_port.is_none()
        && resources.host_adapter_id.is_none()
        && resources.capture_session.is_none()
        && resources.guest_lease.is_none()
        && resources.nat_mapping_ids.is_empty()
    {
        return Ok(NetworkCleanupResult::default());
    }
    let has_host_resources = !resources.firewall_rule_ids.is_empty()
        || resources.host_firewall_rule_id.is_some()
        || resources.capture_session.is_some()
        || !resources.nat_mapping_ids.is_empty();
    if has_host_resources {
        validate_identifier(&resources.vm_id, "network cleanup VM identifier")?;
        validate_identifier(
            &resources.firewall_scope_id,
            "network cleanup firewall scope identifier",
        )?;
    }
    let host_firewall_owned = match (
        &resources.host_firewall_rule_id,
        &resources.host_ipv4,
        &resources.host_service_port,
        &resources.host_adapter_id,
    ) {
        (Some(rule), Some(_), Some(port), Some(adapter)) => {
            rule.starts_with(&resources.rule_prefix)
                && *port != 0
                && validate_identifier(adapter, "network cleanup host adapter identifier").is_ok()
        }
        (None, None, None, None) => true,
        _ => false,
    };
    if (has_host_resources
        && (resources.rule_prefix.is_empty()
            || resources.rule_prefix.len() > 96
            || !resources.rule_prefix.starts_with("Foxhole-")
            || resources
                .firewall_rule_ids
                .iter()
                .any(|name| !name.starts_with(&resources.rule_prefix))
            || resources.firewall_rules.len() != resources.firewall_rule_ids.len()
            || resources
                .firewall_rules
                .iter()
                .zip(&resources.firewall_rule_ids)
                .any(|(rule, id)| rule.name != *id)
            || resources
                .host_firewall_rule_id
                .as_ref()
                .is_some_and(|name| !name.starts_with(&resources.rule_prefix))))
        || !host_firewall_owned
        || resources.capture_session.is_some() != resources.capture_file.is_some()
        || !resources.nat_mapping_ids.is_empty()
    {
        return Err(SandboxError::new(
            "hyperv_network_cleanup",
            "network cleanup journal does not prove exact run ownership",
        ));
    }
    let mut result = if has_host_resources {
        let invocation = PowerShellInvocation {
            operation: "remove only run-owned Hyper-V firewall and capture resources",
            script: CLEANUP_CONTROLLED_NETWORK_SCRIPT,
            input: serde_json::json!({
                "vm_id": resources.vm_id,
                "firewall_scope_id": resources.firewall_scope_id,
                "rule_prefix": resources.rule_prefix,
                "firewall_rule_ids": resources.firewall_rule_ids,
                "firewall_rules": resources.firewall_rules,
                "host_firewall_rule_id": resources.host_firewall_rule_id,
                "host_ipv4": resources.host_ipv4,
                "host_service_port": resources.host_service_port,
                "host_adapter_id": resources.host_adapter_id,
                "guest_ipv4": resources.guest_lease.as_ref().map(|lease| lease.address),
                "capture_session": resources.capture_session,
                "capture_file": resources.capture_file,
            }),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        };
        serde_json::from_value(executor.execute(&invocation)?).map_err(|error| {
            SandboxError::with_source(
                "hyperv_network_cleanup",
                "decode network cleanup result",
                error,
            )
        })?
    } else {
        NetworkCleanupResult::default()
    };
    if let Some(lease) = resources.guest_lease.as_ref() {
        release_guest_address(lease)?;
        result.removed.push(format!("guest_ip:{}", lease.address));
    }
    Ok(result)
}

pub(crate) fn validate_owned_resources(
    resources: &NetworkOwnedResources,
    run_id: &str,
    run_root: &Path,
) -> SandboxResult<()> {
    validate_run_id(run_id)?;
    let expected_prefix = format!("Foxhole-{run_id}-");
    let host_resources = !resources.firewall_rule_ids.is_empty()
        || resources.host_firewall_rule_id.is_some()
        || resources.capture_session.is_some()
        || !resources.nat_mapping_ids.is_empty();
    let capture_owned = match (&resources.capture_session, &resources.capture_file) {
        (Some(session), Some(path)) => {
            session == &format!("FoxholeNet-{run_id}")
                && path == &run_root.join("network-capture.etl")
        }
        (None, None) => true,
        _ => false,
    };
    let host_firewall_owned = match (
        &resources.host_firewall_rule_id,
        &resources.host_ipv4,
        &resources.host_service_port,
        &resources.host_adapter_id,
    ) {
        (Some(rule), Some(_), Some(port), Some(adapter)) => {
            rule.starts_with(&expected_prefix)
                && *port != 0
                && validate_identifier(adapter, "network journal host adapter identifier").is_ok()
        }
        (None, None, None, None) => true,
        _ => false,
    };
    if (host_resources
        && (validate_identifier(&resources.vm_id, "network journal VM identifier").is_err()
            || validate_identifier(
                &resources.firewall_scope_id,
                "network journal firewall scope identifier",
            )
            .is_err()
            || resources.rule_prefix != expected_prefix
            || resources
                .firewall_rule_ids
                .iter()
                .any(|name| !name.starts_with(&expected_prefix))
            || resources.firewall_rules.len() != resources.firewall_rule_ids.len()
            || resources
                .firewall_rules
                .iter()
                .zip(&resources.firewall_rule_ids)
                .any(|(rule, id)| rule.name != *id)
            || resources
                .host_firewall_rule_id
                .as_ref()
                .is_some_and(|name| !name.starts_with(&expected_prefix))
            || !capture_owned))
        || !host_firewall_owned
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "network resource identifiers are not scoped to this run",
        ));
    }
    if !resources.nat_mapping_ids.is_empty() {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "unimplemented NAT mappings cannot appear in a cleanup journal",
        ));
    }
    if let Some(lease) = resources.guest_lease.as_ref()
        && (lease.run_id != run_id
            || !allocation_directory_is_allowed(
                lease.path.parent().unwrap_or_else(|| Path::new("")),
            )
            || lease.path.extension().and_then(|value| value.to_str()) != Some("lease"))
    {
        return Err(SandboxError::new(
            "hyperv_cleanup_journal",
            "guest address lease is outside the protected allocation directory",
        ));
    }
    Ok(())
}

fn allocate_guest_address(
    directory: &Path,
    start: Ipv4Addr,
    end: Ipv4Addr,
    run_id: &str,
) -> SandboxResult<GuestAddressLease> {
    artifact::harden_owned_directory_chain(directory, directory).map_err(|error| {
        SandboxError::with_source(
            "hyperv_network_allocation",
            "protect the guest allocation directory ACL",
            error,
        )
    })?;
    let _directory_pins = artifact::pin_safe_directory_tree(directory, false).map_err(|error| {
        SandboxError::with_source(
            "hyperv_network_allocation",
            "pin the guest allocation directory against replacement",
            error,
        )
    })?;
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        SandboxError::with_source(
            "hyperv_network_allocation",
            "inspect the pre-created guest allocation directory",
            error,
        )
    })?;
    if !directory.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SandboxError::new(
            "hyperv_network_allocation",
            "guest allocation directory must be an existing absolute non-link directory",
        ));
    }
    for raw in u32::from(start)..=u32::from(end) {
        let address = Ipv4Addr::from(raw);
        let path = directory.join(format!("{}.lease", address.to_string().replace('.', "_")));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let lease = GuestAddressLease {
                    run_id: run_id.to_string(),
                    address,
                    path: path.clone(),
                };
                let bytes = serde_json::to_vec(&lease).map_err(|error| {
                    SandboxError::with_source(
                        "hyperv_network_allocation",
                        "serialize guest lease",
                        error,
                    )
                })?;
                if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
                    let _ = fs::remove_file(&path);
                    return Err(SandboxError::with_source(
                        "hyperv_network_allocation",
                        "durably reserve guest address",
                        error,
                    ));
                }
                return Ok(lease);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(SandboxError::with_source(
                    "hyperv_network_allocation",
                    "reserve a unique guest address",
                    error,
                ));
            }
        }
    }
    Err(SandboxError::new(
        "hyperv_network_allocation",
        "no unallocated guest IPv4 address remains in the configured pool",
    ))
}

fn release_guest_address(lease: &GuestAddressLease) -> SandboxResult<()> {
    let metadata = fs::symlink_metadata(&lease.path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_network_cleanup",
            "inspect guest address lease",
            error,
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err(SandboxError::new(
            "hyperv_network_cleanup",
            "refusing to release an unverified guest address lease",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    OpenOptions::new()
        .read(true)
        .open(&lease.path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| {
            SandboxError::with_source("hyperv_network_cleanup", "read guest address lease", error)
        })?;
    let recorded: GuestAddressLease = serde_json::from_slice(&bytes).map_err(|error| {
        SandboxError::with_source(
            "hyperv_network_cleanup",
            "decode guest address lease",
            error,
        )
    })?;
    if recorded != *lease {
        return Err(SandboxError::new(
            "hyperv_network_cleanup",
            "refusing to remove a guest lease whose ownership record changed",
        ));
    }
    fs::remove_file(&lease.path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_network_cleanup",
            "release guest address lease",
            error,
        )
    })
}

pub(crate) fn metadata(
    plan: &HyperVNetworkPlan,
    pre: Option<NetworkAttachment>,
    post: Option<NetworkAttachment>,
    cleanup_results: Vec<String>,
    warnings: Vec<String>,
) -> HyperVNetworkMetadata {
    match plan {
        HyperVNetworkPlan::DenyAll => HyperVNetworkMetadata {
            requested_mode: "deny_all".into(),
            capture_status: "not_requested".into(),
            pre_run_verification: pre.map(verification_record),
            post_run_verification: post.map(verification_record),
            cleanup_results,
            warnings,
            ..HyperVNetworkMetadata::default()
        },
        HyperVNetworkPlan::Controlled {
            network_mode,
            switch_id,
            switch_type,
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
            dns_servers,
            host_ipv4,
            host_service_port,
            firewall_rules,
            host_firewall_rule_id,
            capture_session,
            firewall_scope_id,
            ..
        } => HyperVNetworkMetadata {
            requested_mode: network_mode.name().into(),
            switch_id: Some(switch_id.clone()),
            switch_type: Some(switch_type.powershell_name().into()),
            guest_ipv4: *guest_ipv4,
            prefix_length: Some(*prefix_length),
            gateway_ipv4: *gateway_ipv4,
            dns_servers: dns_servers.clone(),
            host_service_endpoint: host_service_port
                .map(|port| format!("http://{host_ipv4}:{port}")),
            firewall_scope_id: firewall_scope_id.clone(),
            firewall_rule_ids: firewall_rules
                .iter()
                .map(|rule| rule.name.clone())
                .chain(host_firewall_rule_id.iter().cloned())
                .collect(),
            capture_status: if capture_session.is_some() {
                "active_before_target"
            } else {
                "not_requested"
            }
            .into(),
            pre_run_verification: pre.map(verification_record),
            post_run_verification: post.map(verification_record),
            cleanup_results,
            warnings,
        },
    }
}

fn verification_record(value: NetworkAttachment) -> HyperVNetworkVerification {
    HyperVNetworkVerification {
        verified: true,
        adapter_count: value.adapter_count,
        switch_id: value.switch_id,
        switch_type: value.switch_type,
        host_adapter_id: value.host_adapter_id,
        firewall_scope_id: value.firewall_scope_id,
        host_ipv4: value.host_ipv4,
        guest_ipv4: value.guest_ipv4,
        nat_enabled: value.nat_enabled,
        firewall_rule_ids: value.firewall_rule_ids,
        capture_active: value.capture_active,
        ipv6_disabled: value.ipv6_disabled,
        no_unexpected_routes: value.no_unexpected_routes,
        warnings: value.warnings,
    }
}

pub(crate) type GuestNetworkConfiguration = (
    Option<Ipv4Addr>,
    Option<u8>,
    Option<Ipv4Addr>,
    Vec<Ipv4Addr>,
    Option<Ipv4Addr>,
    Option<u16>,
);

pub(crate) fn guest_configuration(plan: &HyperVNetworkPlan) -> GuestNetworkConfiguration {
    match plan {
        HyperVNetworkPlan::DenyAll => (None, None, None, Vec::new(), None, None),
        HyperVNetworkPlan::Controlled {
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
            dns_servers,
            network_mode,
            host_ipv4,
            host_service_port,
            ..
        } => (
            *guest_ipv4,
            Some(*prefix_length),
            *gateway_ipv4,
            dns_servers.clone(),
            matches!(network_mode, ControlledNetworkMode::HostServer).then_some(*host_ipv4),
            matches!(network_mode, ControlledNetworkMode::HostServer)
                .then(|| host_service_port.expect("validated host service port")),
        ),
    }
}

fn validate_gateway(gateway: &ControlledGatewayConfig) -> SandboxResult<()> {
    validate_identifier(&gateway.switch_id, "controlled switch identifier")?;
    validate_identifier(&gateway.gateway_id, "controlled gateway identifier")?;
    validate_identifier(&gateway.host_adapter_id, "host adapter identifier")?;
    if gateway.switch_name.trim().is_empty()
        || gateway.switch_name.len() > 80
        || gateway.switch_name.chars().any(char::is_control)
        || gateway.switch_name.eq_ignore_ascii_case("Default Switch")
        || gateway.switch_type == ControlledSwitchType::External
        || gateway.owned_by_run
        || !(1..=30).contains(&gateway.prefix_length)
        || !gateway.allocation_directory.is_absolute()
        || !allocation_directory_is_allowed(&gateway.allocation_directory)
    {
        return Err(SandboxError::new(
            "hyperv_network",
            "switch, prefix, persistent ownership, or allocation configuration is invalid",
        ));
    }
    for address in [
        gateway.host_ipv4,
        gateway.guest_address_start,
        gateway.guest_address_end,
    ] {
        validate_unicast(address, "controlled IPv4 address")?;
    }
    if u32::from(gateway.guest_address_start) > u32::from(gateway.guest_address_end)
        || !same_subnet(
            gateway.host_ipv4,
            gateway.guest_address_start,
            gateway.prefix_length,
        )
        || !same_subnet(
            gateway.host_ipv4,
            gateway.guest_address_end,
            gateway.prefix_length,
        )
        || (u32::from(gateway.guest_address_start)..=u32::from(gateway.guest_address_end))
            .contains(&u32::from(gateway.host_ipv4))
    {
        return Err(SandboxError::new(
            "hyperv_network",
            "guest address pool is reversed, conflicts with the host, or leaves the subnet",
        ));
    }
    let network = network_address(gateway.host_ipv4, gateway.prefix_length);
    let broadcast = broadcast_address(gateway.host_ipv4, gateway.prefix_length);
    if [
        gateway.host_ipv4,
        gateway.guest_address_start,
        gateway.guest_address_end,
    ]
    .iter()
    .any(|address| *address == network || *address == broadcast)
    {
        return Err(SandboxError::new(
            "hyperv_network",
            "network and broadcast addresses cannot identify host or guest endpoints",
        ));
    }
    Ok(())
}

fn validate_mode(
    gateway: &ControlledGatewayConfig,
    mode: ControlledNetworkMode,
) -> SandboxResult<()> {
    match mode {
        ControlledNetworkMode::HostServer => {
            if gateway.switch_type != ControlledSwitchType::Internal
                || gateway.switch_name != "Foxhole Internal"
                || gateway.host_ipv4 != Ipv4Addr::new(192, 168, 250, 1)
                || gateway.prefix_length != 24
                || gateway.nat_enabled
                || gateway.gateway_ipv4.is_some()
                || !gateway.dns_servers.is_empty()
                || gateway.host_service_port.is_none_or(|port| port == 0)
                || !gateway.firewall_enforced
            {
                return Err(SandboxError::new(
                    "hyperv_network",
                    "host-server mode requires Foxhole Internal, NAT/DNS/gateway disabled, a service port, and expected firewall enforcement",
                ));
            }
        }
        ControlledNetworkMode::External => {
            let gateway_address = gateway.gateway_ipv4.ok_or_else(|| {
                SandboxError::new(
                    "hyperv_network",
                    "external mode requires a controlled IPv4 gateway",
                )
            })?;
            validate_unicast(gateway_address, "controlled gateway IPv4 address")?;
            let unique_dns = gateway
                .dns_servers
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            if gateway.switch_type != ControlledSwitchType::Internal
                || !gateway.nat_enabled
                || !gateway.firewall_enforced
                || !gateway.packet_capture_enabled
                || !gateway.host_private_ranges_blocked
                || gateway.dns_servers.is_empty()
                || gateway.dns_servers.len() > 8
                || unique_dns.len() != gateway.dns_servers.len()
                || gateway.host_service_port.is_some()
                || gateway_address != gateway.host_ipv4
                || gateway
                    .dns_servers
                    .iter()
                    .any(|address| !is_public_ipv4(*address))
            {
                return Err(SandboxError::new(
                    "hyperv_network",
                    "external mode requires Internal switch, NAT/gateway/firewall/capture/private blocks, and one to eight unique public DNS resolvers",
                ));
            }
        }
    }
    Ok(())
}

fn validate_unicast(address: Ipv4Addr, description: &str) -> SandboxResult<()> {
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        Err(SandboxError::new(
            "hyperv_network",
            format!("{description} is unspecified, loopback, link-local, multicast, or broadcast"),
        ))
    } else {
        Ok(())
    }
}

fn network_address(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(address) & mask)
}

fn broadcast_address(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(address) | !mask)
}

fn same_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix: u8) -> bool {
    network_address(left, prefix) == network_address(right, prefix)
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let raw = u32::from(address);
    !forbidden_ranges()
        .iter()
        .any(|(start, end)| (u32::from(*start)..=u32::from(*end)).contains(&raw))
}

fn forbidden_ranges() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    [
        ("0.0.0.0", "0.255.255.255"),
        ("10.0.0.0", "10.255.255.255"),
        ("100.64.0.0", "100.127.255.255"),
        ("127.0.0.0", "127.255.255.255"),
        ("168.63.129.16", "168.63.129.16"),
        ("169.254.0.0", "169.254.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.0.0.0", "192.0.0.255"),
        ("192.0.2.0", "192.0.2.255"),
        ("192.88.99.0", "192.88.99.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("198.18.0.0", "198.19.255.255"),
        ("198.51.100.0", "198.51.100.255"),
        ("203.0.113.0", "203.0.113.255"),
        ("224.0.0.0", "255.255.255.255"),
    ]
    .into_iter()
    .map(|(start, end)| (start.parse().unwrap(), end.parse().unwrap()))
    .collect()
}

fn forbidden_ipv4_cidrs() -> Vec<String> {
    forbidden_ranges()
        .into_iter()
        .flat_map(|(start, end)| range_to_cidrs(u32::from(start), u32::from(end)))
        .collect()
}

fn public_ipv4_cidrs() -> Vec<String> {
    let mut result = Vec::new();
    let mut cursor = 0u64;
    for (start, end) in forbidden_ranges() {
        let start = u32::from(start) as u64;
        let end = u32::from(end) as u64;
        if cursor < start {
            result.extend(range_to_cidrs(cursor as u32, (start - 1) as u32));
        }
        cursor = end.saturating_add(1);
    }
    if cursor <= u32::MAX as u64 {
        result.extend(range_to_cidrs(cursor as u32, u32::MAX));
    }
    result
}

fn range_to_cidrs(mut start: u32, end: u32) -> Vec<String> {
    let mut result = Vec::new();
    loop {
        let alignment_bits = start.trailing_zeros();
        let remaining = end as u64 - start as u64 + 1;
        let size_bits = 63 - remaining.leading_zeros();
        let host_bits = alignment_bits.min(size_bits);
        result.push(format!("{}/{}", Ipv4Addr::from(start), 32 - host_bits));
        let next = start as u64 + (1u64 << host_bits);
        if next > end as u64 {
            break;
        }
        start = next as u32;
    }
    result
}

fn validate_run_id(run_id: &str) -> SandboxResult<()> {
    if !(16..=64).contains(&run_id.len()) || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SandboxError::new(
            "hyperv_network",
            "run identifier is invalid",
        ));
    }
    Ok(())
}

fn validate_identifier(identifier: &str, description: &str) -> SandboxResult<()> {
    if identifier.trim().is_empty()
        || identifier.len() > 128
        || !identifier.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'{' | b'}' | b':' | b'\\')
        })
    {
        return Err(SandboxError::new(
            "hyperv_network",
            format!("{description} contains unsafe characters"),
        ));
    }
    Ok(())
}

fn allocation_directory_is_allowed(directory: &Path) -> bool {
    if cfg!(test) {
        return directory.is_absolute();
    }
    let Some(program_data) = std::env::var_os("ProgramData").filter(|value| !value.is_empty())
    else {
        return false;
    };
    let expected = PathBuf::from(program_data)
        .join("Foxhole")
        .join("network")
        .join("allocations");
    directory
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let thread_name = std::thread::current()
            .name()
            .unwrap_or("test")
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let path = std::env::temp_dir().join(format!(
            "foxhole-network-{name}-{}-{}",
            std::process::id(),
            thread_name
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }

    fn gateway(directory: PathBuf, mode: ControlledNetworkMode) -> ControlledGatewayConfig {
        ControlledGatewayConfig {
            switch_name: "Foxhole Internal".into(),
            switch_id: "11111111-1111-1111-1111-111111111111".into(),
            switch_type: ControlledSwitchType::Internal,
            gateway_id: "FoxholeNat".into(),
            host_ipv4: Ipv4Addr::new(192, 168, 250, 1),
            prefix_length: 24,
            host_service_port: matches!(mode, ControlledNetworkMode::HostServer).then_some(8080),
            host_adapter_id: "22222222-2222-2222-2222-222222222222".into(),
            guest_address_start: Ipv4Addr::new(192, 168, 250, 10),
            guest_address_end: Ipv4Addr::new(192, 168, 250, 10),
            dns_servers: if matches!(mode, ControlledNetworkMode::External) {
                vec![Ipv4Addr::new(1, 1, 1, 1)]
            } else {
                Vec::new()
            },
            gateway_ipv4: matches!(mode, ControlledNetworkMode::External)
                .then_some(Ipv4Addr::new(192, 168, 250, 1)),
            allocation_directory: directory,
            firewall_enforced: true,
            packet_capture_enabled: matches!(mode, ControlledNetworkMode::External),
            host_private_ranges_blocked: matches!(mode, ControlledNetworkMode::External),
            nat_enabled: matches!(mode, ControlledNetworkMode::External),
            owned_by_run: false,
        }
    }

    #[test]
    fn missing_gateway_and_forbidden_host_switches_fail_closed() {
        assert!(plan(&NetworkPolicy::HostServer, None).is_err());
        assert!(plan(&NetworkPolicy::AllowInternet, None).is_err());
        let directory = temporary_directory("switches");
        let mut config = gateway(directory.clone(), ControlledNetworkMode::HostServer);
        config.switch_name = "Default Switch".into();
        assert!(plan(&NetworkPolicy::HostServer, Some(&config)).is_err());
        config = gateway(directory.clone(), ControlledNetworkMode::HostServer);
        config.switch_type = ControlledSwitchType::External;
        assert!(plan(&NetworkPolicy::HostServer, Some(&config)).is_err());
        config = gateway(directory.clone(), ControlledNetworkMode::HostServer);
        config.switch_type = ControlledSwitchType::Private;
        assert!(plan(&NetworkPolicy::HostServer, Some(&config)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_host_ip_wrong_nat_and_unattested_external_controls_fail() {
        let directory = temporary_directory("gateway-validation");
        let mut config = gateway(directory.clone(), ControlledNetworkMode::HostServer);
        config.host_ipv4 = Ipv4Addr::UNSPECIFIED;
        assert!(plan(&NetworkPolicy::HostServer, Some(&config)).is_err());
        config = gateway(directory.clone(), ControlledNetworkMode::HostServer);
        config.nat_enabled = true;
        assert!(plan(&NetworkPolicy::HostServer, Some(&config)).is_err());
        config = gateway(directory.clone(), ControlledNetworkMode::External);
        config.packet_capture_enabled = false;
        assert!(plan(&NetworkPolicy::AllowInternet, Some(&config)).is_err());
        config = gateway(directory.clone(), ControlledNetworkMode::External);
        config.dns_servers.push(Ipv4Addr::new(1, 1, 1, 1));
        assert!(plan(&NetworkPolicy::AllowInternet, Some(&config)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn host_server_creates_only_endpoint_allow_and_default_block_rules() {
        let directory = temporary_directory("host-policy");
        let mut plan = plan(
            &NetworkPolicy::HostServer,
            Some(&gateway(
                directory.clone(),
                ControlledNetworkMode::HostServer,
            )),
        )
        .unwrap();
        let run_id = "11111111111111111111111111111111";
        let lease = activate(&mut plan, run_id, &directory).unwrap().unwrap();
        let HyperVNetworkPlan::Controlled {
            firewall_rules,
            dns_servers,
            gateway_ipv4,
            capture_session,
            ..
        } = &plan
        else {
            unreachable!()
        };
        let allows = firewall_rules
            .iter()
            .filter(|rule| rule.action == "Allow")
            .collect::<Vec<_>>();
        assert_eq!(allows.len(), 2);
        assert!(allows.iter().all(|rule| {
            rule.protocol == "TCP"
                && rule.remote_addresses == ["192.168.250.1"]
                && rule.remote_ports == ["8080"]
        }));
        assert!(allows.iter().any(|rule| rule.direction == "Outbound"));
        assert!(allows.iter().any(|rule| rule.direction == "Inbound"));
        assert!(dns_servers.is_empty());
        assert!(gateway_ipv4.is_none());
        assert!(capture_session.is_none());
        release_guest_address(&lease).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_public_ranges_block_local_metadata_and_multicast() {
        for blocked in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(168, 63, 129, 16),
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(
                !is_public_ipv4(blocked),
                "blocked address accepted: {blocked}"
            );
        }
        assert!(is_public_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_public_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn external_rules_allow_only_approved_dns_and_public_tcp() {
        let directory = temporary_directory("external-policy");
        let mut config = gateway(directory.clone(), ControlledNetworkMode::External);
        config.dns_servers.push(Ipv4Addr::new(8, 8, 8, 8));
        let mut plan = plan(&NetworkPolicy::AllowInternet, Some(&config)).unwrap();
        let lease = activate(&mut plan, "88888888888888888888888888888888", &directory)
            .unwrap()
            .unwrap();
        let HyperVNetworkPlan::Controlled { firewall_rules, .. } = &plan else {
            unreachable!()
        };
        let allows = firewall_rules
            .iter()
            .filter(|rule| rule.action == "Allow")
            .collect::<Vec<_>>();
        let dns_allows = allows
            .iter()
            .filter(|rule| rule.remote_ports == ["53"])
            .collect::<Vec<_>>();
        assert_eq!(dns_allows.len(), 4);
        assert!(dns_allows.iter().all(|rule| {
            rule.protocol == "Any"
                && !rule.stateful
                && (rule.remote_addresses == ["1.1.1.1"] || rule.remote_addresses == ["8.8.8.8"])
                && rule.local_addresses == [lease.address.to_string()]
        }));
        assert!(dns_allows.iter().any(|rule| rule.direction == "Outbound"));
        assert!(dns_allows.iter().any(|rule| rule.direction == "Inbound"));
        let outbound_weights = firewall_rules
            .iter()
            .filter(|rule| rule.direction == "Outbound")
            .map(|rule| rule.priority)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            outbound_weights.len(),
            firewall_rules
                .iter()
                .filter(|rule| rule.direction == "Outbound")
                .count()
        );
        assert!(
            allows
                .iter()
                .filter(|rule| rule.remote_ports.is_empty())
                .all(|rule| {
                    rule.direction == "Outbound" && rule.protocol == "TCP" && rule.stateful
                })
        );
        assert!(firewall_rules.iter().any(|rule| {
            rule.action == "Deny"
                && rule.direction == "Outbound"
                && rule.protocol == "Any"
                && rule.remote_addresses == ["Any"]
                && rule.remote_ports == ["53"]
        }));
        for blocked in forbidden_ipv4_cidrs() {
            assert!(
                firewall_rules
                    .iter()
                    .any(|rule| rule.action == "Deny"
                        && rule.remote_addresses == [blocked.clone()])
            );
        }
        release_guest_address(&lease).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_guest_configuration_has_gateway_dns_and_no_host_service() {
        let directory = temporary_directory("external-guest");
        let mut plan = plan(
            &NetworkPolicy::AllowInternet,
            Some(&gateway(directory.clone(), ControlledNetworkMode::External)),
        )
        .unwrap();
        let lease = activate(&mut plan, "99999999999999999999999999999999", &directory)
            .unwrap()
            .unwrap();
        let (guest, prefix, gateway, dns, host, port) = guest_configuration(&plan);
        assert_eq!(guest, Some(Ipv4Addr::new(192, 168, 250, 10)));
        assert_eq!(prefix, Some(24));
        assert_eq!(gateway, Some(Ipv4Addr::new(192, 168, 250, 1)));
        assert_eq!(dns, [Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(host, None);
        assert_eq!(port, None);
        release_guest_address(&lease).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn duplicate_address_allocation_and_owner_mismatch_are_rejected() {
        let directory = temporary_directory("lease");
        let address = Ipv4Addr::new(192, 168, 250, 10);
        let first = allocate_guest_address(
            &directory,
            address,
            address,
            "22222222222222222222222222222222",
        )
        .unwrap();
        assert!(
            allocate_guest_address(
                &directory,
                address,
                address,
                "33333333333333333333333333333333"
            )
            .is_err()
        );
        let mut forged = first.clone();
        forged.run_id = "33333333333333333333333333333333".into();
        assert!(release_guest_address(&forged).is_err());
        release_guest_address(&first).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cleanup_journal_rejects_partial_host_firewall_ownership() {
        let run_id = "77777777777777777777777777777777";
        let run_root = temporary_directory("partial-host-firewall");
        let resources = NetworkOwnedResources {
            host_ipv4: Some(Ipv4Addr::new(192, 168, 250, 1)),
            ..NetworkOwnedResources::default()
        };
        assert!(validate_owned_resources(&resources, run_id, &run_root).is_err());
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    fn attachment_and_post_run_drift_checks_cover_all_critical_state() {
        let directory = temporary_directory("drift");
        let mut plan = plan(
            &NetworkPolicy::HostServer,
            Some(&gateway(
                directory.clone(),
                ControlledNetworkMode::HostServer,
            )),
        )
        .unwrap();
        let lease = activate(&mut plan, "44444444444444444444444444444444", &directory)
            .unwrap()
            .unwrap();
        let HyperVNetworkPlan::Controlled {
            switch_id,
            host_adapter_id,
            host_ipv4,
            firewall_rules,
            ..
        } = &plan
        else {
            unreachable!()
        };
        let valid = NetworkAttachment {
            adapter_count: 1,
            switch_id: Some(switch_id.clone()),
            switch_type: Some("Internal".into()),
            host_adapter_id: Some(host_adapter_id.clone()),
            firewall_scope_id: Some("66666666-6666-6666-6666-666666666666".into()),
            host_ipv4: Some(*host_ipv4),
            guest_ipv4: Some(lease.address),
            nat_enabled: false,
            firewall_rule_ids: firewall_rules
                .iter()
                .map(|rule| rule.name.clone())
                .chain(std::iter::once(
                    "Foxhole-44444444444444444444444444444444-host-inbound".to_string(),
                ))
                .collect(),
            capture_active: false,
            ipv6_disabled: true,
            no_unexpected_routes: true,
            warnings: Vec::new(),
        };
        assert!(verify_attachment(&plan, &valid, true).is_ok());
        let mut drift = valid.clone();
        drift.adapter_count = 2;
        assert!(verify_attachment(&plan, &drift, true).is_err());
        drift = valid.clone();
        drift.switch_id = Some("55555555-5555-5555-5555-555555555555".into());
        assert!(verify_attachment(&plan, &drift, true).is_err());
        drift = valid.clone();
        drift.firewall_rule_ids.clear();
        assert!(verify_attachment(&plan, &drift, true).is_err());
        drift = valid;
        drift.guest_ipv4 = None;
        assert!(verify_attachment(&plan, &drift, true).is_err());
        release_guest_address(&lease).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
