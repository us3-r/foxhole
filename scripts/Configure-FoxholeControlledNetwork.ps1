#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('HostOnly', 'External')]
    [string]$Mode,

    [ValidateRange(1, 65535)]
    [uint16]$HostServicePort = 8080,

    [ValidateNotNullOrEmpty()]
    [string[]]$DnsServers = @('1.1.1.1', '8.8.8.8'),

    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

Import-Module Hyper-V -ErrorAction Stop

$programDataRoot = [Environment]::GetFolderPath('CommonApplicationData')
$networkRoot = Join-Path $programDataRoot 'Foxhole\network'
$allocationDirectory = Join-Path $networkRoot 'allocations'

if ($Mode -eq 'HostOnly') {
    $switchName = 'Foxhole Internal'
    $hostAddress = '192.168.250.1'
    $subnet = '192.168.250.0/24'
    $guestStart = '192.168.250.10'
    $guestEnd = '192.168.250.200'
    $gatewayId = 'FoxholeHostOnly'
    $natEnabled = $false
    $gatewayAddress = $null
    $approvedDns = @()
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path $networkRoot 'host-only.json'
    }
} else {
    $switchName = 'Foxhole External NAT'
    $hostAddress = '192.168.251.1'
    $subnet = '192.168.251.0/24'
    $guestStart = '192.168.251.10'
    $guestEnd = '192.168.251.200'
    $gatewayId = 'FoxholeExternalNat'
    $natEnabled = $true
    $gatewayAddress = $hostAddress
    $approvedDns = @($DnsServers)
    if ($approvedDns.Count -lt 1 -or $approvedDns.Count -gt 8 -or @($approvedDns | Sort-Object -Unique).Count -ne $approvedDns.Count) {
        throw 'External mode requires one to eight unique approved DNS resolvers'
    }
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path $networkRoot 'external.json'
    }
}

foreach ($address in @($hostAddress, $guestStart, $guestEnd) + @($approvedDns)) {
    $parsed = [System.Net.IPAddress]::Parse($address)
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 is supported by the controlled network setup: $address"
    }
}

$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($null -eq $switch) {
    if ($PSCmdlet.ShouldProcess($switchName, 'Create persistent Internal Hyper-V switch')) {
        $switch = New-VMSwitch -Name $switchName -SwitchType Internal -ErrorAction Stop
    } else {
        return
    }
}
if ([string]$switch.Name -eq 'Default Switch' -or [string]$switch.SwitchType -ne 'Internal') {
    throw "The configured switch must be a non-default Internal switch: $switchName"
}

$adapterName = "vEthernet ($switchName)"
$hostAdapter = Get-NetAdapter -Name $adapterName -ErrorAction Stop
if ([string]$hostAdapter.Status -ne 'Up') {
    throw "The controlled host adapter is not up: $adapterName"
}

if ($PSCmdlet.ShouldProcess($adapterName, "Set the fixed address $hostAddress/24 and disable IPv6")) {
    Set-NetIPInterface -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop | Out-Null
    @(Get-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue) |
        Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
    New-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -IPAddress $hostAddress -PrefixLength 24 -Type Unicast -ErrorAction Stop | Out-Null
    Disable-NetAdapterBinding -Name $adapterName -ComponentID ms_tcpip6 -ErrorAction Stop | Out-Null
}

$addresses = @(Get-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
if ($addresses.Count -ne 1 -or [string]$addresses[0].IPAddress -ne $hostAddress -or [uint32]$addresses[0].PrefixLength -ne 24) {
    throw 'The controlled host adapter did not converge to its one expected fixed IPv4 address'
}
$ipv6 = Get-NetAdapterBinding -Name $adapterName -ComponentID ms_tcpip6 -ErrorAction Stop
if ([bool]$ipv6.Enabled) {
    throw 'IPv6 remained enabled on the controlled host adapter'
}
if (@(Get-NetRoute -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object DestinationPrefix -eq '0.0.0.0/0').Count -ne 0) {
    throw 'The controlled host adapter has an unexpected default route'
}

$matchingNat = @(Get-NetNat -ErrorAction Stop | Where-Object InternalIPInterfaceAddressPrefix -eq $subnet)
if ($Mode -eq 'HostOnly') {
    if ($matchingNat.Count -ne 0) {
        throw 'Host-only setup refuses to continue while a NAT owns 192.168.250.0/24; remove it explicitly first'
    }
} else {
    if ($matchingNat.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($gatewayId, "Create persistent NAT for $subnet")) {
            New-NetNat -Name $gatewayId -InternalIPInterfaceAddressPrefix $subnet -ErrorAction Stop | Out-Null
        }
    } elseif ($matchingNat.Count -ne 1 -or [string]$matchingNat[0].Name -ne $gatewayId) {
        throw 'The external subnet is claimed by an unexpected or ambiguous NAT'
    }
    $matchingNat = @(Get-NetNat -ErrorAction Stop | Where-Object InternalIPInterfaceAddressPrefix -eq $subnet)
    if ($matchingNat.Count -ne 1 -or [string]$matchingNat[0].Name -ne $gatewayId -or -not [bool]$matchingNat[0].Active) {
        throw 'The configured external NAT is not uniquely present and active'
    }
}

New-Item -ItemType Directory -Path $networkRoot -Force | Out-Null
New-Item -ItemType Directory -Path $allocationDirectory -Force | Out-Null
& icacls.exe $allocationDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to protect the guest-address allocation directory ACL'
}

$config = [ordered]@{
    switch_name = $switchName
    switch_id = [string]$switch.Id
    switch_type = 'internal'
    gateway_id = $gatewayId
    host_ipv4 = $hostAddress
    prefix_length = 24
    host_service_port = if ($Mode -eq 'HostOnly') { [uint16]$HostServicePort } else { $null }
    host_adapter_id = [string]$hostAdapter.InterfaceGuid
    guest_address_start = $guestStart
    guest_address_end = $guestEnd
    dns_servers = @($approvedDns)
    gateway_ipv4 = $gatewayAddress
    allocation_directory = $allocationDirectory
    firewall_enforced = $true
    packet_capture_enabled = ($Mode -eq 'External')
    host_private_ranges_blocked = ($Mode -eq 'External')
    nat_enabled = $natEnabled
    owned_by_run = $false
}

$configParent = Split-Path -Parent $ConfigPath
if ([string]::IsNullOrWhiteSpace($configParent)) {
    throw 'ConfigPath must include an absolute parent directory'
}
New-Item -ItemType Directory -Path $configParent -Force | Out-Null
$temporaryConfig = "$ConfigPath.$([guid]::NewGuid().ToString('N')).tmp"
$configJson = $config | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($temporaryConfig, $configJson, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporaryConfig -Destination $ConfigPath -Force

Write-Host "Verified $Mode controlled networking."
Write-Host "Switch: $switchName ($($switch.Id), Internal)"
Write-Host "Host adapter: $($hostAdapter.InterfaceGuid), $hostAddress/24"
Write-Host "Configuration: $ConfigPath"
