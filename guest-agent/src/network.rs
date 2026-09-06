use crate::runner::{AgentError, AgentResult};
use foxhole::sandbox::backend::{IpNetwork, NetworkPolicy};
use foxhole::sandbox::hyperv::guest_protocol::{
    GuestNetworkAttestation, GuestNetworkPolicy, GuestRunRequest,
};

pub fn sandbox_network_policy(request: &GuestRunRequest) -> AgentResult<NetworkPolicy> {
    match request.network_policy {
        GuestNetworkPolicy::DenyAll => Ok(NetworkPolicy::DenyAll),
        GuestNetworkPolicy::HostServer => request
            .host_service_ipv4
            .map(|address| {
                NetworkPolicy::AllowList(vec![IpNetwork::V4 {
                    address,
                    prefix: 32,
                }])
            })
            .ok_or_else(|| {
                AgentError::new(
                    "network",
                    "missing_host_service",
                    "host_server request omitted its validated host endpoint",
                )
            }),
        GuestNetworkPolicy::AllowInternet => Ok(NetworkPolicy::AllowInternet),
        GuestNetworkPolicy::CaptureOnly => Ok(NetworkPolicy::CaptureOnly),
        GuestNetworkPolicy::AllowList => request
            .allowed_networks
            .iter()
            .map(|entry| {
                entry.parse::<IpNetwork>().map_err(|error| {
                    AgentError::new(
                        "network",
                        "invalid_allow_list",
                        format!("convert allow-list entry {entry:?}: {error}"),
                    )
                })
            })
            .collect::<AgentResult<Vec<_>>>()
            .map(NetworkPolicy::AllowList),
    }
}

#[cfg(target_os = "windows")]
const CONFIGURE_NIC_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $stage = 'decode request'
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $stage = 'enumerate guest adapters'
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop)
    if ($adapters.Count -ne 1) { throw 'The guest must expose exactly one physical/synthetic NIC' }
    $adapter = $adapters[0]
    $stage = 'disable IPv6 binding'
    Disable-NetAdapterBinding -InterfaceDescription $adapter.InterfaceDescription -ComponentID ms_tcpip6 -ErrorAction Stop | Out-Null
    $stage = 'disable DHCP and weak host routing'
    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled -WeakHostSend Disabled -WeakHostReceive Disabled -ErrorAction Stop | Out-Null
    $stage = 'remove existing IPv4 routes'
    Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction Stop
    $stage = 'remove existing IPv4 addresses'
    Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
    $parameters = @{
        InterfaceIndex = $adapter.ifIndex
        IPAddress = [string]$request.guest_ipv4
        PrefixLength = [uint32]$request.prefix_length
        AddressFamily = 'IPv4'
        ErrorAction = 'Stop'
    }
    if ($null -ne $request.gateway_ipv4) { $parameters.DefaultGateway = [string]$request.gateway_ipv4 }
    $stage = 'apply static IPv4 address and gateway'
    New-NetIPAddress @parameters | Out-Null
    $stage = 'apply DNS resolver policy'
    if (@($request.dns_servers).Count -eq 0) {
        # Windows' reset mode can restore image/DHCP defaults. Point the resolver at guest
        # loopback instead; the adapter ACL independently blocks every DNS destination.
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @('127.0.0.1') -ErrorAction Stop
        Set-DnsClient -InterfaceIndex $adapter.ifIndex -RegisterThisConnectionsAddress $false -UseSuffixWhenRegistering $false -ErrorAction Stop
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($request.dns_servers) -ErrorAction Stop
    }
    $stage = 'disable NetBIOS'
    $configuration = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex=" + [string]$adapter.ifIndex) -ErrorAction Stop
    if ($null -eq $configuration) { throw 'The guest NIC has no WMI network configuration object' }
    $netbiosResult = Invoke-CimMethod -InputObject $configuration -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction Stop
    if ([uint32]$netbiosResult.ReturnValue -ne 0) { throw 'Windows rejected the request to disable NetBIOS' }
    $configuration = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex=" + [string]$adapter.ifIndex) -ErrorAction Stop
    if ([uint32]$configuration.TcpipNetbiosOptions -ne 2) { throw 'NetBIOS remained enabled on the controlled guest NIC' }
    $stage = 'attest static IPv4 address'
    $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        [string]$_.IPAddress -eq [string]$request.guest_ipv4 -and [uint32]$_.PrefixLength -eq [uint32]$request.prefix_length
    })
    if ($addresses.Count -ne 1) { throw 'The guest IPv4 address was not applied exactly once' }
    $stage = 'attest default route policy'
    $defaults = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    if ($null -eq $request.gateway_ipv4) {
        if ($defaults.Count -ne 0) { throw 'Host-server mode must not have a default route' }
    } elseif ($defaults.Count -ne 1 -or [string]$defaults[0].NextHop -ne [string]$request.gateway_ipv4) {
        throw 'The external-mode default route is missing or wrong'
    }
    $stage = 'attest DNS resolver policy'
    $observedDns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
    $expectedDns = @($request.dns_servers)
    if ($expectedDns.Count -eq 0) {
        if ($observedDns.Count -ne 1 -or [string]$observedDns[0] -ne '127.0.0.1') { throw 'DNS was not disabled to guest loopback' }
        $dns = @()
    } else {
        $dns = @($observedDns)
        $observedDnsKey = (@($dns | Sort-Object) -join ',')
        $expectedDnsKey = (@($expectedDns | Sort-Object) -join ',')
        if ($observedDnsKey -ne $expectedDnsKey) {
            throw ('DNS resolver configuration does not match the request (expected ' + $expectedDnsKey + '; observed ' + $observedDnsKey + ')')
        }
    }
    $stage = 'attest IPv6 binding state'
    $ipv6Binding = Get-NetAdapterBinding -InterfaceDescription $adapter.InterfaceDescription -ComponentID ms_tcpip6 -ErrorAction Stop
    if ([bool]$ipv6Binding.Enabled) { throw 'IPv6 remained enabled on the controlled guest NIC' }
    $data = [ordered]@{
        interface_index = [uint32]$adapter.ifIndex
        interface_guid = [string]$adapter.InterfaceGuid
        mac_address = [string]$adapter.MacAddress
        guest_ipv4 = [string]$request.guest_ipv4
        prefix_length = [uint32]$request.prefix_length
        gateway_ipv4 = $request.gateway_ipv4
        dns_servers = @($dns)
        ipv6_disabled = $true
        no_unexpected_routes = $true
    }
    [ordered]@{ schema_version = 1; ok = $true; data = $data } | ConvertTo-Json -Compress -Depth 5
} catch {
    [ordered]@{ schema_version = 1; ok = $false; error = [ordered]@{
        code = 'guest_nic_configuration_failed'; message = ([string]$stage + ': ' + [string]$_.Exception.Message)
    }} | ConvertTo-Json -Compress -Depth 5
}
"#;

pub fn configure_trusted_nic(
    request: &GuestRunRequest,
) -> AgentResult<Option<GuestNetworkAttestation>> {
    if matches!(
        request.network_policy,
        GuestNetworkPolicy::DenyAll
            | GuestNetworkPolicy::AllowList
            | GuestNetworkPolicy::CaptureOnly
    ) {
        return Ok(None);
    }
    #[cfg(target_os = "windows")]
    {
        use serde::Deserialize;
        use std::io::Write;
        use std::path::PathBuf;
        use std::process::{Command, Stdio};

        #[derive(Deserialize)]
        struct Envelope {
            schema_version: u32,
            ok: bool,
            #[serde(default)]
            data: Option<GuestNetworkAttestation>,
            #[serde(default)]
            error: Option<GuestNetworkError>,
        }
        #[derive(Deserialize)]
        struct GuestNetworkError {
            message: String,
        }

        let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
            AgentError::new(
                "network",
                "missing_system_root",
                "SystemRoot is unavailable to the trusted guest agent",
            )
        })?;
        let powershell = PathBuf::from(&system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let input = serde_json::json!({
            "guest_ipv4": request.guest_ipv4,
            "prefix_length": request.prefix_length,
            "gateway_ipv4": request.gateway_ipv4,
            "dns_servers": request.dns_servers,
        });
        let mut child = Command::new(&powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                CONFIGURE_NIC_SCRIPT,
            ])
            .env_clear()
            .env("SystemRoot", &system_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                AgentError::with_source(
                    "network",
                    "start_guest_nic_configuration",
                    format!("start {}", powershell.display()),
                    error,
                )
            })?;
        let encoded = serde_json::to_vec(&input).map_err(|error| {
            AgentError::with_source(
                "network",
                "encode_guest_nic_configuration",
                "encode trusted NIC request",
                error,
            )
        })?;
        child
            .stdin
            .take()
            .ok_or_else(|| {
                AgentError::new(
                    "network",
                    "missing_guest_nic_stdin",
                    "PowerShell NIC configuration stdin was unavailable",
                )
            })?
            .write_all(&encoded)
            .map_err(|error| {
                AgentError::with_source(
                    "network",
                    "write_guest_nic_configuration",
                    "write trusted NIC request",
                    error,
                )
            })?;
        let output = child.wait_with_output().map_err(|error| {
            AgentError::with_source(
                "network",
                "wait_guest_nic_configuration",
                "wait for trusted NIC configuration",
                error,
            )
        })?;
        if !output.status.success() || output.stdout.len() > 64 * 1024 {
            return Err(AgentError::new(
                "network",
                "guest_nic_configuration_process_failed",
                "trusted NIC configuration process failed or exceeded its output bound",
            ));
        }
        let envelope: Envelope = serde_json::from_slice(&output.stdout).map_err(|error| {
            AgentError::with_source(
                "network",
                "decode_guest_nic_configuration",
                "decode trusted NIC attestation",
                error,
            )
        })?;
        if envelope.schema_version != 1 || !envelope.ok {
            return Err(AgentError::new(
                "network",
                "guest_nic_configuration_failed",
                envelope
                    .error
                    .map(|error| error.message)
                    .unwrap_or_else(|| "trusted NIC configuration returned no attestation".into()),
            ));
        }
        let attestation = envelope.data.ok_or_else(|| {
            AgentError::new(
                "network",
                "missing_guest_nic_attestation",
                "trusted NIC configuration returned no attestation",
            )
        })?;
        attestation.validate().map_err(|error| {
            AgentError::new(
                "network",
                "invalid_guest_nic_attestation",
                format!("validate trusted NIC attestation: {error}"),
            )
        })?;
        Ok(Some(attestation))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(AgentError::new(
            "network",
            "unsupported_guest_network_configuration",
            "controlled guest NIC configuration requires Windows",
        ))
    }
}
