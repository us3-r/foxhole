use super::{
    base_image, capability, network,
    powershell::{NativePowerShell, PowerShellExecutor, PowerShellInvocation},
};
use crate::doctor::{CheckStatus as S, DoctorArgs, DoctorNetwork, DoctorReport};
use crate::sandbox::backend::NetworkPolicy;

pub fn inspect(args: &DoctorArgs) -> DoctorReport {
    let mut report = DoctorReport::default();
    let executor = NativePowerShell;
    let mut available = false;
    match capability::detect(&executor) {
        Ok(cap) => {
            for (id, ok, fix) in [
                (
                    "platform",
                    cap.platform_supported,
                    "Use Windows with Hyper-V support.",
                ),
                (
                    "hypervisor",
                    cap.hypervisor_present,
                    "Enable hardware virtualization and restart after enabling Hyper-V.",
                ),
                (
                    "feature",
                    cap.feature_enabled,
                    "Enable the Hyper-V Windows feature in an administrator session.",
                ),
                (
                    "vmms",
                    cap.vmms_running,
                    "Start the Hyper-V Virtual Machine Management service.",
                ),
                (
                    "management_access",
                    cap.management_access,
                    "Run this command from an elevated PowerShell session.",
                ),
                (
                    "hyperv_cmdlets",
                    cap.missing_cmdlets.is_empty(),
                    "Install the Hyper-V PowerShell management tools.",
                ),
            ] {
                report.add(
                    id,
                    if ok { S::Pass } else { S::Fail },
                    if ok {
                        "available"
                    } else {
                        "unavailable or access denied"
                    },
                    (!ok).then_some(fix),
                );
            }
            available = cap.require_available().is_ok();
            report.add(
                "hyperv_module",
                S::NotChecked,
                cap.module_version.unwrap_or_else(|| "not found".into()),
                None,
            );
            if args.network_policy != DoctorNetwork::DenyAll {
                report.add("network_cmdlets", if cap.network_missing_cmdlets.is_empty() { S::Pass } else { S::Fail }, format!("Missing: {:?}", cap.network_missing_cmdlets), Some("Controlled networking needs NetSecurity, NetTCPIP and NetEventPacketCapture cmdlets."));
            }
            for issue in cap.issues {
                report.add(&issue.code, S::Warning, issue.message, None);
            }
        }
        Err(error) => report.add(
            "capability_probe",
            S::Fail,
            error.to_string(),
            Some("Run on a supported Windows Hyper-V host in elevated PowerShell."),
        ),
    }
    match (&args.base_image, &args.base_manifest) {
        (Some(image), Some(manifest)) if available => {
            eprintln!("[doctor] Validating and hashing the execution image; this can take several minutes.");
            match base_image::validate(&executor, &base_image::BaseImageConfig::new(image.clone(), manifest.clone())) {
                Ok(base) => report.add("base_image", S::Pass, format!("{}; image_version={}; protocol={}; sha256={}", image.display(), base.manifest.image_version, base.manifest.guest_protocol_version, base.manifest.sha256), None),
                Err(error) => report.add("base_image", S::Fail, error.to_string(), Some("Use the matching sealed VHDX/manifest; rerun Finalize-FoxholeBaseImage.ps1 only after intentional image provisioning.")),
            }
        }
        (Some(_), Some(_)) => report.add("base_image", S::NotChecked, "Image validation requires working Hyper-V management access", Some("Fix host checks and rerun doctor.")),
        _ => report.add("base_image", S::Fail, "Execution image and manifest must both be supplied", Some("Pass --base-image and --base-manifest, or set FOXHOLE_HYPERV_BASE_IMAGE and FOXHOLE_HYPERV_BASE_MANIFEST.")),
    }
    if args.network_policy == DoctorNetwork::DenyAll {
        report.add(
            "network",
            S::Pass,
            "deny-all selected; no NIC or controlled gateway is required",
            None,
        );
    } else {
        match args
            .gateway_config
            .as_deref()
            .ok_or_else(|| "Missing --gateway-config".to_string())
            .and_then(|path| {
                crate::doctor::read_config::<network::ControlledGatewayConfig>(path)
                    .map_err(|e| e.to_string())
            })
            .and_then(|gateway| {
                let policy = if args.network_policy == DoctorNetwork::HostServer {
                    NetworkPolicy::HostServer
                } else {
                    NetworkPolicy::AllowInternet
                };
                network::plan(&policy, Some(&gateway)).map_err(|e| e.to_string())?;
                Ok(gateway)
            }) {
            Ok(gateway) => {
                report.add(
                    "gateway_config",
                    S::Pass,
                    format!(
                        "{}; host={}:{:?}; NAT={}",
                        gateway.switch_name,
                        gateway.host_ipv4,
                        gateway.host_service_port,
                        gateway.nat_enabled
                    ),
                    None,
                );
                let invocation = PowerShellInvocation::new(
                    "doctor read-only switch inspection",
                    r#"
$ErrorActionPreference='Stop'
try {
 $r=[Console]::In.ReadToEnd() | ConvertFrom-Json
 $s=Get-VMSwitch -Id ([guid]$r.id) -ErrorAction Stop
 $valid=([string]$s.SwitchType -eq 'Internal' -and [string]$s.Name -eq [string]$r.name)
 @{schema_version=1;ok=$true;data=@{matches=$valid}} | ConvertTo-Json -Compress
} catch { @{schema_version=1;ok=$false;error=@{code='doctor_switch';message=$_.Exception.Message}} | ConvertTo-Json -Compress }
"#,
                    serde_json::json!({"id":gateway.switch_id,"name":gateway.switch_name}),
                );
                match executor.execute(&invocation) {
                    Ok(value) if value["matches"] == true => report.add(
                        "gateway_switch",
                        S::Pass,
                        "Configured internal switch identity matches the host",
                        None,
                    ),
                    result => report.add(
                        "gateway_switch",
                        S::Fail,
                        format!("Switch missing, inaccessible, or changed: {result:?}"),
                        Some(
                            "Review the gateway configuration and controlled-network provisioning.",
                        ),
                    ),
                }
                report.add("network_attestation", S::NotChecked, "NAT, routes, host listener, firewall and per-VM ACL enforcement are checked by the live run; a matching switch alone is insufficient", Some("Run the live host-server smoke test."));
            }
            Err(error) => report.add(
                "gateway_config",
                S::Fail,
                error,
                Some("Supply a gateway JSON provisioned for the selected network policy."),
            ),
        }
        #[cfg(windows)]
        {
            let converter = super::powershell::system_powershell_path()
                .ok()
                .and_then(|path| path.ancestors().nth(3).map(|p| p.join("etl2pcapng.exe")));
            let exists = converter.as_ref().is_some_and(|p| p.is_file());
            report.add("host_pcapng_converter", if exists { S::Pass } else { S::Warning }, if exists { "System32/etl2pcapng.exe is present; conversion still needs live verification" } else { "System32/etl2pcapng.exe is missing; host ETL may be retained without PCAPNG" }, (!exists).then_some("Install the administrator-approved etl2pcapng binary at the documented System32 path."));
        }
    }
    report
}
