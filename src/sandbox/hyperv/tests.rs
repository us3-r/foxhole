use super::capability;
use super::network::{
    self, ControlledNetworkMode, ControlledSwitchType, FirewallRuleSpec, HyperVNetworkPlan,
    NetworkOwnedResources, plan,
};
use super::powershell::{PowerShellExecutor, PowerShellInvocation};
use crate::sandbox::backend::{NetworkPolicy, SandboxError, SandboxResult};
use serde_json::Value;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug)]
struct FakePowerShell {
    responses: Mutex<VecDeque<SandboxResult<Value>>>,
    calls: Mutex<Vec<(&'static str, &'static str, Value)>>,
}

impl FakePowerShell {
    fn new(responses: impl IntoIterator<Item = SandboxResult<Value>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl PowerShellExecutor for FakePowerShell {
    fn execute(&self, invocation: &PowerShellInvocation) -> SandboxResult<Value> {
        self.calls.lock().unwrap().push((
            invocation.operation,
            invocation.script,
            invocation.input.clone(),
        ));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                Err(SandboxError::new(
                    "fake_powershell",
                    "unexpected PowerShell invocation",
                ))
            })
    }
}

#[test]
fn deny_all_is_the_default_safe_host_network_plan() {
    assert_eq!(
        plan(&NetworkPolicy::DenyAll, None).unwrap(),
        HyperVNetworkPlan::DenyAll
    );
}

#[test]
fn capability_detection_is_typed_and_cross_platform_with_a_fake_host() {
    let executor = FakePowerShell::new([Ok(serde_json::json!({
        "available": true,
        "platform_supported": true,
        "hypervisor_present": true,
        "feature_enabled": true,
        "vmms_running": true,
        "management_access": true,
        "module_version": "10.0",
        "missing_cmdlets": [],
        "issues": []
    }))]);
    let report = capability::detect(&executor).unwrap();
    report.require_available().unwrap();
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].1.contains("Get-VMHost"));
    assert_eq!(calls[0].2, serde_json::json!({}));
}

#[test]
fn deny_all_fake_verifies_zero_nics_and_never_interpolates_vm_id() {
    let executor = FakePowerShell::new([Ok(serde_json::json!({
        "adapter_count": 0,
        "switch_id": null
    }))]);
    let plan = HyperVNetworkPlan::DenyAll;
    let vm_id = "11111111-1111-1111-1111-111111111111";
    network::configure(&executor, vm_id, &plan).unwrap();
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(!calls[0].1.contains(vm_id));
    assert_eq!(calls[0].2["vm_id"], vm_id);
}

fn active_host_plan() -> HyperVNetworkPlan {
    HyperVNetworkPlan::Controlled {
        network_mode: ControlledNetworkMode::HostServer,
        switch_name: "Foxhole Internal".into(),
        switch_id: "11111111-1111-1111-1111-111111111111".into(),
        switch_type: ControlledSwitchType::Internal,
        gateway_id: "FoxholeHostOnly".into(),
        host_ipv4: Ipv4Addr::new(192, 168, 250, 1),
        prefix_length: 24,
        host_service_port: Some(8080),
        host_adapter_id: "22222222-2222-2222-2222-222222222222".into(),
        guest_address_start: Ipv4Addr::new(192, 168, 250, 10),
        guest_address_end: Ipv4Addr::new(192, 168, 250, 20),
        dns_servers: Vec::new(),
        gateway_ipv4: None,
        allocation_directory: PathBuf::from(r"C:\ProgramData\Foxhole\network\allocations"),
        nat_enabled: false,
        guest_ipv4: Some(Ipv4Addr::new(192, 168, 250, 10)),
        lease_path: None,
        firewall_rules: vec![FirewallRuleSpec {
            name: "Foxhole-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host-service".into(),
            direction: "Outbound".into(),
            action: "Allow".into(),
            protocol: "TCP".into(),
            priority: 1,
            stateful: true,
            local_addresses: vec!["192.168.250.10".into()],
            remote_addresses: vec!["192.168.250.1".into()],
            remote_ports: vec!["8080".into()],
        }],
        host_firewall_rule_id: Some("Foxhole-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host-inbound".into()),
        capture_session: None,
        capture_file: None,
        firewall_scope_id: Some("33333333-3333-3333-3333-333333333333".into()),
    }
}

fn host_attachment(rule_ids: Vec<&str>) -> Value {
    serde_json::json!({
        "adapter_count": 1,
        "switch_id": "11111111-1111-1111-1111-111111111111",
        "switch_type": "Internal",
        "host_adapter_id": "22222222-2222-2222-2222-222222222222",
        "firewall_scope_id": "33333333-3333-3333-3333-333333333333",
        "host_ipv4": "192.168.250.1",
        "guest_ipv4": null,
        "nat_enabled": false,
        "firewall_rule_ids": rule_ids,
        "capture_active": false,
        "ipv6_disabled": true,
        "no_unexpected_routes": true,
        "warnings": []
    })
}

#[test]
fn controlled_mock_requires_exact_firewall_rules_and_keeps_input_as_data() {
    let rule = "Foxhole-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host-service";
    let host_rule = "Foxhole-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host-inbound";
    let executor = FakePowerShell::new([Ok(host_attachment(vec![rule, host_rule]))]);
    let vm_id = "33333333-3333-3333-3333-333333333333";
    network::configure(&executor, vm_id, &active_host_plan()).unwrap();
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(!calls[0].1.contains(vm_id));
    assert_eq!(calls[0].2["vm_id"], vm_id);
    assert_eq!(calls[0].2["firewall_rules"][0]["remote_ports"][0], "8080");
    drop(calls);

    let overly_broad =
        FakePowerShell::new([Ok(host_attachment(vec![rule, host_rule, "Global-Allow"]))]);
    assert!(network::configure(&overly_broad, vm_id, &active_host_plan()).is_err());
}

#[test]
fn cleanup_mock_removes_only_run_prefixed_resources() {
    let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let rule = format!("Foxhole-{run_id}-host-service");
    let resources = NetworkOwnedResources {
        vm_id: "44444444-4444-4444-4444-444444444444".into(),
        firewall_scope_id: "33333333-3333-3333-3333-333333333333".into(),
        rule_prefix: format!("Foxhole-{run_id}-"),
        firewall_rule_ids: vec![rule.clone()],
        firewall_rules: vec![FirewallRuleSpec {
            name: rule.clone(),
            direction: "Outbound".into(),
            action: "Allow".into(),
            protocol: "TCP".into(),
            priority: 300,
            stateful: true,
            local_addresses: vec!["192.168.250.10".into()],
            remote_addresses: vec!["192.168.250.1".into()],
            remote_ports: vec!["8080".into()],
        }],
        host_firewall_rule_id: None,
        host_ipv4: None,
        host_service_port: None,
        host_adapter_id: None,
        capture_session: Some(format!("FoxholeNet-{run_id}")),
        capture_file: Some(PathBuf::from(r"C:\Foxhole\runs\network-capture.etl")),
        guest_lease: None,
        nat_mapping_ids: Vec::new(),
    };
    let executor = FakePowerShell::new([Ok(serde_json::json!({
        "removed": [format!("firewall:{rule}")]
    }))]);
    network::cleanup_owned_resources(&executor, &resources).unwrap();
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls[0].2["firewall_rule_ids"], serde_json::json!([rule]));
    assert_eq!(calls[0].2["rule_prefix"], format!("Foxhole-{run_id}-"));
    drop(calls);

    let mut forged = resources;
    forged
        .firewall_rule_ids
        .push("unrelated-global-rule".into());
    let no_calls = FakePowerShell::new([]);
    assert!(network::cleanup_owned_resources(&no_calls, &forged).is_err());
    assert!(no_calls.calls.lock().unwrap().is_empty());
}
