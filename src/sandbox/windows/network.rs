use crate::sandbox::backend::{IpNetwork, NetworkPolicy, SandboxError, SandboxResult};
use std::sync::Arc;
use windows::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_MATCH_EQUAL, FWP_SID, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_ACTION0, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmProviderAdd0, FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::Security::{PSID, SID};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR};

const PROVIDER_KEY: GUID = GUID::from_u128(0xecf95535_4b08_42f5_b482_1c9e5c6df15f);
const SUBLAYER_KEY: GUID = GUID::from_u128(0xda9f060e_f675_41ce_bf98_7a52a544c75d);
const PROVIDER_NAME: &str = "Foxhole restricted-process provider";
const SUBLAYER_NAME: &str = "Foxhole per-run network policy";

pub(super) struct NetworkFilters {
    api: Arc<dyn WfpApi>,
    engine: HANDLE,
    filter_ids: Vec<u64>,
    cleanup_warnings: Vec<String>,
}

impl NetworkFilters {
    pub(super) fn install(policy: &NetworkPolicy, package_sid: PSID) -> SandboxResult<Self> {
        Self::install_with_api(policy, package_sid, Arc::new(SystemWfpApi))
    }

    fn install_with_api(
        policy: &NetworkPolicy,
        package_sid: PSID,
        api: Arc<dyn WfpApi>,
    ) -> SandboxResult<Self> {
        if matches!(policy, NetworkPolicy::HostServer) {
            return Err(SandboxError::new(
                "network_filters",
                "host_server is a Hyper-V-only policy; the restricted-process backend requires an explicit allow-list",
            ));
        }
        if matches!(
            policy,
            NetworkPolicy::AllowInternet | NetworkPolicy::CaptureOnly
        ) {
            return Ok(Self {
                api,
                engine: HANDLE::default(),
                filter_ids: Vec::new(),
                cleanup_warnings: Vec::new(),
            });
        }
        if package_sid.is_invalid() {
            return Err(SandboxError::new(
                "network_filters",
                "cannot install WFP filters without the per-run AppContainer SID",
            ));
        }

        ensure_provider_and_sublayer(api.as_ref())?;
        let mut session_name = wide("Foxhole dynamic sandbox run");
        let session = FWPM_SESSION0 {
            displayData: display_data(&mut session_name, None),
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 5_000,
            ..Default::default()
        };
        let engine = open_engine(api.as_ref(), Some(&session))?;
        let mut filters = Self {
            api,
            engine,
            filter_ids: Vec::new(),
            cleanup_warnings: Vec::new(),
        };

        let install_result = filters.install_transaction(policy, package_sid);
        if let Err(error) = install_result {
            filters.close_engine();
            return Err(error);
        }
        Ok(filters)
    }

    pub(super) fn filter_ids(&self) -> &[u64] {
        &self.filter_ids
    }

    pub(super) fn cleanup(&mut self) -> SandboxResult<()> {
        if self.engine.is_invalid() {
            return Ok(());
        }
        for id in self.filter_ids.drain(..).rev() {
            let status = self.api.filter_delete(self.engine, id);
            if status != 0 {
                self.cleanup_warnings
                    .push(format!("failed to delete WFP filter {id}: 0x{status:08x}"));
            }
        }
        self.close_engine();
        if self.cleanup_warnings.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::new(
                "network_cleanup",
                self.cleanup_warnings.join("; "),
            ))
        }
    }

    fn install_transaction(
        &mut self,
        policy: &NetworkPolicy,
        package_sid: PSID,
    ) -> SandboxResult<()> {
        status(
            self.api.transaction_begin(self.engine),
            "begin WFP filter transaction",
        )?;
        let result = (|| {
            match policy {
                NetworkPolicy::DenyAll => {}
                NetworkPolicy::AllowList(entries) => {
                    for entry in entries {
                        match entry {
                            IpNetwork::V4 { .. } => self.add_allow_filter(
                                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                package_sid,
                                *entry,
                            )?,
                            IpNetwork::V6 { .. } => self.add_allow_filter(
                                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                package_sid,
                                *entry,
                            )?,
                        }
                    }
                }
                NetworkPolicy::HostServer
                | NetworkPolicy::AllowInternet
                | NetworkPolicy::CaptureOnly => unreachable!(),
            }

            self.add_package_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                package_sid,
                FWP_ACTION_BLOCK,
                1,
                "Foxhole block outbound IPv4",
            )?;
            self.add_package_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                package_sid,
                FWP_ACTION_BLOCK,
                1,
                "Foxhole block outbound IPv6",
            )?;
            self.add_package_filter(
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                package_sid,
                FWP_ACTION_BLOCK,
                1,
                "Foxhole block inbound IPv4",
            )?;
            self.add_package_filter(
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                package_sid,
                FWP_ACTION_BLOCK,
                1,
                "Foxhole block inbound IPv6",
            )?;
            status(
                self.api.transaction_commit(self.engine),
                "commit WFP filter transaction",
            )
        })();

        if result.is_err() {
            self.api.transaction_abort(self.engine);
            self.filter_ids.clear();
        }
        result
    }

    fn add_package_filter(
        &mut self,
        layer: GUID,
        package_sid: PSID,
        action: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
        weight: u8,
        name: &str,
    ) -> SandboxResult<()> {
        let mut package_condition = package_condition(package_sid);
        self.add_filter(
            layer,
            std::slice::from_mut(&mut package_condition),
            action,
            weight,
            name,
        )
    }

    fn add_allow_filter(
        &mut self,
        layer: GUID,
        package_sid: PSID,
        network: IpNetwork,
    ) -> SandboxResult<()> {
        let package = package_condition(package_sid);
        let mut v4;
        let mut v6;
        let address = match network {
            IpNetwork::V4 { address, prefix } => {
                v4 = FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(address.octets()),
                    mask: prefix_mask_v4(prefix),
                };
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: &mut v4,
                        },
                    },
                }
            }
            IpNetwork::V6 { address, prefix } => {
                v6 = FWP_V6_ADDR_AND_MASK {
                    addr: address.octets(),
                    prefixLength: prefix,
                };
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                            v6AddrMask: &mut v6,
                        },
                    },
                }
            }
        };
        let mut conditions = [package, address];
        self.add_filter(
            layer,
            &mut conditions,
            FWP_ACTION_PERMIT,
            15,
            &format!("Foxhole allow {network}"),
        )
    }

    fn add_filter(
        &mut self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
        weight: u8,
        name: &str,
    ) -> SandboxResult<()> {
        let mut provider_key = PROVIDER_KEY;
        let mut name = wide(name);
        let filter = FWPM_FILTER0 {
            displayData: display_data(&mut name, None),
            flags: if action == FWP_ACTION_BLOCK {
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
            } else {
                Default::default()
            },
            providerKey: &mut provider_key,
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0u64;
        status(
            self.api.filter_add(self.engine, &filter, &mut id),
            "add per-run WFP filter",
        )?;
        self.filter_ids.push(id);
        Ok(())
    }

    fn close_engine(&mut self) {
        if !self.engine.is_invalid() {
            self.api.engine_close(self.engine);
            self.engine = HANDLE::default();
        }
    }
}

impl Drop for NetworkFilters {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn ensure_provider_and_sublayer(api: &dyn WfpApi) -> SandboxResult<()> {
    let engine = open_engine(api, None)?;
    let result = (|| {
        status(
            api.transaction_begin(engine),
            "begin WFP provider transaction",
        )?;
        let mut provider_name = wide(PROVIDER_NAME);
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display_data(&mut provider_name, None),
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        let provider_status = api.provider_add(engine, &provider);
        allow_already_exists(provider_status, "register the Foxhole WFP provider")?;

        let mut sublayer_name = wide(SUBLAYER_NAME);
        let mut provider_key = PROVIDER_KEY;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&mut sublayer_name, None),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            weight: 0x7000,
            ..Default::default()
        };
        let sublayer_status = api.sublayer_add(engine, &sublayer);
        allow_already_exists(sublayer_status, "register the Foxhole WFP sublayer")?;
        status(
            api.transaction_commit(engine),
            "commit WFP provider transaction",
        )
    })();
    if result.is_err() {
        api.transaction_abort(engine);
    }
    api.engine_close(engine);
    result
}

fn open_engine(api: &dyn WfpApi, session: Option<&FWPM_SESSION0>) -> SandboxResult<HANDLE> {
    let mut engine = HANDLE::default();
    status(
        api.engine_open(session, &mut engine),
        "open the WFP policy engine",
    )?;
    Ok(engine)
}

trait WfpApi: Send + Sync {
    fn engine_open(&self, session: Option<&FWPM_SESSION0>, engine: &mut HANDLE) -> u32;
    fn engine_close(&self, engine: HANDLE);
    fn transaction_begin(&self, engine: HANDLE) -> u32;
    fn transaction_commit(&self, engine: HANDLE) -> u32;
    fn transaction_abort(&self, engine: HANDLE);
    fn provider_add(&self, engine: HANDLE, provider: &FWPM_PROVIDER0) -> u32;
    fn sublayer_add(&self, engine: HANDLE, sublayer: &FWPM_SUBLAYER0) -> u32;
    fn filter_add(&self, engine: HANDLE, filter: &FWPM_FILTER0, id: &mut u64) -> u32;
    fn filter_delete(&self, engine: HANDLE, id: u64) -> u32;
}

struct SystemWfpApi;

impl WfpApi for SystemWfpApi {
    fn engine_open(&self, session: Option<&FWPM_SESSION0>, engine: &mut HANDLE) -> u32 {
        unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                session.map(|session| session as *const _),
                engine,
            )
        }
    }

    fn engine_close(&self, engine: HANDLE) {
        unsafe { FwpmEngineClose0(engine) };
    }

    fn transaction_begin(&self, engine: HANDLE) -> u32 {
        unsafe { FwpmTransactionBegin0(engine, 0) }
    }

    fn transaction_commit(&self, engine: HANDLE) -> u32 {
        unsafe { FwpmTransactionCommit0(engine) }
    }

    fn transaction_abort(&self, engine: HANDLE) {
        unsafe { FwpmTransactionAbort0(engine) };
    }

    fn provider_add(&self, engine: HANDLE, provider: &FWPM_PROVIDER0) -> u32 {
        unsafe { FwpmProviderAdd0(engine, provider, None) }
    }

    fn sublayer_add(&self, engine: HANDLE, sublayer: &FWPM_SUBLAYER0) -> u32 {
        unsafe { FwpmSubLayerAdd0(engine, sublayer, None) }
    }

    fn filter_add(&self, engine: HANDLE, filter: &FWPM_FILTER0, id: &mut u64) -> u32 {
        unsafe { FwpmFilterAdd0(engine, filter, None, Some(id)) }
    }

    fn filter_delete(&self, engine: HANDLE, id: u64) -> u32 {
        unsafe { FwpmFilterDeleteById0(engine, id) }
    }
}

fn package_condition(package_sid: PSID) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
            r#type: FWP_SID,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                sid: package_sid.0.cast::<SID>(),
            },
        },
    }
}

fn display_data(name: &mut [u16], description: Option<&mut [u16]>) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: PWSTR(name.as_mut_ptr()),
        description: description
            .map(|description| PWSTR(description.as_mut_ptr()))
            .unwrap_or(PWSTR::null()),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn allow_already_exists(status_code: u32, operation: &'static str) -> SandboxResult<()> {
    if status_code == 0 || status_code == FWP_E_ALREADY_EXISTS.0 as u32 {
        Ok(())
    } else {
        status(status_code, operation)
    }
}

fn status(status_code: u32, operation: &'static str) -> SandboxResult<()> {
    if status_code == 0 {
        Ok(())
    } else {
        Err(SandboxError::new(
            "network_filters",
            format!("{operation} failed with status 0x{status_code:08x}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeWfpApi {
        fail: Option<&'static str>,
        next_id: AtomicU64,
        calls: Mutex<Vec<&'static str>>,
    }

    impl FakeWfpApi {
        fn new(fail: Option<&'static str>) -> Self {
            Self {
                fail,
                next_id: AtomicU64::new(1),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn status(&self, operation: &'static str) -> u32 {
            self.calls.lock().unwrap().push(operation);
            if self.fail == Some(operation) { 5 } else { 0 }
        }
    }

    impl WfpApi for FakeWfpApi {
        fn engine_open(&self, session: Option<&FWPM_SESSION0>, engine: &mut HANDLE) -> u32 {
            let operation = if session.is_some() {
                "open_dynamic"
            } else {
                "open_provider"
            };
            let status = self.status(operation);
            if status == 0 {
                *engine = HANDLE(std::ptr::dangling_mut());
            }
            status
        }

        fn engine_close(&self, _engine: HANDLE) {
            self.calls.lock().unwrap().push("close");
        }

        fn transaction_begin(&self, _engine: HANDLE) -> u32 {
            self.status("begin")
        }

        fn transaction_commit(&self, _engine: HANDLE) -> u32 {
            self.status("commit")
        }

        fn transaction_abort(&self, _engine: HANDLE) {
            self.calls.lock().unwrap().push("abort");
        }

        fn provider_add(&self, _engine: HANDLE, _provider: &FWPM_PROVIDER0) -> u32 {
            self.status("provider")
        }

        fn sublayer_add(&self, _engine: HANDLE, _sublayer: &FWPM_SUBLAYER0) -> u32 {
            self.status("sublayer")
        }

        fn filter_add(&self, _engine: HANDLE, _filter: &FWPM_FILTER0, id: &mut u64) -> u32 {
            let status = self.status("filter_add");
            if status == 0 {
                *id = self.next_id.fetch_add(1, Ordering::Relaxed);
            }
            status
        }

        fn filter_delete(&self, _engine: HANDLE, _id: u64) -> u32 {
            self.status("filter_delete")
        }
    }

    fn fake_sid() -> PSID {
        PSID(std::ptr::dangling_mut())
    }

    #[test]
    fn ipv4_prefix_masks_use_wfp_host_order_values() {
        assert_eq!(prefix_mask_v4(0), 0);
        assert_eq!(prefix_mask_v4(24), 0xffff_ff00);
        assert_eq!(prefix_mask_v4(32), u32::MAX);
    }

    #[test]
    fn non_enforcing_policies_do_not_open_the_wfp_engine() {
        for policy in [NetworkPolicy::AllowInternet, NetworkPolicy::CaptureOnly] {
            let mut filters = NetworkFilters::install(&policy, PSID::default()).unwrap();
            assert!(filters.filter_ids().is_empty());
            assert!(filters.cleanup().is_ok());
        }
    }

    #[test]
    fn enforcing_policies_reject_an_invalid_package_sid() {
        for policy in [NetworkPolicy::DenyAll, NetworkPolicy::AllowList(Vec::new())] {
            let error = match NetworkFilters::install(&policy, PSID::default()) {
                Ok(_) => panic!("invalid SID must fail closed"),
                Err(error) => error,
            };
            assert_eq!(error.stage, "network_filters");
        }
    }

    #[test]
    fn status_helpers_cover_success_already_exists_and_failure() {
        assert!(status(0, "success").is_ok());
        assert!(allow_already_exists(0, "success").is_ok());
        assert!(allow_already_exists(FWP_E_ALREADY_EXISTS.0 as u32, "exists").is_ok());
        let error = status(5, "denied").expect_err("nonzero status must fail");
        assert!(error.to_string().contains("0x00000005"));
        assert!(allow_already_exists(5, "denied").is_err());
    }

    #[test]
    fn wfp_value_builders_are_well_formed() {
        let mut name = wide("name");
        let mut description = wide("description");
        assert_eq!(name.last(), Some(&0));
        let display = display_data(&mut name, Some(&mut description));
        assert!(!display.name.is_null());
        assert!(!display.description.is_null());

        let mut no_description_name = wide("name");
        let display = display_data(&mut no_description_name, None);
        assert!(display.description.is_null());

        let condition = package_condition(PSID::default());
        assert_eq!(condition.fieldKey, FWPM_CONDITION_ALE_PACKAGE_ID);
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
    }

    #[test]
    fn fake_wfp_api_covers_deny_and_dual_stack_allow_list_transactions() {
        for (policy, expected_filters) in [
            (NetworkPolicy::DenyAll, 4),
            (
                NetworkPolicy::AllowList(vec![
                    "192.0.2.0/24".parse().unwrap(),
                    "2001:db8::/32".parse().unwrap(),
                ]),
                6,
            ),
        ] {
            let api = Arc::new(FakeWfpApi::new(None));
            let mut filters = NetworkFilters::install_with_api(&policy, fake_sid(), api.clone())
                .expect("fake WFP install");
            assert_eq!(filters.filter_ids().len(), expected_filters);
            filters.cleanup().unwrap();
            let calls = api.calls.lock().unwrap();
            assert_eq!(
                calls.iter().filter(|call| **call == "filter_add").count(),
                expected_filters
            );
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| **call == "filter_delete")
                    .count(),
                expected_filters
            );
            assert!(calls.contains(&"commit"));
            assert!(calls.contains(&"close"));
        }
    }

    #[test]
    fn every_wfp_setup_stage_failure_aborts_or_closes_safely() {
        for failure in [
            "open_provider",
            "begin",
            "provider",
            "sublayer",
            "commit",
            "open_dynamic",
            "filter_add",
        ] {
            let api = Arc::new(FakeWfpApi::new(Some(failure)));
            assert!(
                NetworkFilters::install_with_api(&NetworkPolicy::DenyAll, fake_sid(), api.clone())
                    .is_err()
            );
            let calls = api.calls.lock().unwrap();
            if failure != "open_provider" {
                assert!(calls.contains(&"close"));
            }
            if matches!(failure, "provider" | "sublayer" | "commit" | "filter_add") {
                assert!(calls.contains(&"abort"));
            }
        }
    }

    #[test]
    fn cleanup_reports_filter_deletion_failures() {
        let install_api = Arc::new(FakeWfpApi::new(None));
        let mut filters =
            NetworkFilters::install_with_api(&NetworkPolicy::DenyAll, fake_sid(), install_api)
                .unwrap();
        filters.api = Arc::new(FakeWfpApi::new(Some("filter_delete")));
        let error = filters
            .cleanup()
            .expect_err("delete failures must be reported");
        assert_eq!(error.stage, "network_cleanup");
        assert!(filters.engine.is_invalid());
    }
}
