use super::desktop::PrivateDesktop;
use super::mitigations;
use super::monitor::{ActivityMonitor, MonitorResult};
use super::network::NetworkFilters;
use super::token::RestrictedToken;
use super::workspace::Workspace;
use crate::sandbox::backend::{
    BackendKind, BackendMetadata, BackendState, MitigationProfile, ReportStage, ResourceLimits,
    SandboxBackend, SandboxError, SandboxRequest, SandboxResult, StageTimer,
};
use crate::sandbox::sandbox_utils::{
    build_windows_command_line, log_inside, log_monitor, log_outside, to_wide_null,
    win32_path_string,
};
use crate::structs::{
    CleanupStatus, NetworkObservation, ProcessObservation, SandboxRunResult, StreamCaptureSummary,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    CloseHandle, E_ACCESSDENIED, E_INVALIDARG, ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER,
    ERROR_MORE_DATA, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSED,
    MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_RESERVED,
    MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationGetAppContainerConfig;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath,
};
use windows::Win32::Security::{
    CreateWellKnownSid, DeriveCapabilitySidsFromName, EqualSid, FreeSid, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSID, SECURITY_ATTRIBUTES,
    SECURITY_CAPABILITIES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenAppContainerSid, TokenCapabilities, TokenGroups, TokenIntegrityLevel, TokenIsAppContainer,
    TokenIsLessPrivilegedAppContainer, WELL_KNOWN_SID_TYPE, WinBuiltinAnyPackageSid,
    WinCapabilityInternetClientSid,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STREAM_INFO, FILE_TYPE_DISK, FileStreamInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
    GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_UILIMIT, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
use windows::Win32::System::Memory::{
    GetProcessHeap, HEAP_FLAGS, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
use windows::Win32::System::Threading::{
    self, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateMutexW,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ReleaseMutex, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{Error, HRESULT, PCWSTR, PWSTR, Result};

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw

const APP_CONTAINER_NAME_PREFIX: &str = "foxhole.sandbox.";
const LEGACY_APP_CONTAINER_NAME: &str = "foxhole.sandbox";
const APP_CONTAINER_DISPLAY: &str = "Foxhole Sandbox";
const APP_CONTAINER_DESCRIPTION: &str = "Foxhole AppContainer sandbox profile";
const RESTRICTED_EXECUTION_MUTEX: &str = "Local\\Foxhole.RestrictedProcess.Execution.v1";
#[cfg(test)]
const RESTRICTED_EXECUTION_WAIT_MS: u32 = 60_000;
#[cfg(not(test))]
const RESTRICTED_EXECUTION_WAIT_MS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER_CODE: u32 = 122;
const SE_GROUP_ENABLED_ATTRIBUTE: u32 = 0x00000004;
const STILL_ACTIVE: u32 = 259;
const WAIT_SLICE_MS: u32 = 250;
const MONITOR_POLL_MS: u64 = 100;
const MAX_SANDBOX_TARGET_BYTES: u64 = 600 * 1024 * 1024;
const MAX_BATCH_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CAPTURED_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_TERMINAL_LOG_BYTES: usize = 64 * 1024;
const MAX_TERMINAL_LOG_LINES: usize = 1_000;
const MAX_PROCESS_OBSERVATIONS: usize = 4_096;
const MAX_NETWORK_OBSERVATIONS: usize = 4_096;
const MAX_NETWORK_ROWS_PER_SNAPSHOT: usize = 8_192;
const MAX_PROCESS_SNAPSHOT_ENTRIES: usize = 65_536;
const MAX_NETWORK_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_STORAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STORAGE_ENTRIES: usize = 10_000;
const MAX_STREAMS_PER_STORAGE_ENTRY: usize = 64;
const MAX_STORAGE_PATH_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_INFO_BYTES: usize = 1024 * 1024;
const MAX_PE_HEADER_OFFSET: u64 = 16 * 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

struct ProcThreadAttributeList {
    heap: windows::Win32::Foundation::HANDLE,
    mem: *mut c_void,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    initialized: bool,
}

impl ProcThreadAttributeList {
    unsafe fn new(attribute_count: u32) -> Result<Self> {
        let mut size = 0usize;
        let _ = unsafe {
            Threading::InitializeProcThreadAttributeList(None, attribute_count, Some(0), &mut size)
        };

        let heap = unsafe { GetProcessHeap()? };
        let mem = unsafe { HeapAlloc(heap, HEAP_ZERO_MEMORY, size) };
        if mem.is_null() {
            return Err(Error::from_thread());
        }

        let list = LPPROC_THREAD_ATTRIBUTE_LIST(mem);
        unsafe {
            Threading::InitializeProcThreadAttributeList(
                Some(list),
                attribute_count,
                Some(0),
                &mut size,
            )?;
        }

        Ok(Self {
            heap,
            mem,
            list,
            initialized: true,
        })
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe {
            if self.initialized {
                Threading::DeleteProcThreadAttributeList(self.list);
            }
            if !self.mem.is_null() {
                let _ = HeapFree(self.heap, HEAP_FLAGS(0), Some(self.mem as *const c_void));
            }
        }
    }
}

#[derive(Debug)]
struct WinHandle {
    handle: HANDLE,
}

impl WinHandle {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn get(&self) -> HANDLE {
        self.handle
    }

    fn close(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
            self.handle = HANDLE::default();
        }
    }

    fn into_raw(mut self) -> HANDLE {
        mem::take(&mut self.handle)
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        self.close();
    }
}

struct ProcessTerminationGuard {
    process: HANDLE,
    armed: bool,
}

struct ChildOutputPipe {
    reader: File,
    writer: WinHandle,
}

struct ChildInputPipe {
    reader: WinHandle,
    writer: File,
}

struct WindowsLaunch {
    application_name: String,
    command_line: String,
    stdin: Option<BatchInput>,
    gui_target: bool,
    _target_pin: Option<PinnedTarget>,
}

struct BatchInput {
    target: PinnedTarget,
    append_final_newline: bool,
}

struct PinnedTarget {
    path: PathBuf,
    file: File,
    len: u64,
    identity: FileIdentity,
    _directory_pins: Vec<File>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

struct AppContainerStorage {
    root: PathBuf,
    working_dir: PathBuf,
}

struct TrustedWindowsPaths {
    windows: PathBuf,
    system: PathBuf,
}

struct CapturedOutput {
    bytes: Vec<u8>,
    bytes_seen: u64,
}

struct WaitOutcome {
    timed_out: bool,
    warning: Option<String>,
}

struct AppContainerProcess<'a> {
    application_name: &'a str,
    command_line: &'a str,
    working_dir: &'a Path,
    storage_root: &'a Path,
    security_capabilities: &'a mut SECURITY_CAPABILITIES,
    token: HANDLE,
    desktop_name: PWSTR,
    request: &'a SandboxRequest,
    gui_target: bool,
    started_at: Instant,
}

#[derive(Debug)]
pub struct WindowsSandboxRun {
    pub result: SandboxRunResult,
    pub target_path: PathBuf,
    pub target_size_bytes: u64,
    pub target_sha256: String,
    pub profile_name: Option<String>,
    pub metadata: BackendMetadata,
    pub stages: Vec<ReportStage>,
}

enum PreparedRun {
    DryRun,
    Live(Box<LivePrepared>),
}

struct LivePrepared {
    network: NetworkFilters,
    launch: WindowsLaunch,
    workspace: Workspace,
    desktop: PrivateDesktop,
    token: RestrictedToken,
    request: SandboxRequest,
    capability_sids: Vec<CapabilitySid>,
    storage_root: PathBuf,
    app_container: AppContainerProfile,
}

pub struct RestrictedProcessBackend {
    state: BackendState,
    prepared: Option<PreparedRun>,
    target_path: Option<PathBuf>,
    target_size_bytes: u64,
    target_sha256: Option<String>,
    profile_name: Option<String>,
    started_at: Option<Instant>,
    cleanup_leftovers: Vec<String>,
    execution_lease: Option<RestrictedExecutionLease>,
}

impl Default for RestrictedProcessBackend {
    fn default() -> Self {
        Self {
            state: BackendState::Created,
            prepared: None,
            target_path: None,
            target_size_bytes: 0,
            target_sha256: None,
            profile_name: None,
            started_at: None,
            cleanup_leftovers: Vec::new(),
            execution_lease: None,
        }
    }
}

struct RestrictedExecutionLease(HANDLE);

impl RestrictedExecutionLease {
    fn acquire() -> SandboxResult<Self> {
        let name = to_wide_null(RESTRICTED_EXECUTION_MUTEX);
        let handle =
            unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }.map_err(|error| {
                SandboxError::with_source(
                    "restricted_execution_lease",
                    "create the per-session restricted-backend execution mutex",
                    error,
                )
            })?;
        match unsafe { WaitForSingleObject(handle, RESTRICTED_EXECUTION_WAIT_MS) } {
            WAIT_OBJECT_0 => Ok(Self(handle)),
            WAIT_ABANDONED => {
                log_outside(
                    "recovered an abandoned restricted-backend execution lease after a prior broker exit",
                );
                Ok(Self(handle))
            }
            WAIT_TIMEOUT => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err(SandboxError::new(
                    "restricted_execution_lease",
                    "another live restricted-process run is active in this Windows session",
                ))
            }
            WAIT_FAILED => {
                let error = std::io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err(SandboxError::with_source(
                    "restricted_execution_lease",
                    "acquire the restricted-backend execution mutex",
                    error,
                ))
            }
            other => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err(SandboxError::new(
                    "restricted_execution_lease",
                    format!("unexpected execution-mutex wait result: {}", other.0),
                ))
            }
        }
    }
}

impl Drop for RestrictedExecutionLease {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = ReleaseMutex(self.0);
                let _ = CloseHandle(self.0);
            }
            self.0 = HANDLE::default();
        }
    }
}

impl ProcessTerminationGuard {
    fn new(process: HANDLE) -> Self {
        Self {
            process,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessTerminationGuard {
    fn drop(&mut self) {
        if self.armed && !self.process.is_invalid() {
            unsafe {
                let _ = TerminateProcess(self.process, 1);
                let _ = WaitForSingleObject(self.process, 5_000);
            }
        }
    }
}

struct CapabilitySid {
    bytes: Vec<u8>,
}

impl CapabilitySid {
    fn new(kind: WELL_KNOWN_SID_TYPE) -> Result<Self> {
        let mut bytes = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = bytes.len() as u32;
        unsafe {
            CreateWellKnownSid(
                kind,
                None,
                Some(PSID(bytes.as_mut_ptr() as *mut c_void)),
                &mut size,
            )?;
        }
        bytes.truncate(size as usize);
        Ok(Self { bytes })
    }

    fn as_psid(&mut self) -> PSID {
        PSID(self.bytes.as_mut_ptr() as *mut c_void)
    }

    fn from_name(name: &str) -> Result<Self> {
        let name = to_wide_null(name);
        let mut group_sids = std::ptr::null_mut();
        let mut group_count = 0u32;
        let mut capability_sids = std::ptr::null_mut();
        let mut capability_count = 0u32;
        unsafe {
            DeriveCapabilitySidsFromName(
                PCWSTR(name.as_ptr()),
                &mut group_sids,
                &mut group_count,
                &mut capability_sids,
                &mut capability_count,
            )?;
        }
        let _groups = LocalSidArray::new(group_sids, group_count);
        let capabilities = LocalSidArray::new(capability_sids, capability_count);
        if capability_count != 1 || capability_sids.is_null() {
            return Err(Error::new(
                E_INVALIDARG,
                "capability derivation did not return exactly one capability SID",
            ));
        }
        let sid = unsafe { *capabilities.ptr };
        let length = unsafe { GetLengthSid(sid) } as usize;
        if length == 0 || length > SECURITY_MAX_SID_SIZE as usize {
            return Err(Error::new(
                E_INVALIDARG,
                "derived capability SID has an invalid length",
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), length) }.to_vec();
        Ok(Self { bytes })
    }
}

struct LocalSidArray {
    ptr: *mut PSID,
    count: u32,
}

impl LocalSidArray {
    fn new(ptr: *mut PSID, count: u32) -> Self {
        Self { ptr, count }
    }
}

impl Drop for LocalSidArray {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                for sid in std::slice::from_raw_parts(self.ptr, self.count as usize) {
                    if !sid.is_invalid() {
                        LocalFree(Some(HLOCAL(sid.0)));
                    }
                }
                LocalFree(Some(HLOCAL(self.ptr.cast())));
            }
        }
    }
}

struct AppContainerProfile {
    sid: PSID,
    name: String,
    name_wide: Vec<u16>,
    marker: Option<File>,
    marker_path: PathBuf,
    _marker_directory_pins: Vec<File>,
    deleted: bool,
}

impl AppContainerProfile {
    fn get(&self) -> PSID {
        self.sid
    }

    fn delete(&mut self) -> Result<()> {
        if self.deleted {
            return Ok(());
        }

        let mut last_error = None;
        for _ in 0..3 {
            match unsafe { DeleteAppContainerProfile(PCWSTR(self.name_wide.as_ptr())) } {
                Ok(()) => {
                    self.deleted = true;
                    self.marker.take();
                    if let Err(err) = fs::remove_file(&self.marker_path)
                        && err.kind() != std::io::ErrorKind::NotFound
                    {
                        log_outside(format!(
                            "failed to remove AppContainer cleanup marker {}: {err}",
                            terminal_safe_text(&self.marker_path.display().to_string())
                        ));
                    }
                    log_outside(format!(
                        "deleted disposable AppContainer profile {}",
                        terminal_safe_text(&self.name)
                    ));
                    return Ok(());
                }
                Err(err) => {
                    last_error = Some(err);
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }

        Err(last_error.unwrap_or_else(Error::from_thread))
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.deleted
            && let Err(err) = self.delete()
        {
            log_outside(format!(
                "failed to delete disposable AppContainer profile {}: {err}",
                terminal_safe_text(&self.name)
            ));
        }
        if !self.sid.is_invalid() {
            unsafe {
                let _ = FreeSid(self.sid);
            }
        }
    }
}

pub fn start_with_request(request: SandboxRequest) -> SandboxResult<WindowsSandboxRun> {
    println!("[cli debug] in start_with_request @restricted_process");
    let mut backend = RestrictedProcessBackend::default();
    let validation_timer = StageTimer::start("request_validation");
    request.validate_for_backend(BackendKind::RestrictedProcess)?;
    let validation_stage = validation_timer.finish(true, Vec::new(), Vec::new());

    let preparation_timer = StageTimer::start("preparation");
    if let Err(preparation_error) = backend.prepare(&request) {
        crate::interrupt::begin_cleanup();
        let cleanup_error = backend.cleanup().err();
        return match cleanup_error {
            Some(cleanup_error) => Err(SandboxError::new(
                "preparation_and_cleanup",
                format!("{preparation_error}; cleanup also failed: {cleanup_error}"),
            )),
            None => Err(preparation_error),
        };
    }
    let preparation_stage = preparation_timer.finish(true, Vec::new(), Vec::new());

    let execution_timer = StageTimer::start("execution");
    let mut result = backend.execute(&request);
    let execution_stage = execution_timer.finish(
        result.is_ok(),
        Vec::new(),
        result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .into_iter()
            .collect(),
    );
    crate::interrupt::begin_cleanup();
    let cleanup_timer = StageTimer::start("cleanup");
    let cleanup = backend.cleanup();
    let cleanup_stage = cleanup_timer.finish(
        cleanup.is_ok(),
        Vec::new(),
        cleanup
            .as_ref()
            .err()
            .map(ToString::to_string)
            .into_iter()
            .collect(),
    );
    match (&mut result, cleanup) {
        (Ok(result), Ok(())) => {
            result.cleanup.attempted = true;
            result.cleanup.success = true;
        }
        (Ok(result), Err(cleanup_error)) => {
            let warning = cleanup_error.to_string();
            result.cleanup.attempted = true;
            result.cleanup.success = false;
            result.cleanup.warnings.push(warning.clone());
            result.cleanup.leftover_resources = backend.cleanup_leftovers.clone();
            result.monitor_warnings.push(warning);
        }
        (Err(execution_error), Err(cleanup_error)) => {
            return Err(SandboxError::new(
                "execution_and_cleanup",
                format!("{execution_error}; cleanup also failed: {cleanup_error}"),
            ));
        }
        (Err(_), Ok(())) => {}
    }

    let result = result?;
    let completion_stage = ReportStage {
        warnings: if result.timed_out {
            vec![
                "the target reached its configured timeout and its process tree was terminated"
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
        ..ReportStage::instant("timeout_or_completion", true)
    };
    let observation_stage = ReportStage {
        warnings: result.monitor_warnings.clone(),
        ..ReportStage::instant("observation", true)
    };
    let artifact_stage = ReportStage::instant("artifact_collection", true);
    let metadata = BackendMetadata::RestrictedProcess {
        profile_name: backend.profile_name.clone(),
        integrity_level: result.integrity_level.clone(),
        mitigation_profile: result.mitigation_profile.clone(),
    };
    Ok(WindowsSandboxRun {
        result,
        target_path: backend.target_path.ok_or_else(|| {
            SandboxError::new("result", "sandbox target metadata was not retained")
        })?,
        target_size_bytes: backend.target_size_bytes,
        target_sha256: backend.target_sha256.ok_or_else(|| {
            SandboxError::new("result", "sandbox target integrity hash was not retained")
        })?,
        profile_name: backend.profile_name,
        metadata,
        stages: vec![
            validation_stage,
            preparation_stage,
            execution_stage,
            observation_stage,
            completion_stage,
            artifact_stage,
            cleanup_stage,
        ],
    })
}

impl SandboxBackend for RestrictedProcessBackend {
    fn prepare(&mut self, request: &SandboxRequest) -> SandboxResult<()> {
        if self.state != BackendState::Created {
            return Err(SandboxError::new(
                "prepare",
                format!("backend cannot prepare from state {:?}", self.state),
            ));
        }
        self.state = BackendState::Preparing;
        self.started_at = Some(Instant::now());
        if let Err(error) = request.validate_for_backend(BackendKind::RestrictedProcess) {
            self.state = BackendState::Failed;
            return Err(error);
        }

        let target = request.target.to_str().ok_or_else(|| {
            self.state = BackendState::Failed;
            SandboxError::new(
                "request_validation",
                "the Windows target path is not valid Unicode",
            )
        })?;
        let mut pinned_target = pin_target(target).map_err(|error| {
            self.state = BackendState::Failed;
            windows_stage_error("request_validation", "pin and validate the target", error)
        })?;
        let target_sha256 = hash_pinned_target(&mut pinned_target).map_err(|error| {
            self.state = BackendState::Failed;
            windows_stage_error(
                "request_validation",
                "hash the pinned sandbox target",
                error,
            )
        })?;
        self.target_path = Some(pinned_target.path.clone());
        self.target_size_bytes = pinned_target.len;
        self.target_sha256 = Some(target_sha256);
        log_outside(format!(
            "target: {}",
            terminal_safe_text(&win32_path_string(&pinned_target.path))
        ));
        log_outside(format!("timeout: {}s", request.timeout_secs));

        if request.dry_run {
            let launch =
                prepare_windows_launch(pinned_target, &request.arguments).map_err(|error| {
                    self.state = BackendState::Failed;
                    windows_stage_error("prepare", "validate the Windows launch plan", error)
                })?;
            if request.mitigation_profile == MitigationProfile::Maximum && launch.gui_target {
                self.state = BackendState::Failed;
                return Err(SandboxError::new(
                    "mitigations",
                    "the maximum mitigation profile disables Win32k and cannot launch a GUI target",
                ));
            }
            let target_name = self
                .target_path
                .as_deref()
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<redacted>".to_string());
            log_outside(format!(
                "dry run validated {} target {} with {} redacted argument(s)",
                if launch.stdin.is_some() {
                    "batch"
                } else {
                    "executable"
                },
                terminal_safe_text(&target_name),
                request.arguments.len()
            ));
            self.prepared = Some(PreparedRun::DryRun);
            self.state = BackendState::Ready;
            return Ok(());
        }

        self.execution_lease = Some(RestrictedExecutionLease::acquire()?);
        scavenge_stale_app_container_profiles();
        let mut capability_sids = build_capability_sids(
            request.network_policy.needs_internet_capability(),
            is_batch_target(&pinned_target.path),
        )
        .map_err(|error| windows_stage_error("prepare", "build network capability SIDs", error))?;
        let sid_attributes = sid_attributes(&mut capability_sids);
        let mut app_container = Some(create_disposable_app_container(&sid_attributes).map_err(
            |error| windows_stage_error("prepare", "create the per-run sandbox identity", error),
        )?);
        self.profile_name = app_container.as_ref().map(|profile| profile.name.clone());

        let prepared_result = (|| {
            let app_container_ref = app_container
                .as_mut()
                .ok_or_else(|| SandboxError::new("prepare", "per-run sandbox identity was lost"))?;
            ensure_no_loopback_exemption(app_container_ref.get()).map_err(|error| {
                windows_stage_error("network_filters", "reject loopback exemptions", error)
            })?;
            let storage = app_container_storage(app_container_ref.get(), &app_container_ref.name)
                .map_err(|error| {
                windows_stage_error("workspace", "resolve AppContainer storage", error)
            })?;
            let sandbox_sid = sid_to_string_text(app_container_ref.get()).map_err(|error| {
                windows_stage_error("prepare", "format the per-run sandbox SID", error)
            })?;
            pinned_target.verify_identity().map_err(|error| {
                windows_stage_error("workspace", "revalidate the pinned target", error)
            })?;
            let target_name = pinned_target
                .path
                .file_name()
                .ok_or_else(|| SandboxError::new("workspace", "sandbox target has no file name"))?;
            let workspace = Workspace::create(
                &storage.working_dir,
                &pinned_target.file,
                target_name,
                &sandbox_sid,
                request,
            )?;
            let staged_target = workspace.target.to_str().ok_or_else(|| {
                SandboxError::new("workspace", "staged target path is not valid Unicode")
            })?;
            let staged_target = pin_target(staged_target).map_err(|error| {
                windows_stage_error("workspace", "pin the staged target", error)
            })?;
            let launch =
                prepare_windows_launch(staged_target, &request.arguments).map_err(|error| {
                    windows_stage_error("prepare", "build the staged Windows launch plan", error)
                })?;
            if request.mitigation_profile == MitigationProfile::Maximum && launch.gui_target {
                return Err(SandboxError::new(
                    "mitigations",
                    "the maximum mitigation profile disables Win32k and cannot launch a GUI target",
                ));
            }
            let token = RestrictedToken::create(request.mitigation_profile)?;
            let run_id = app_container_ref
                .name
                .strip_prefix(APP_CONTAINER_NAME_PREFIX)
                .unwrap_or(&app_container_ref.name);
            let desktop = PrivateDesktop::create(run_id, &sandbox_sid)?;
            let network =
                NetworkFilters::install(&request.network_policy, app_container_ref.get())?;
            log_outside(format!(
                "network policy {} installed with {} WFP filter(s)",
                request.network_policy.name(),
                network.filter_ids().len()
            ));

            let app_container = app_container
                .take()
                .ok_or_else(|| SandboxError::new("prepare", "per-run sandbox identity was lost"))?;
            Ok(Box::new(LivePrepared {
                network,
                launch,
                workspace,
                desktop,
                token,
                request: request.clone(),
                capability_sids,
                storage_root: storage.root,
                app_container,
            }))
        })();

        match prepared_result {
            Ok(prepared) => {
                self.prepared = Some(PreparedRun::Live(prepared));
                self.state = BackendState::Ready;
                Ok(())
            }
            Err(error) => {
                if let Some(app_container) = app_container.as_mut()
                    && let Err(cleanup_error) = app_container.delete()
                {
                    log_outside(format!(
                        "preparation failed and AppContainer cleanup also failed: {cleanup_error}"
                    ));
                }
                self.state = BackendState::Failed;
                Err(error)
            }
        }
    }

    fn execute(&mut self, request: &SandboxRequest) -> SandboxResult<SandboxRunResult> {
        if self.state != BackendState::Ready {
            return Err(SandboxError::new(
                "execute",
                format!("backend cannot execute from state {:?}", self.state),
            ));
        }
        self.state = BackendState::Running;
        let started_at = self.started_at.unwrap_or_else(Instant::now);
        let Some(prepared) = self.prepared.as_mut() else {
            self.state = BackendState::Failed;
            return Err(SandboxError::new(
                "execute",
                "backend has no prepared launch plan",
            ));
        };

        let result = match prepared {
            PreparedRun::DryRun => Ok(SandboxRunResult {
                backend: "restricted_process".to_string(),
                network_policy: request.network_policy.name().to_string(),
                integrity_level: if request.mitigation_profile == MitigationProfile::Maximum {
                    "untrusted".to_string()
                } else {
                    "low".to_string()
                },
                mitigation_profile: request.mitigation_profile.to_string(),
                pid: 0,
                exit_code: Some(0),
                timed_out: false,
                working_dir: None,
                duration_ms: elapsed_ms(started_at),
                stdout: String::new(),
                stderr: String::new(),
                stdout_capture: empty_capture_summary(),
                stderr_capture: empty_capture_summary(),
                processes: Vec::new(),
                network_connections: Vec::new(),
                file_observations: Vec::new(),
                registry_observations: Vec::new(),
                mapped_paths: Vec::new(),
                monitor_warnings: Vec::new(),
                cleanup: CleanupStatus::pending(),
            }),
            PreparedRun::Live(prepared) => {
                if &prepared.request != request {
                    return Err(SandboxError::new(
                        "execute",
                        "execute request differs from the prepared request",
                    ));
                }
                let mut sid_attributes = sid_attributes(&mut prepared.capability_sids);
                let mut security_capabilities = SECURITY_CAPABILITIES {
                    AppContainerSid: prepared.app_container.get(),
                    Capabilities: if sid_attributes.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        sid_attributes.as_mut_ptr()
                    },
                    CapabilityCount: sid_attributes.len() as u32,
                    Reserved: 0,
                };
                if let Some(target_pin) = prepared.launch._target_pin.as_ref() {
                    target_pin.verify_identity().map_err(|error| {
                        windows_stage_error("execute", "revalidate the staged target", error)
                    })?;
                }
                let stdin = prepared.launch.stdin.take();
                let mut result = run_app_container_process(
                    AppContainerProcess {
                        application_name: &prepared.launch.application_name,
                        command_line: &prepared.launch.command_line,
                        working_dir: &prepared.workspace.work,
                        storage_root: &prepared.storage_root,
                        security_capabilities: &mut security_capabilities,
                        token: prepared.token.get(),
                        desktop_name: prepared.desktop.startup_name(),
                        request,
                        gui_target: prepared.launch.gui_target,
                        started_at,
                    },
                    stdin,
                )
                .map_err(|error| {
                    windows_stage_error("execute", "run the restricted process", error)
                })?;
                result.working_dir = Some(prepared.workspace.work.display().to_string());
                result.integrity_level = prepared.token.integrity_level().to_string();
                let (file_observations, observation_warnings) =
                    prepared.workspace.file_observations(elapsed_ms(started_at));
                result.file_observations = file_observations;
                result.monitor_warnings.extend(observation_warnings);
                result.mapped_paths = prepared.workspace.mappings.clone();
                Ok(result)
            }
        };

        self.state = if result.is_ok() {
            BackendState::Completed
        } else {
            BackendState::Failed
        };
        result
    }

    fn cleanup(&mut self) -> SandboxResult<()> {
        if matches!(self.state, BackendState::Finished | BackendState::Created) {
            self.execution_lease.take();
            self.state = BackendState::Finished;
            return Ok(());
        }
        self.state = BackendState::Cleaning;
        let mut warnings = Vec::new();
        if let Some(PreparedRun::Live(prepared)) = self.prepared.take() {
            let LivePrepared {
                mut app_container,
                mut network,
                launch,
                workspace,
                token,
                desktop,
                ..
            } = *prepared;
            if let Err(error) = network.cleanup() {
                warnings.push(error.to_string());
            }
            drop(launch);
            drop(workspace);
            drop(desktop);
            drop(token);
            if let Err(error) = app_container.delete() {
                self.cleanup_leftovers
                    .push(format!("appcontainer: {}", app_container.name));
                warnings.push(format!("delete disposable AppContainer profile: {error}"));
            }
        }
        self.execution_lease.take();
        self.state = BackendState::Finished;
        if warnings.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::new("cleanup", warnings.join("; ")))
        }
    }
}

fn windows_stage_error(stage: &'static str, operation: &'static str, error: Error) -> SandboxError {
    SandboxError::with_source(stage, operation, error)
}

#[cfg(test)]
fn start_with_security_capabilities(
    cmdline: &mut [u16],
    security_capabilities: &SECURITY_CAPABILITIES,
) -> Result<Threading::PROCESS_INFORMATION> {
    if cmdline.is_empty() || *cmdline.last().unwrap_or(&1) != 0 {
        return Err(Error::new(
            E_INVALIDARG,
            "cmdline must be non-empty and null-terminated UTF-16",
        ));
    }

    let attr_list = unsafe { ProcThreadAttributeList::new(1)? };

    unsafe {
        Threading::UpdateProcThreadAttribute(
            attr_list.list,
            0,
            Threading::PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(security_capabilities as *const _ as *const c_void),
            mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )?;
    }

    let mut startinfoex = STARTUPINFOEXW::default();
    startinfoex.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startinfoex.lpAttributeList = attr_list.list;

    let mut process_info = Threading::PROCESS_INFORMATION::default();

    unsafe {
        Threading::CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            Threading::EXTENDED_STARTUPINFO_PRESENT
                | Threading::CREATE_UNICODE_ENVIRONMENT
                | Threading::CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &startinfoex.StartupInfo,
            &mut process_info,
        )?;
    }

    Ok(process_info)
}

fn run_app_container_process(
    request: AppContainerProcess<'_>,
    stdin: Option<BatchInput>,
) -> Result<SandboxRunResult> {
    let AppContainerProcess {
        application_name,
        command_line,
        working_dir,
        storage_root,
        security_capabilities,
        token,
        desktop_name,
        request,
        gui_target,
        started_at,
    } = request;
    let mut stdout_pipe = child_output_pipe()?;
    let mut stderr_pipe = child_output_pipe()?;
    let mut stdin_pipe = child_input_pipe()?;
    let inherited_handles = [
        stdin_pipe.reader.get(),
        stdout_pipe.writer.get(),
        stderr_pipe.writer.get(),
    ];
    let mitigation_policy = mitigations::policy(request.mitigation_profile, gui_target);
    let all_application_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let attr_list = unsafe { ProcThreadAttributeList::new(4)? };

    unsafe {
        Threading::UpdateProcThreadAttribute(
            attr_list.list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(security_capabilities as *const _ as *const c_void),
            mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )?;
        Threading::UpdateProcThreadAttribute(
            attr_list.list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(inherited_handles.as_ptr() as *const c_void),
            mem::size_of_val(&inherited_handles),
            None,
            None,
        )?;
        Threading::UpdateProcThreadAttribute(
            attr_list.list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(&mitigation_policy as *const _ as *const c_void),
            mem::size_of_val(&mitigation_policy),
            None,
            None,
        )?;
        Threading::UpdateProcThreadAttribute(
            attr_list.list,
            0,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
            Some(&all_application_packages_policy as *const _ as *const c_void),
            mem::size_of_val(&all_application_packages_policy),
            None,
            None,
        )?;
    }

    let mut startinfoex = STARTUPINFOEXW::default();
    startinfoex.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startinfoex.lpAttributeList = attr_list.list;
    startinfoex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startinfoex.StartupInfo.hStdOutput = stdout_pipe.writer.get();
    startinfoex.StartupInfo.hStdError = stderr_pipe.writer.get();
    startinfoex.StartupInfo.hStdInput = stdin_pipe.reader.get();
    startinfoex.StartupInfo.lpDesktop = desktop_name;

    let mut process_info = PROCESS_INFORMATION::default();
    let application_name_wide = to_wide_null(application_name);
    let mut command_line_wide = to_wide_null(command_line);
    let working_dir_wide = to_wide_null(&win32_path_string(working_dir));
    let environment = build_sanitized_environment(working_dir, storage_root)?;
    let mut job = create_limited_job(request.timeout_secs, &request.resource_limits)?;

    log_outside(format!(
        "creating process object for {}",
        terminal_safe_text(application_name)
    ));
    unsafe {
        Threading::CreateProcessAsUserW(
            Some(token),
            PCWSTR(application_name_wide.as_ptr()),
            Some(PWSTR(command_line_wide.as_mut_ptr())),
            None,
            None,
            true,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED
                | CREATE_NO_WINDOW,
            Some(environment.as_ptr() as *const c_void),
            PCWSTR(working_dir_wide.as_ptr()),
            &startinfoex.StartupInfo,
            &mut process_info,
        )?;
    }

    let process = WinHandle::new(process_info.hProcess);
    let thread_handle = WinHandle::new(process_info.hThread);
    let mut launch_guard = ProcessTerminationGuard::new(process.get());

    log_outside(format!(
        "created suspended process pid={} tid={}",
        process_info.dwProcessId, process_info.dwThreadId
    ));

    unsafe {
        AssignProcessToJobObject(job.get(), process.get())?;
    }
    // From here on, the kill-on-close job owns cleanup on every error path.
    launch_guard.disarm();
    log_outside(format!(
        "assigned pid={} to kill-on-close job",
        process_info.dwProcessId
    ));

    let expected_capabilities = if security_capabilities.CapabilityCount == 0 {
        &[][..]
    } else {
        unsafe {
            std::slice::from_raw_parts(
                security_capabilities.Capabilities,
                security_capabilities.CapabilityCount as usize,
            )
        }
    };
    verify_suspended_sandbox_token(
        process.get(),
        security_capabilities.AppContainerSid,
        expected_capabilities,
        if request.mitigation_profile == MitigationProfile::Maximum {
            0
        } else {
            4096
        },
    )?;
    stdout_pipe.writer.close();
    stderr_pipe.writer.close();
    stdin_pipe.reader.close();
    let stdout_reader = spawn_output_reader(stdout_pipe.reader);
    let stderr_reader = spawn_output_reader(stderr_pipe.reader);
    let stdin_writer = stdin.map(|input| spawn_input_writer(stdin_pipe.writer, input));

    let root_pid = process_info.dwProcessId;
    let monitor = ActivityMonitor::spawn(move |stop| monitor_activity(root_pid, stop, started_at));

    let process_outcome = (|| -> Result<(WaitOutcome, u32)> {
        log_inside(format!(
            "verified LPAC token active for pid={}",
            process_info.dwProcessId
        ));
        let resume_result = unsafe { ResumeThread(thread_handle.get()) };
        if resume_result == u32::MAX {
            return Err(Error::from_thread());
        }
        log_outside(format!("resumed pid={}", process_info.dwProcessId));

        let wait = wait_for_process(process.get(), job.get(), request.timeout_secs, storage_root)?;
        let mut exit_code = STILL_ACTIVE;
        unsafe {
            GetExitCodeProcess(process.get(), &mut exit_code)?;
        }
        Ok((wait, exit_code))
    })();

    // Always stop and join the monitor, including process resume/wait error paths.
    let mut monitor = monitor.stop_and_join();

    // Closing the kill-on-close job releases any surviving descendants and, in turn,
    // their inherited output handles. This guarantees both reader threads reach EOF.
    job.close();
    if let Some(writer) = stdin_writer {
        finish_input_writer(writer, &mut monitor.warnings);
    }
    let (stdout, stdout_capture) =
        finish_output_reader(stdout_reader, "stdout", &mut monitor.warnings);
    let (stderr, stderr_capture) =
        finish_output_reader(stderr_reader, "stderr", &mut monitor.warnings);
    log_captured_output("stdout", &stdout);
    log_captured_output("stderr", &stderr);
    let (wait, exit_code) = process_outcome?;
    if let Some(warning) = wait.warning {
        monitor.warnings.push(warning);
    }

    if wait.timed_out {
        log_outside(format!(
            "pid={} timed out and was terminated",
            process_info.dwProcessId
        ));
    } else {
        log_outside(format!(
            "pid={} exited with code {}",
            process_info.dwProcessId, exit_code
        ));
    }

    Ok(SandboxRunResult {
        backend: "restricted_process".to_string(),
        network_policy: request.network_policy.name().to_string(),
        integrity_level: if request.mitigation_profile == MitigationProfile::Maximum {
            "untrusted".to_string()
        } else {
            "low".to_string()
        },
        mitigation_profile: request.mitigation_profile.to_string(),
        pid: process_info.dwProcessId,
        exit_code: (exit_code != STILL_ACTIVE).then_some(exit_code),
        timed_out: wait.timed_out,
        working_dir: None,
        duration_ms: elapsed_ms(started_at),
        stdout,
        stderr,
        stdout_capture,
        stderr_capture,
        processes: monitor.processes,
        network_connections: monitor.network_connections,
        file_observations: Vec::new(),
        registry_observations: Vec::new(),
        mapped_paths: Vec::new(),
        monitor_warnings: std::mem::take(&mut monitor.warnings),
        cleanup: CleanupStatus::pending(),
    })
}

fn prepare_windows_launch(mut target: PinnedTarget, args: &[String]) -> Result<WindowsLaunch> {
    let is_batch = is_batch_target(&target.path);
    if !is_batch {
        let gui_target = ensure_supported_pe_target(&mut target)?;
        target.verify_identity()?;
        let target_path = win32_path_string(&target.path);
        return Ok(WindowsLaunch {
            application_name: target_path.clone(),
            command_line: build_windows_command_line(&target_path, args),
            stdin: None,
            gui_target,
            _target_pin: Some(target),
        });
    }

    if !args.is_empty() {
        return Err(Error::new(
            E_INVALIDARG,
            "arguments for batch targets are not supported inside the AppContainer yet",
        ));
    }

    target.verify_identity()?;
    let metadata = target.file.metadata().map_err(|err| {
        Error::new(
            E_INVALIDARG,
            format!(
                "failed to inspect batch target {}: {err}",
                terminal_safe_text(&target.path.display().to_string())
            ),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_BATCH_INPUT_BYTES {
        return Err(Error::new(
            E_INVALIDARG,
            format!(
                "batch target must be a regular file no larger than {MAX_BATCH_INPUT_BYTES} bytes"
            ),
        ));
    }
    let append_final_newline = if metadata.len() == 0 {
        true
    } else {
        target.file.seek(SeekFrom::End(-1)).map_err(io_error)?;
        let mut last = [0u8; 1];
        target.file.read_exact(&mut last).map_err(io_error)?;
        target.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        last[0] != b'\n'
    };
    let cmd = trusted_windows_paths()?.system.join("cmd.exe");
    let cmd = win32_path_string(&cmd);
    log_outside("batch target will be interpreted by sandboxed cmd.exe");
    Ok(WindowsLaunch {
        application_name: cmd.clone(),
        command_line: build_windows_command_line(&cmd, &["/D".to_string()]),
        stdin: Some(BatchInput {
            target,
            append_final_newline,
        }),
        gui_target: false,
        _target_pin: None,
    })
}

fn is_batch_target(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
        })
}

fn ensure_supported_pe_target(target: &mut PinnedTarget) -> Result<bool> {
    const DOS_HEADER_BYTES: usize = 64;
    const PE_PREFIX_BYTES: usize = 4 + 20 + 70;
    const OPTIONAL_HEADER_OFFSET: usize = 4 + 20;
    const OPTIONAL_SUBSYSTEM_OFFSET: usize = 68;
    const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
    const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

    if target.len < DOS_HEADER_BYTES as u64 {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox executable is too small to contain a valid PE header",
        ));
    }
    let mut dos = [0u8; DOS_HEADER_BYTES];
    target.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    target.file.read_exact(&mut dos).map_err(io_error)?;
    if &dos[..2] != b"MZ" {
        return Err(Error::new(
            E_ACCESSDENIED,
            "only validated Windows PE executables may be launched",
        ));
    }
    let pe_offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
    if pe_offset > MAX_PE_HEADER_OFFSET
        || pe_offset
            .checked_add(PE_PREFIX_BYTES as u64)
            .is_none_or(|end| end > target.len)
    {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox executable has an invalid or excessively distant PE header",
        ));
    }

    let mut pe = [0u8; PE_PREFIX_BYTES];
    target
        .file
        .seek(SeekFrom::Start(pe_offset))
        .map_err(io_error)?;
    target.file.read_exact(&mut pe).map_err(io_error)?;
    target.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    if &pe[..4] != b"PE\0\0" {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox executable has an invalid PE signature",
        ));
    }
    let optional_size = u16::from_le_bytes(pe[20..22].try_into().unwrap()) as usize;
    let optional_magic = u16::from_le_bytes(
        pe[OPTIONAL_HEADER_OFFSET..OPTIONAL_HEADER_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    if optional_size < OPTIONAL_SUBSYSTEM_OFFSET + 2 || !matches!(optional_magic, 0x010b | 0x020b) {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox executable has an unsupported PE optional header",
        ));
    }
    let subsystem_offset = OPTIONAL_HEADER_OFFSET + OPTIONAL_SUBSYSTEM_OFFSET;
    let subsystem = u16::from_le_bytes(
        pe[subsystem_offset..subsystem_offset + 2]
            .try_into()
            .unwrap(),
    );
    if !matches!(
        subsystem,
        IMAGE_SUBSYSTEM_WINDOWS_GUI | IMAGE_SUBSYSTEM_WINDOWS_CUI
    ) {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox executable uses an unsupported PE subsystem",
        ));
    }
    Ok(subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
}

fn child_output_pipe() -> Result<ChildOutputPipe> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut read_handle = HANDLE::default();
    let mut write_handle = HANDLE::default();
    unsafe {
        CreatePipe(&mut read_handle, &mut write_handle, Some(&attributes), 0)?;
    }
    let read_handle = WinHandle::new(read_handle);
    let writer = WinHandle::new(write_handle);
    unsafe {
        SetHandleInformation(read_handle.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
    }
    let raw_read_handle = read_handle.into_raw();
    let reader = unsafe { File::from_raw_handle(raw_read_handle.0) };
    Ok(ChildOutputPipe { reader, writer })
}

fn child_input_pipe() -> Result<ChildInputPipe> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut read_handle = HANDLE::default();
    let mut write_handle = HANDLE::default();
    unsafe {
        CreatePipe(&mut read_handle, &mut write_handle, Some(&attributes), 0)?;
    }
    let reader = WinHandle::new(read_handle);
    let write_handle = WinHandle::new(write_handle);
    unsafe {
        SetHandleInformation(write_handle.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
    }
    let raw_write_handle = write_handle.into_raw();
    let writer = unsafe { File::from_raw_handle(raw_write_handle.0) };
    Ok(ChildInputPipe { reader, writer })
}

fn spawn_output_reader(mut reader: File) -> thread::JoinHandle<std::io::Result<CapturedOutput>> {
    thread::spawn(move || read_output_bounded(&mut reader))
}

fn read_output_bounded(reader: &mut impl Read) -> std::io::Result<CapturedOutput> {
    let mut output = CapturedOutput {
        bytes: Vec::with_capacity(MAX_CAPTURED_STREAM_BYTES.min(64 * 1024)),
        bytes_seen: 0,
    };
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.bytes_seen = output.bytes_seen.saturating_add(count as u64);
        let remaining = MAX_CAPTURED_STREAM_BYTES.saturating_sub(output.bytes.len());
        let retained = remaining.min(count);
        output.bytes.extend_from_slice(&buffer[..retained]);
    }
    Ok(output)
}

fn spawn_input_writer(
    mut writer: File,
    mut input: BatchInput,
) -> thread::JoinHandle<std::io::Result<()>> {
    thread::spawn(move || {
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = input.target.file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied.saturating_add(count as u64);
            if copied > MAX_BATCH_INPUT_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "batch target grew beyond the input limit while being streamed",
                ));
            }
            writer.write_all(&buffer[..count])?;
        }
        if input.append_final_newline {
            writer.write_all(b"\r\n")?;
        }
        Ok(())
    })
}

fn finish_input_writer(
    writer: thread::JoinHandle<std::io::Result<()>>,
    warnings: &mut Vec<String>,
) {
    match writer.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => warnings.push(format!("failed to stream batch target to cmd.exe: {err}")),
        Err(_) => warnings.push("batch input thread panicked".to_string()),
    }
}

fn finish_output_reader(
    reader: thread::JoinHandle<std::io::Result<CapturedOutput>>,
    stream: &str,
    warnings: &mut Vec<String>,
) -> (String, StreamCaptureSummary) {
    match reader.join() {
        Ok(Ok(output)) => {
            let summary = StreamCaptureSummary {
                bytes_seen: output.bytes_seen,
                bytes_stored: output.bytes.len() as u64,
                truncated: output.bytes_seen > output.bytes.len() as u64,
            };
            if summary.truncated {
                warnings.push(format!(
                    "{stream} truncated: observed {} bytes and retained {} bytes",
                    summary.bytes_seen, summary.bytes_stored
                ));
            }
            let mut value = String::from_utf8_lossy(&output.bytes).into_owned();
            truncate_string_at_boundary(&mut value, MAX_CAPTURED_STREAM_BYTES);
            (value, summary)
        }
        Ok(Err(err)) => {
            warnings.push(format!("failed to capture {stream}: {err}"));
            (String::new(), empty_capture_summary())
        }
        Err(_) => {
            warnings.push(format!("{stream} capture thread panicked"));
            (String::new(), empty_capture_summary())
        }
    }
}

fn empty_capture_summary() -> StreamCaptureSummary {
    StreamCaptureSummary {
        bytes_seen: 0,
        bytes_stored: 0,
        truncated: false,
    }
}

fn log_captured_output(stream: &str, output: &str) {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    let mut bytes_logged = 0usize;
    let mut truncated = false;
    for (lines_logged, line) in output.lines().enumerate() {
        if lines_logged >= MAX_TERMINAL_LOG_LINES || bytes_logged >= MAX_TERMINAL_LOG_BYTES {
            truncated = true;
            break;
        }
        let remaining = MAX_TERMINAL_LOG_BYTES - bytes_logged;
        let (escaped, line_truncated) = escape_terminal_text(line, remaining);
        let _ = writeln!(stdout, "[sandbox][inside][{stream}] {escaped}");
        bytes_logged = bytes_logged.saturating_add(escaped.len());
        if line_truncated {
            truncated = true;
            break;
        }
    }
    if truncated {
        let _ = writeln!(
            stdout,
            "[sandbox][inside][{stream}] <terminal replay truncated>"
        );
    }
}

fn truncate_string_at_boundary(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

fn terminal_safe_text(value: &str) -> String {
    const MAX_FIELD_BYTES: usize = 4 * 1024;
    let (mut escaped, truncated) = escape_terminal_text(value, MAX_FIELD_BYTES);
    if truncated {
        escaped.push_str("<truncated>");
    }
    escaped
}

fn escape_terminal_text(value: &str, max_bytes: usize) -> (String, bool) {
    let mut escaped = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        let replacement = if character.is_control() || is_unicode_format_control(character) {
            format!("\\u{{{:04X}}}", character as u32)
        } else {
            character.to_string()
        };
        if escaped.len().saturating_add(replacement.len()) > max_bytes {
            return (escaped, true);
        }
        escaped.push_str(&replacement);
    }
    (escaped, false)
}

fn is_unicode_format_control(character: char) -> bool {
    matches!(
        character as u32,
        0x00ad
            | 0x061c
            | 0x070f
            | 0x0890..=0x0891
            | 0x08e2
            | 0x180e
            | 0x200b..=0x200f
            | 0x2028..=0x2029
            | 0x202a..=0x202e
            | 0x2060..=0x2064
            | 0x2066..=0x206f
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0001
            | 0xe0020..=0xe007f
    )
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(E_INVALIDARG, error.to_string())
}

fn hash_pinned_target(target: &mut PinnedTarget) -> Result<String> {
    target.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let copied = std::io::copy(
        &mut std::io::Read::by_ref(&mut target.file).take(target.len.saturating_add(1)),
        &mut hasher,
    )
    .map_err(io_error)?;
    target.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    if copied != target.len {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox target changed while its integrity hash was calculated",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

impl PinnedTarget {
    fn verify_identity(&self) -> Result<()> {
        let verifier = open_pinned_file(&self.path).map_err(|err| {
            Error::new(
                E_INVALIDARG,
                format!(
                    "failed to re-open pinned sandbox target {}: {err}",
                    terminal_safe_text(&self.path.display().to_string())
                ),
            )
        })?;
        if ensure_plain_disk_file(&verifier, &self.path)? != self.len {
            return Err(Error::new(
                E_ACCESSDENIED,
                "sandbox target size changed before process creation",
            ));
        }
        if file_identity(&verifier)? != self.identity {
            return Err(Error::new(
                E_ACCESSDENIED,
                "sandbox target identity changed before process creation",
            ));
        }
        verify_final_handle_path(&verifier, &self.path)
    }
}

fn pin_target(file: &str) -> Result<PinnedTarget> {
    let protected_artifact_root = crate::artifact::artifact_root()
        .and_then(|root| root.canonicalize())
        .map_err(|err| {
            Error::new(
                E_ACCESSDENIED,
                format!("failed to resolve Foxhole's protected artifact root: {err}"),
            )
        })?;
    let absolute = absolute_target_path(file)?;
    let drive_root = local_drive_root(&absolute)?;
    crate::artifact::verify_local_fixed_volume(&drive_root).map_err(|err| {
        Error::new(
            E_ACCESSDENIED,
            format!("sandbox target is not on a fixed local volume: {err}"),
        )
    })?;

    let mut parents = absolute.ancestors().skip(1).collect::<Vec<_>>();
    parents.reverse();
    let mut directory_pins = Vec::with_capacity(parents.len());
    for parent in parents {
        if parent.as_os_str().is_empty() {
            continue;
        }
        let pin = open_pinned_directory(parent).map_err(|err| {
            Error::new(
                E_ACCESSDENIED,
                format!(
                    "failed to pin sandbox target parent {}: {err}",
                    terminal_safe_text(&parent.display().to_string())
                ),
            )
        })?;
        ensure_plain_directory_handle(&pin, parent)?;
        verify_final_handle_path(&pin, parent)?;
        directory_pins.push(pin);
    }

    let target = open_pinned_file(&absolute).map_err(|err| {
        Error::new(
            E_INVALIDARG,
            format!(
                "failed to pin sandbox target {}: {err}",
                terminal_safe_text(&absolute.display().to_string())
            ),
        )
    })?;
    let len = ensure_plain_disk_file(&target, &absolute)?;
    if len > MAX_SANDBOX_TARGET_BYTES {
        return Err(Error::new(
            E_INVALIDARG,
            format!("sandbox target is {len} bytes; limit is {MAX_SANDBOX_TARGET_BYTES} bytes"),
        ));
    }
    verify_final_handle_path(&target, &absolute)?;
    let opened_path = crate::artifact::final_path_by_handle(&target).map_err(|err| {
        Error::new(
            E_ACCESSDENIED,
            format!("failed to resolve pinned sandbox target handle: {err}"),
        )
    })?;
    if crate::artifact::path_is_within(&opened_path, &protected_artifact_root) {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox target cannot be inside Foxhole's protected artifact root",
        ));
    }
    let identity = file_identity(&target)?;

    Ok(PinnedTarget {
        path: opened_path,
        file: target,
        len,
        identity,
        _directory_pins: directory_pins,
    })
}

fn absolute_target_path(file: &str) -> Result<PathBuf> {
    let supplied = Path::new(file);
    let joined = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        std::env::current_dir().map_err(io_error)?.join(supplied)
    };
    let mut absolute = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                return Err(Error::new(
                    E_INVALIDARG,
                    "sandbox target paths cannot contain '..' components",
                ));
            }
            Component::CurDir => continue,
            Component::Normal(name) => {
                crate::artifact::validate_file_name_component(name)
                    .map_err(|err| Error::new(E_INVALIDARG, err.to_string()))?;
                absolute.push(name);
            }
            Component::Prefix(_) | Component::RootDir => absolute.push(component.as_os_str()),
        }
    }
    reject_nonlocal_path(&absolute)?;
    if absolute.file_name().is_none() {
        return Err(Error::new(E_INVALIDARG, "sandbox target has no file name"));
    }
    Ok(absolute)
}

fn local_drive_root(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox target has no drive prefix",
        ));
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox target must use an absolute local drive path",
        ));
    }
    let mut root = PathBuf::new();
    root.push(prefix.as_os_str());
    root.push(Component::RootDir.as_os_str());
    Ok(root)
}

fn reject_nonlocal_path(path: &Path) -> Result<()> {
    let local = matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    if !local {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox targets must be regular files on a local drive",
        ));
    }
    Ok(())
}

fn open_pinned_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

fn open_pinned_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

fn ensure_plain_directory_handle(file: &File, path: &Path) -> Result<()> {
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
        return Err(Error::new(
            E_ACCESSDENIED,
            format!(
                "sandbox target parent is not a plain directory: {}",
                terminal_safe_text(&path.display().to_string())
            ),
        ));
    }
    if unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK {
        return Err(Error::new(
            E_ACCESSDENIED,
            "sandbox target parent is not on a disk filesystem",
        ));
    }
    Ok(())
}

fn ensure_plain_disk_file(file: &File, path: &Path) -> Result<u64> {
    let metadata = file.metadata().map_err(io_error)?;
    let handle = HANDLE(file.as_raw_handle());
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0
        || unsafe { GetFileType(handle) } != FILE_TYPE_DISK
    {
        return Err(Error::new(
            E_ACCESSDENIED,
            format!(
                "sandbox target is not a plain local-disk file: {}",
                terminal_safe_text(&path.display().to_string())
            ),
        ));
    }
    Ok(metadata.len())
}

fn file_identity(file: &File) -> Result<FileIdentity> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information)?;
    }
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    })
}

fn verify_final_handle_path(file: &File, expected: &Path) -> Result<()> {
    let mut buffer = vec![0u16; 512];
    let actual = loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(HANDLE(file.as_raw_handle()), &mut buffer, VOLUME_NAME_DOS)
        } as usize;
        if length == 0 {
            return Err(Error::from_thread());
        }
        if length < buffer.len() {
            break PathBuf::from(String::from_utf16_lossy(&buffer[..length]));
        }
        buffer.resize(length.saturating_add(1), 0);
    };

    let actual = win32_path_string(&actual);
    let expected = win32_path_string(expected);
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(Error::new(
            E_ACCESSDENIED,
            format!(
                "pinned target resolved to an unexpected path: {}",
                terminal_safe_text(&actual)
            ),
        ));
    }
    Ok(())
}

fn token_u32(
    token: HANDLE,
    information_class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<u32> {
    let mut value = 0u32;
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            information_class,
            Some(&mut value as *mut _ as *mut c_void),
            mem::size_of::<u32>() as u32,
            &mut returned,
        )?;
    }
    if returned < mem::size_of::<u32>() as u32 {
        return Err(Error::new(
            E_INVALIDARG,
            "token query returned a truncated scalar",
        ));
    }
    Ok(value)
}

fn token_information(
    token: HANDLE,
    information_class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>> {
    let mut required = 0u32;
    let _ = unsafe { GetTokenInformation(token, information_class, None, 0, &mut required) };
    if required == 0 {
        return Err(Error::from_thread());
    }
    let words = (required as usize).div_ceil(mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    unsafe {
        GetTokenInformation(
            token,
            information_class,
            Some(buffer.as_mut_ptr() as *mut c_void),
            required,
            &mut required,
        )?;
    }
    Ok(buffer)
}

fn verify_suspended_sandbox_token(
    process: HANDLE,
    expected_sid: PSID,
    expected_capabilities: &[SID_AND_ATTRIBUTES],
    maximum_integrity_rid: u32,
) -> Result<()> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token)?;
    }
    let token = WinHandle::new(token);
    let integrity = token_information(token.get(), TokenIntegrityLevel).map_err(|err| {
        Error::new(
            err.code(),
            format!("failed to query suspended token integrity: {err}"),
        )
    })?;
    let label = unsafe { &*(integrity.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
    if count.is_null() || unsafe { *count } == 0 {
        return Err(Error::new(
            E_ACCESSDENIED,
            "created process token has an invalid integrity SID",
        ));
    }
    let rid = unsafe { GetSidSubAuthority(label.Label.Sid, u32::from(*count) - 1) };
    if rid.is_null() || unsafe { *rid } > maximum_integrity_rid {
        return Err(Error::new(
            E_ACCESSDENIED,
            "created process token integrity exceeds the requested sandbox level",
        ));
    }
    if token_u32(token.get(), TokenIsAppContainer).map_err(|err| {
        Error::new(
            err.code(),
            format!("failed to query suspended AppContainer token state: {err}"),
        )
    })? == 0
    {
        return Err(Error::new(
            E_ACCESSDENIED,
            "created process is not an AppContainer",
        ));
    }
    match token_u32(token.get(), TokenIsLessPrivilegedAppContainer) {
        Ok(0) => {
            return Err(Error::new(
                E_ACCESSDENIED,
                "created process is not a less-privileged AppContainer",
            ));
        }
        Ok(_) => {}
        Err(err) if err.code() == E_INVALIDARG => {
            // Older Windows releases implement LPAC creation but not the newer
            // TokenIsLessPrivilegedAppContainer information class. On those systems,
            // verify the defining LPAC property: ALL APPLICATION PACKAGES is not enabled.
            if token_has_enabled_well_known_group(token.get(), WinBuiltinAnyPackageSid)? {
                return Err(Error::new(
                    E_ACCESSDENIED,
                    "created token still enables ALL APPLICATION PACKAGES",
                ));
            }
            log_outside("LPAC token verified by absence of the ALL APPLICATION PACKAGES group");
        }
        Err(err) => {
            return Err(Error::new(
                err.code(),
                format!("failed to query suspended LPAC token state: {err}"),
            ));
        }
    }

    let buffer = token_information(token.get(), TokenAppContainerSid).map_err(|err| {
        Error::new(
            err.code(),
            format!("failed to query suspended AppContainer SID: {err}"),
        )
    })?;
    let information = unsafe { &*(buffer.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION) };
    if information.TokenAppContainer.is_invalid()
        || unsafe { EqualSid(information.TokenAppContainer, expected_sid) }.is_err()
    {
        return Err(Error::new(
            E_ACCESSDENIED,
            "created process has an unexpected AppContainer identity",
        ));
    }
    verify_token_capabilities(token.get(), expected_capabilities)?;
    Ok(())
}

fn verify_token_capabilities(token: HANDLE, expected: &[SID_AND_ATTRIBUTES]) -> Result<()> {
    let buffer = token_information(token, TokenCapabilities).map_err(|err| {
        Error::new(
            err.code(),
            format!("failed to query suspended token capabilities: {err}"),
        )
    })?;
    let actual = counted_sid_attributes(&buffer)?;
    if actual.len() != expected.len()
        || actual.iter().any(|capability| {
            capability.Attributes & SE_GROUP_ENABLED_ATTRIBUTE == 0
                || !expected
                    .iter()
                    .any(|allowed| unsafe { EqualSid(capability.Sid, allowed.Sid) }.is_ok())
        })
        || expected.iter().any(|allowed| {
            !actual
                .iter()
                .any(|capability| unsafe { EqualSid(capability.Sid, allowed.Sid) }.is_ok())
        })
    {
        return Err(Error::new(
            E_ACCESSDENIED,
            "created process token capabilities do not exactly match sandbox policy",
        ));
    }
    Ok(())
}

fn token_has_enabled_well_known_group(token: HANDLE, kind: WELL_KNOWN_SID_TYPE) -> Result<bool> {
    let mut expected = CapabilitySid::new(kind)?;
    let buffer = token_information(token, TokenGroups)?;
    let values = counted_sid_attributes(&buffer)?;
    Ok(values.iter().any(|group| {
        group.Attributes & SE_GROUP_ENABLED_ATTRIBUTE != 0
            && unsafe { EqualSid(group.Sid, expected.as_psid()) }.is_ok()
    }))
}

fn counted_sid_attributes(buffer: &[usize]) -> Result<&[SID_AND_ATTRIBUTES]> {
    unsafe { rows_from_counted_table(buffer, mem::offset_of!(TOKEN_GROUPS, Groups)) }
        .ok_or_else(|| Error::new(E_INVALIDARG, "token query returned a truncated group array"))
}

fn build_sanitized_environment(working_dir: &Path, storage_root: &Path) -> Result<Vec<u16>> {
    let trusted = trusted_windows_paths()?;
    let system_root = win32_path_string(&trusted.windows);
    let system32 = win32_path_string(&trusted.system);
    let comspec = win32_path_string(&trusted.system.join("cmd.exe"));
    let private_dir = win32_path_string(working_dir);
    let profile_dir = win32_path_string(storage_root);

    let mut entries = vec![
        ("APPDATA", private_dir.clone()),
        ("COMSPEC", comspec),
        ("LOCALAPPDATA", profile_dir.clone()),
        ("PATH", system32),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD".to_string()),
        ("SystemRoot", system_root.clone()),
        ("TEMP", private_dir.clone()),
        ("TMP", private_dir.clone()),
        ("USERPROFILE", profile_dir),
        ("WINDIR", system_root),
    ];
    entries.sort_unstable_by_key(|(name, _)| name.to_ascii_uppercase());

    let mut block = Vec::new();
    for (name, value) in entries {
        if name.contains(['\0', '=']) || value.contains('\0') {
            return Err(Error::new(
                E_INVALIDARG,
                "sandbox environment contains an invalid NUL or key separator",
            ));
        }
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn trusted_windows_paths() -> Result<TrustedWindowsPaths> {
    let windows = query_windows_directory(GetSystemWindowsDirectoryW, "Windows directory")?;
    let system = query_windows_directory(GetSystemDirectoryW, "Windows system directory")?;
    Ok(TrustedWindowsPaths { windows, system })
}

fn query_windows_directory(
    query: unsafe fn(Option<&mut [u16]>) -> u32,
    description: &str,
) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    let path = loop {
        let length = unsafe { query(Some(&mut buffer)) } as usize;
        if length == 0 {
            return Err(Error::from_thread());
        }
        if length < buffer.len() {
            break PathBuf::from(String::from_utf16_lossy(&buffer[..length]));
        }
        buffer.resize(length.saturating_add(1), 0);
    };
    if !path.is_absolute() {
        return Err(Error::new(
            E_ACCESSDENIED,
            format!("the OS returned a non-absolute {description}"),
        ));
    }
    reject_nonlocal_path(&path)?;
    Ok(path)
}

fn build_capability_sids(
    allow_internet_client: bool,
    batch_runtime: bool,
) -> Result<Vec<CapabilitySid>> {
    let mut sids = Vec::new();
    if batch_runtime {
        // LPAC removes registry access that ordinary AppContainers receive.
        // cmd.exe requires read-only registry access during initialization, and
        // Windows command-line HTTPS clients need Schannel identity services.
        sids.push(CapabilitySid::from_name("registryRead")?);
        sids.push(CapabilitySid::from_name("lpacIdentityServices")?);
    }
    if allow_internet_client {
        sids.push(CapabilitySid::new(WinCapabilityInternetClientSid)?);
    }
    Ok(sids)
}

fn sid_attributes(sids: &mut [CapabilitySid]) -> Vec<SID_AND_ATTRIBUTES> {
    sids.iter_mut()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: SE_GROUP_ENABLED_ATTRIBUTE,
        })
        .collect()
}

fn create_disposable_app_container(
    capabilities: &[SID_AND_ATTRIBUTES],
) -> Result<AppContainerProfile> {
    let (name, marker_path, marker, marker_directory_pins) = create_profile_marker()?;
    let name_wide = to_wide_null(&name);
    let display = to_wide_null(APP_CONTAINER_DISPLAY);
    let description = to_wide_null(APP_CONTAINER_DESCRIPTION);
    let capability_slice = (!capabilities.is_empty()).then_some(capabilities);

    let created = unsafe {
        CreateAppContainerProfile(
            PCWSTR(name_wide.as_ptr()),
            PCWSTR(display.as_ptr()),
            PCWSTR(description.as_ptr()),
            capability_slice,
        )
    };
    let sid = match created {
        Ok(sid) => sid,
        Err(err) => {
            drop(marker);
            let _ = fs::remove_file(&marker_path);
            return Err(err);
        }
    };
    log_outside(format!(
        "created disposable AppContainer profile {}",
        terminal_safe_text(&name)
    ));
    Ok(AppContainerProfile {
        sid,
        name,
        name_wide,
        marker: Some(marker),
        marker_path,
        _marker_directory_pins: marker_directory_pins,
        deleted: false,
    })
}

fn app_container_storage(
    app_container_sid: PSID,
    profile_name: &str,
) -> Result<AppContainerStorage> {
    let sid_string = sid_to_string(app_container_sid)?;
    let path = unsafe { GetAppContainerFolderPath(PCWSTR(sid_string.as_ptr()))? };
    let root = PathBuf::from(unsafe { take_cotaskmem_pwstr(path) });
    if !root.is_absolute() {
        return Err(Error::new(
            E_INVALIDARG,
            format!(
                "AppContainer storage path is not absolute: {}",
                terminal_safe_text(&root.display().to_string())
            ),
        ));
    }
    crate::artifact::validate_absolute_local_path(&root).map_err(|err| {
        Error::new(
            E_ACCESSDENIED,
            format!("AppContainer storage path is not a safe local path: {err}"),
        )
    })?;
    crate::artifact::verify_local_fixed_volume(&root).map_err(|err| {
        Error::new(
            E_ACCESSDENIED,
            format!("AppContainer storage is not on a fixed local volume: {err}"),
        )
    })?;
    ensure_directory_not_reparse(&root)?;

    let temp = root.join("Temp");
    fs::create_dir_all(&temp).map_err(|err| {
        Error::new(
            E_INVALIDARG,
            format!(
                "failed to create AppContainer Temp directory {}: {err}",
                terminal_safe_text(&temp.display().to_string())
            ),
        )
    })?;
    ensure_directory_not_reparse(&temp)?;

    let suffix = profile_name
        .strip_prefix(APP_CONTAINER_NAME_PREFIX)
        .ok_or_else(|| Error::new(E_INVALIDARG, "invalid disposable profile name"))?;
    let working_dir = temp.join(format!("run-{suffix}"));
    if !working_dir.starts_with(&root) {
        return Err(Error::new(
            E_INVALIDARG,
            "AppContainer working directory escaped its profile root",
        ));
    }
    fs::create_dir(&working_dir).map_err(|err| {
        Error::new(
            E_INVALIDARG,
            format!(
                "failed to create sandbox working directory {}: {err}",
                terminal_safe_text(&working_dir.display().to_string())
            ),
        )
    })?;
    ensure_directory_not_reparse(&working_dir)?;

    // Windows rewrites LOCALAPPDATA/TEMP for AppContainer tokens even when an explicit
    // environment is supplied. Because Foxhole deliberately supplies the private profile root
    // rather than the host LocalAppData directory, pre-create the resulting nested private path.
    let rewritten_components = ["Packages", profile_name, "AC", "Temp"];
    let mut rewritten = root.clone();
    for component in rewritten_components {
        rewritten.push(component);
        fs::create_dir(&rewritten)
            .or_else(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(err)
                }
            })
            .map_err(io_error)?;
        ensure_directory_not_reparse(&rewritten)?;
    }

    Ok(AppContainerStorage { root, working_dir })
}

fn profile_marker_dir() -> std::io::Result<(PathBuf, Vec<File>)> {
    let artifact_root = crate::artifact::artifact_root()?;
    let directory = artifact_root.join("profile-cleanup");
    let pins = crate::artifact::pin_safe_directory_tree(&directory, true)?;
    crate::artifact::harden_owned_directory_chain(&artifact_root, &directory)?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AppContainer cleanup marker path is not a plain directory",
        ));
    }
    Ok((directory, pins))
}

fn disposable_profile_name() -> Result<String> {
    Ok(format!(
        "{APP_CONTAINER_NAME_PREFIX}{}",
        crate::artifact::random_hex(16).map_err(io_error)?
    ))
}

fn is_disposable_profile_name(value: &str) -> bool {
    value
        .strip_prefix(APP_CONTAINER_NAME_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn create_profile_marker() -> Result<(String, PathBuf, File, Vec<File>)> {
    let (directory, pins) = profile_marker_dir().map_err(io_error)?;
    for _ in 0..8 {
        let name = disposable_profile_name()?;
        let path = directory.join(&name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&path)
        {
            Ok(marker) => return Ok((name, path, marker, pins)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(io_error(err)),
        }
    }
    Err(Error::new(
        E_INVALIDARG,
        "failed to allocate a unique AppContainer cleanup marker",
    ))
}

fn scavenge_stale_app_container_profiles() {
    let legacy_name = to_wide_null(LEGACY_APP_CONTAINER_NAME);
    match unsafe { DeleteAppContainerProfile(PCWSTR(legacy_name.as_ptr())) } {
        Ok(()) => log_outside("legacy fixed AppContainer profile cleanup completed"),
        Err(err) => log_outside(format!(
            "legacy fixed AppContainer profile could not be removed and will be retried: {err}"
        )),
    }

    let Ok((directory, _directory_pins)) = profile_marker_dir() else {
        log_outside("unable to open AppContainer cleanup marker directory");
        return;
    };
    let Ok(entries) = fs::read_dir(&directory) else {
        log_outside("unable to enumerate AppContainer cleanup markers");
        return;
    };

    for entry in entries.flatten().take(1_024) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_disposable_profile_name(&name) {
            continue;
        }
        let path = entry.path();
        let Ok(marker) = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&path)
        else {
            // A live Foxhole process holds its marker without sharing.
            continue;
        };
        let name_wide = to_wide_null(&name);
        match unsafe { DeleteAppContainerProfile(PCWSTR(name_wide.as_ptr())) } {
            Ok(()) => {
                drop(marker);
                let _ = fs::remove_file(&path);
                log_outside(format!(
                    "removed stale AppContainer profile {}",
                    terminal_safe_text(&name)
                ));
            }
            Err(err) => log_outside(format!(
                "failed to scavenge stale AppContainer profile {}: {err}",
                terminal_safe_text(&name)
            )),
        }
    }
}

fn ensure_directory_not_reparse(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
        return Err(Error::new(
            E_INVALIDARG,
            format!(
                "sandbox storage path is not a plain directory: {}",
                terminal_safe_text(&path.display().to_string())
            ),
        ));
    }
    Ok(())
}

fn ensure_no_loopback_exemption(app_container_sid: PSID) -> Result<()> {
    let mut count = 0u32;
    let mut entries = std::ptr::null_mut::<SID_AND_ATTRIBUTES>();
    let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
    if status != 0 {
        return Err(Error::from_hresult(HRESULT::from_win32(status)));
    }

    let mut exempt = false;
    if count > 0 && entries.is_null() {
        return Err(Error::new(
            E_INVALIDARG,
            "loopback exemption query returned a null result",
        ));
    }
    if !entries.is_null() {
        let values = unsafe { std::slice::from_raw_parts(entries, count as usize) };
        exempt = values
            .iter()
            .any(|entry| unsafe { EqualSid(entry.Sid, app_container_sid) }.is_ok());

        let heap = unsafe { GetProcessHeap()? };
        for entry in values {
            if !entry.Sid.is_invalid() {
                unsafe {
                    let _ = HeapFree(heap, HEAP_FLAGS(0), Some(entry.Sid.0 as *const c_void));
                }
            }
        }
        unsafe {
            let _ = HeapFree(heap, HEAP_FLAGS(0), Some(entries as *const c_void));
        }
    }

    if exempt {
        return Err(Error::new(
            E_ACCESSDENIED,
            "refusing to launch an AppContainer with a loopback exemption",
        ));
    }
    Ok(())
}

fn sid_to_string(sid: PSID) -> Result<Vec<u16>> {
    let mut raw = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut raw)?;
    }
    let value = unsafe { pwstr_to_string(raw) };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(raw.0 as *mut c_void)));
    }
    Ok(to_wide_null(&value))
}

fn sid_to_string_text(sid: PSID) -> Result<String> {
    let value = sid_to_string(sid)?;
    let value = value.strip_suffix(&[0]).unwrap_or(&value);
    String::from_utf16(value)
        .map_err(|_| Error::new(E_INVALIDARG, "sandbox SID is not valid UTF-16"))
}

unsafe fn take_cotaskmem_pwstr(ptr: PWSTR) -> String {
    let value = unsafe { pwstr_to_string(ptr) };
    unsafe {
        CoTaskMemFree(Some(ptr.0 as *const c_void));
    }
    value
}

unsafe fn pwstr_to_string(ptr: PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.0.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr.0, len))
    }
}

fn create_limited_job(timeout_secs: u64, resource_limits: &ResourceLimits) -> Result<WinHandle> {
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null())? };
    let handle = WinHandle::new(job);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_JOB_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = resource_limits.active_process_limit;
    limits.BasicLimitInformation.PerJobUserTimeLimit =
        timeout_secs.saturating_mul(10_000_000).min(i64::MAX as u64) as i64;
    limits.ProcessMemoryLimit = resource_limits.process_memory_bytes;
    limits.JobMemoryLimit = resource_limits.job_memory_bytes;

    unsafe {
        SetInformationJobObject(
            handle.get(),
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const c_void,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
    }

    let ui_restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT(0x00ff),
    };
    unsafe {
        SetInformationJobObject(
            handle.get(),
            JobObjectBasicUIRestrictions,
            &ui_restrictions as *const _ as *const c_void,
            mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )?;
    }

    let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
        ..Default::default()
    };
    cpu.Anonymous.CpuRate = resource_limits.cpu_rate_percent.saturating_mul(100);
    unsafe {
        SetInformationJobObject(
            handle.get(),
            JobObjectCpuRateControlInformation,
            &cpu as *const _ as *const c_void,
            mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        )?;
    }

    Ok(handle)
}

fn wait_for_process(
    process: HANDLE,
    job: HANDLE,
    timeout_secs: u64,
    storage_root: &Path,
) -> Result<WaitOutcome> {
    let started = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if crate::interrupt::requested() {
            terminate_job_and_wait(job, process)?;
            return Err(Error::new(
                HRESULT(0x8000_4004_u32 as i32),
                "sandbox run interrupted; cleanup will now run",
            ));
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            terminate_job_and_wait(job, process)?;
            return Ok(WaitOutcome {
                timed_out: true,
                warning: None,
            });
        }
        let wait_ms = timeout
            .saturating_sub(elapsed)
            .as_millis()
            .min(WAIT_SLICE_MS as u128)
            .max(1) as u32;
        let wait = unsafe { WaitForSingleObject(process, wait_ms) };
        if wait == WAIT_OBJECT_0 {
            return Ok(WaitOutcome {
                timed_out: false,
                warning: storage_limit_violation(storage_root),
            });
        }
        if wait == WAIT_FAILED {
            return Err(Error::from_thread());
        }
        if wait != WAIT_TIMEOUT {
            return Err(Error::new(
                E_INVALIDARG,
                format!("unexpected WaitForSingleObject result: {}", wait.0),
            ));
        }

        if started.elapsed() >= timeout {
            terminate_job_and_wait(job, process)?;
            return Ok(WaitOutcome {
                timed_out: true,
                warning: None,
            });
        }
        let storage_warning = storage_limit_violation(storage_root);
        if started.elapsed() >= timeout {
            terminate_job_and_wait(job, process)?;
            return Ok(WaitOutcome {
                timed_out: true,
                warning: None,
            });
        }
        if let Some(warning) = storage_warning {
            terminate_job_and_wait(job, process)?;
            return Ok(WaitOutcome {
                timed_out: false,
                warning: Some(warning),
            });
        }
    }
}

fn terminate_job_and_wait(job: HANDLE, process: HANDLE) -> Result<()> {
    unsafe {
        TerminateJobObject(job, 1)?;
        if WaitForSingleObject(process, u32::MAX) == WAIT_FAILED {
            return Err(Error::from_thread());
        }
    }
    Ok(())
}

fn storage_limit_violation(root: &Path) -> Option<String> {
    match storage_usage(root) {
        Ok(bytes) if bytes <= MAX_STORAGE_BYTES => None,
        Ok(bytes) => Some(format!(
            "sandbox storage limit exceeded: observed {bytes} bytes (limit {MAX_STORAGE_BYTES})"
        )),
        Err(err) => Some(format!(
            "sandbox storage validation failed; job was terminated: {err}"
        )),
    }
}

fn storage_usage(root: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut entries_seen = 0usize;
    let mut path_bytes_seen = storage_path_bytes(root)?;
    let (root_pin, root_metadata) = pin_storage_entry(root)?;
    if !root_metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sandbox storage root is not a directory",
        ));
    }
    verify_storage_handle_path(&root_pin, root)?;
    reject_named_storage_streams(&root_pin, root)?;

    let mut directory_pins = vec![root_pin];
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)? {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_STORAGE_ENTRIES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("sandbox storage contains more than {MAX_STORAGE_ENTRIES} entries"),
                ));
            }
            let path = entry?.path();
            path_bytes_seen = path_bytes_seen
                .checked_add(storage_path_bytes(&path)?)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "sandbox storage path budget overflowed",
                    )
                })?;
            if path_bytes_seen > MAX_STORAGE_PATH_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "sandbox storage paths exceed the {MAX_STORAGE_PATH_BYTES}-byte traversal budget"
                    ),
                ));
            }
            let (pin, metadata) = pin_storage_entry(&path)?;
            verify_storage_handle_path(&pin, &path)?;
            reject_named_storage_streams(&pin, &path)?;
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
                if total > MAX_STORAGE_BYTES {
                    return Ok(total);
                }
            } else if metadata.is_dir() {
                stack.push(path);
                directory_pins.push(pin);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "sandbox storage contains a non-file, non-directory entry",
                ));
            }
        }
    }
    Ok(total)
}

fn pin_storage_entry(path: &Path) -> std::io::Result<(File, fs::Metadata)> {
    let file = open_storage_entry(path, FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)?;
    let metadata = validate_storage_entry(&file, path)?;
    if !metadata.is_dir() {
        return Ok((file, metadata));
    }

    // Directory pins intentionally do not share WRITE: otherwise a specimen can turn a
    // validated directory into a junction in place before the broker enumerates it.
    let directory = open_storage_entry(path, FILE_SHARE_READ.0)?;
    let directory_metadata = validate_storage_entry(&directory, path)?;
    if !directory_metadata.is_dir()
        || file_identity(&file).map_err(|err| std::io::Error::other(err.to_string()))?
            != file_identity(&directory).map_err(|err| std::io::Error::other(err.to_string()))?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "sandbox storage directory identity changed while being pinned",
        ));
    }
    Ok((directory, directory_metadata))
}

fn open_storage_entry(path: &Path, share_mode: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

fn validate_storage_entry(file: &File, path: &Path) -> std::io::Result<fs::Metadata> {
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "reparse point found in sandbox storage: {}",
                terminal_safe_text(&path.display().to_string())
            ),
        ));
    }
    if unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sandbox storage contains a non-disk entry",
        ));
    }
    Ok(metadata)
}

fn verify_storage_handle_path(file: &File, path: &Path) -> std::io::Result<()> {
    verify_final_handle_path(file, path).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("sandbox storage path changed during validation: {err}"),
        )
    })
}

fn storage_path_bytes(path: &Path) -> std::io::Result<usize> {
    path.as_os_str()
        .encode_wide()
        .count()
        .checked_mul(mem::size_of::<u16>())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sandbox storage path length overflowed",
            )
        })
}

fn reject_named_storage_streams(file: &File, path: &Path) -> std::io::Result<()> {
    let mut buffer_bytes = 4 * 1024usize;
    let buffer = loop {
        let words = buffer_bytes.div_ceil(mem::size_of::<usize>());
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(words).map_err(|_| {
            std::io::Error::other("failed to allocate bounded storage stream buffer")
        })?;
        buffer.resize(words, 0usize);
        match unsafe {
            GetFileInformationByHandleEx(
                HANDLE(file.as_raw_handle()),
                FileStreamInfo,
                buffer.as_mut_ptr() as *mut c_void,
                buffer_bytes as u32,
            )
        } {
            Ok(()) => break buffer,
            Err(err) if err.code() == HRESULT::from_win32(ERROR_HANDLE_EOF.0) => return Ok(()),
            Err(err)
                if err.code() == HRESULT::from_win32(ERROR_MORE_DATA.0)
                    || err.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) =>
            {
                if buffer_bytes >= MAX_STREAM_INFO_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "sandbox storage stream metadata exceeds its bounded buffer",
                    ));
                }
                buffer_bytes = buffer_bytes.saturating_mul(2).min(MAX_STREAM_INFO_BYTES);
            }
            Err(err) => {
                return Err(std::io::Error::other(format!(
                    "failed to enumerate storage streams for {}: {err}",
                    terminal_safe_text(&path.display().to_string())
                )));
            }
        }
    };

    validate_storage_stream_buffer(&buffer, path)
}

fn validate_storage_stream_buffer(buffer: &[usize], path: &Path) -> std::io::Result<()> {
    let available = buffer.len().saturating_mul(mem::size_of::<usize>());
    let header_bytes = mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let mut offset = 0usize;
    for stream_index in 0..MAX_STREAMS_PER_STORAGE_ENTRY {
        if offset
            .checked_add(header_bytes)
            .is_none_or(|end| end > available)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage stream metadata contains a truncated header",
            ));
        }
        let entry = unsafe { (buffer.as_ptr() as *const u8).add(offset) };
        let next = unsafe { std::ptr::read_unaligned(entry as *const u32) } as usize;
        let name_bytes = unsafe { std::ptr::read_unaligned(entry.add(4) as *const u32) } as usize;
        if name_bytes == 0 || !name_bytes.is_multiple_of(mem::size_of::<u16>()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage stream metadata contains an invalid name length",
            ));
        }
        let entry_bytes = header_bytes.checked_add(name_bytes).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage stream metadata length overflowed",
            )
        })?;
        if offset
            .checked_add(entry_bytes)
            .is_none_or(|end| end > available)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage stream metadata contains a truncated name",
            ));
        }
        let stream_name = unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(
                entry.add(header_bytes) as *const u16,
                name_bytes / mem::size_of::<u16>(),
            ))
        };
        if !stream_name.eq_ignore_ascii_case("::$DATA") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "named data stream found in sandbox storage: {}",
                    terminal_safe_text(&path.display().to_string())
                ),
            ));
        }
        if next == 0 {
            return Ok(());
        }
        if next < entry_bytes
            || !next.is_multiple_of(mem::align_of::<FILE_STREAM_INFO>())
            || offset
                .checked_add(next)
                .is_none_or(|new_offset| new_offset >= available)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage stream metadata contains an invalid next-entry offset",
            ));
        }
        offset += next;
        if stream_index + 1 == MAX_STREAMS_PER_STORAGE_ENTRY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "sandbox storage entry has more than {MAX_STREAMS_PER_STORAGE_ENTRY} streams"
                ),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SocketObservation {
    pid: u32,
    protocol: &'static str,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: &'static str,
}

#[derive(Clone, Debug)]
struct ProcessSnapshot {
    pid: u32,
    parent_pid: u32,
    image: String,
}

fn monitor_activity(root_pid: u32, stop: Arc<AtomicBool>, started_at: Instant) -> MonitorResult {
    let mut result = MonitorResult::default();
    let mut seen_processes = HashSet::new();
    let mut seen_connections = HashSet::new();
    let mut dropped_process_events = 0u64;
    let mut dropped_network_events = 0u64;
    let mut skipped_network_snapshots = false;
    let mut truncated_network_snapshots = 0u64;
    let mut incomplete_network_snapshots = 0u64;

    loop {
        let processes = process_tree(root_pid);
        let observed_at_ms = elapsed_ms(started_at);
        for process in &processes {
            if seen_processes.contains(&process.pid) {
                continue;
            }
            if seen_processes.len() >= MAX_PROCESS_OBSERVATIONS {
                dropped_process_events = dropped_process_events.saturating_add(1);
                continue;
            }
            if seen_processes.insert(process.pid) {
                log_monitor(format!(
                    "spawned process pid={} parent={} image={}",
                    process.pid,
                    process.parent_pid,
                    terminal_safe_text(&process.image)
                ));
                result.processes.push(ProcessObservation {
                    pid: process.pid,
                    parent_pid: process.parent_pid,
                    image: process.image.clone(),
                    observed_at_ms,
                });
            }
        }

        let pids = processes
            .iter()
            .map(|process| process.pid)
            .collect::<HashSet<_>>();
        if seen_connections.len() >= MAX_NETWORK_OBSERVATIONS {
            skipped_network_snapshots = true;
        } else {
            let (connections, snapshot_truncated, snapshot_incomplete) =
                network_connections_for_pids(&pids);
            if snapshot_truncated {
                truncated_network_snapshots = truncated_network_snapshots.saturating_add(1);
            }
            if snapshot_incomplete {
                incomplete_network_snapshots = incomplete_network_snapshots.saturating_add(1);
            }
            for connection in connections {
                if seen_connections.contains(&connection) {
                    continue;
                }
                if seen_connections.len() >= MAX_NETWORK_OBSERVATIONS {
                    dropped_network_events = dropped_network_events.saturating_add(1);
                    continue;
                }
                if seen_connections.insert(connection.clone()) {
                    if connection.remote_addr.is_empty() {
                        log_monitor(format!(
                            "pid={} {} local={}:{} state={}",
                            connection.pid,
                            connection.protocol,
                            connection.local_addr,
                            connection.local_port,
                            connection.state
                        ));
                    } else {
                        log_monitor(format!(
                            "pid={} {} {}:{} -> {}:{} state={}",
                            connection.pid,
                            connection.protocol,
                            connection.local_addr,
                            connection.local_port,
                            connection.remote_addr,
                            connection.remote_port,
                            connection.state
                        ));
                    }
                    result.network_connections.push(NetworkObservation {
                        pid: connection.pid,
                        protocol: connection.protocol.to_string(),
                        local_address: connection.local_addr,
                        local_port: connection.local_port,
                        remote_address: connection.remote_addr,
                        remote_port: connection.remote_port,
                        state: connection.state.to_string(),
                        observed_at_ms,
                    });
                }
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_millis(MONITOR_POLL_MS));
    }

    if dropped_process_events > 0 {
        result.warnings.push(format!(
            "process observation limit reached; dropped {dropped_process_events} later poll events"
        ));
    }
    if dropped_network_events > 0 {
        result.warnings.push(format!(
            "network observation limit reached; dropped {dropped_network_events} later poll events"
        ));
    }
    if skipped_network_snapshots {
        result.warnings.push(
            "network observation limit reached; later global socket snapshots were skipped"
                .to_string(),
        );
    }
    if truncated_network_snapshots > 0 {
        result.warnings.push(format!(
            "{truncated_network_snapshots} network snapshots exceeded the per-snapshot row cap"
        ));
    }
    if incomplete_network_snapshots > 0 {
        result.warnings.push(format!(
                "{incomplete_network_snapshots} network snapshots were incomplete because a bounded table query failed"
            ));
    }

    result
}

fn process_tree(root_pid: u32) -> Vec<ProcessSnapshot> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let Ok(snapshot) = snapshot else {
        return Vec::new();
    };
    let mut snapshot = WinHandle::new(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut entries = HashMap::new();
    let mut entries_seen = 0usize;

    let first = unsafe { Process32FirstW(snapshot.get(), &mut entry) };
    if first.is_ok() {
        loop {
            if entries_seen >= MAX_PROCESS_SNAPSHOT_ENTRIES {
                break;
            }
            entries_seen += 1;
            children
                .entry(entry.th32ParentProcessID)
                .or_default()
                .push(entry.th32ProcessID);
            entries.insert(
                entry.th32ProcessID,
                ProcessSnapshot {
                    pid: entry.th32ProcessID,
                    parent_pid: entry.th32ParentProcessID,
                    image: utf16_array_to_string(&entry.szExeFile),
                },
            );
            if unsafe { Process32NextW(snapshot.get(), &mut entry) }.is_err() {
                break;
            }
        }
    }
    snapshot.close();

    let mut process_ids = HashSet::from([root_pid]);
    let mut stack = vec![root_pid];
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children.get(&pid) {
            for child in kids {
                if process_ids.insert(*child) {
                    stack.push(*child);
                }
            }
        }
    }

    process_ids
        .into_iter()
        .filter_map(|pid| entries.remove(&pid))
        .collect()
}

fn utf16_array_to_string(value: &[u16]) -> String {
    let len = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

fn elapsed_ms(started_at: Instant) -> u64 {
    started_at.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn network_connections_for_pids(pids: &HashSet<u32>) -> (Vec<SocketObservation>, bool, bool) {
    let mut connections = Vec::new();
    let mut truncated = false;
    let mut incomplete = false;

    append_network_query(
        &mut connections,
        &mut truncated,
        &mut incomplete,
        tcp4_connections_for_pids(pids, MAX_NETWORK_ROWS_PER_SNAPSHOT.saturating_add(1)),
    );
    if connections.len() < MAX_NETWORK_ROWS_PER_SNAPSHOT {
        let limit = MAX_NETWORK_ROWS_PER_SNAPSHOT
            .saturating_sub(connections.len())
            .saturating_add(1);
        let rows = tcp6_connections_for_pids(pids, limit);
        append_network_query(&mut connections, &mut truncated, &mut incomplete, rows);
    } else {
        truncated = true;
    }
    if connections.len() < MAX_NETWORK_ROWS_PER_SNAPSHOT {
        let limit = MAX_NETWORK_ROWS_PER_SNAPSHOT
            .saturating_sub(connections.len())
            .saturating_add(1);
        let rows = udp4_connections_for_pids(pids, limit);
        append_network_query(&mut connections, &mut truncated, &mut incomplete, rows);
    } else {
        truncated = true;
    }
    if connections.len() < MAX_NETWORK_ROWS_PER_SNAPSHOT {
        let limit = MAX_NETWORK_ROWS_PER_SNAPSHOT
            .saturating_sub(connections.len())
            .saturating_add(1);
        let rows = udp6_connections_for_pids(pids, limit);
        append_network_query(&mut connections, &mut truncated, &mut incomplete, rows);
    } else {
        truncated = true;
    }
    (connections, truncated, incomplete)
}

fn append_network_query(
    output: &mut Vec<SocketObservation>,
    truncated: &mut bool,
    incomplete: &mut bool,
    rows: Option<Vec<SocketObservation>>,
) {
    match rows {
        Some(rows) => append_network_rows(output, truncated, rows),
        None => *incomplete = true,
    }
}

fn append_network_rows(
    output: &mut Vec<SocketObservation>,
    truncated: &mut bool,
    mut rows: Vec<SocketObservation>,
) {
    let remaining = MAX_NETWORK_ROWS_PER_SNAPSHOT.saturating_sub(output.len());
    if rows.len() > remaining {
        rows.truncate(remaining);
        *truncated = true;
    }
    output.extend(rows);
}

fn query_network_table(
    mut query: impl FnMut(Option<*mut c_void>, &mut u32) -> u32,
) -> Option<Vec<usize>> {
    let mut size = 0u32;
    let first = query(None, &mut size);
    if first != ERROR_INSUFFICIENT_BUFFER_CODE && first != 0 {
        return None;
    }

    for _ in 0..3 {
        let requested = size as usize;
        if requested > MAX_NETWORK_SNAPSHOT_BYTES {
            return None;
        }
        let word_size = mem::size_of::<usize>();
        let words = requested
            .checked_add(word_size - 1)?
            .checked_div(word_size)?
            .max(1);
        if words.checked_mul(word_size)? > MAX_NETWORK_SNAPSHOT_BYTES {
            return None;
        }
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(words).ok()?;
        buffer.resize(words, 0usize);
        let result = query(Some(buffer.as_mut_ptr() as *mut c_void), &mut size);
        if result == 0 {
            return Some(buffer);
        }
        if result != ERROR_INSUFFICIENT_BUFFER_CODE {
            return None;
        }
    }
    None
}

unsafe fn rows_from_counted_table<Row>(buffer: &[usize], rows_offset: usize) -> Option<&[Row]> {
    let available = buffer.len().checked_mul(mem::size_of::<usize>())?;
    if available < mem::size_of::<u32>() || rows_offset > available {
        return None;
    }
    let count = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const u32) } as usize;
    let rows_size = count.checked_mul(mem::size_of::<Row>())?;
    if rows_offset.checked_add(rows_size)? > available {
        return None;
    }
    let rows = unsafe { (buffer.as_ptr() as *const u8).add(rows_offset) as *const Row };
    if rows.addr() % mem::align_of::<Row>() != 0 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(rows, count) })
}

fn tcp4_connections_for_pids(pids: &HashSet<u32>, limit: usize) -> Option<Vec<SocketObservation>> {
    let buffer = query_network_table(|buffer, size| unsafe {
        GetExtendedTcpTable(
            buffer,
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    let rows = (unsafe {
        rows_from_counted_table::<MIB_TCPROW_OWNER_PID>(
            &buffer,
            mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        )
    })?;
    Some(
        rows.iter()
            .filter(|row| pids.contains(&row.dwOwningPid))
            .take(limit)
            .map(|row| SocketObservation {
                pid: row.dwOwningPid,
                protocol: "tcp/ipv4",
                local_addr: ipv4_from_mib(row.dwLocalAddr).to_string(),
                local_port: port_from_mib(row.dwLocalPort),
                remote_addr: ipv4_from_mib(row.dwRemoteAddr).to_string(),
                remote_port: port_from_mib(row.dwRemotePort),
                state: tcp_state_name(row.dwState),
            })
            .collect(),
    )
}

fn tcp6_connections_for_pids(pids: &HashSet<u32>, limit: usize) -> Option<Vec<SocketObservation>> {
    let buffer = query_network_table(|buffer, size| unsafe {
        GetExtendedTcpTable(
            buffer,
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    let rows = (unsafe {
        rows_from_counted_table::<MIB_TCP6ROW_OWNER_PID>(
            &buffer,
            mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        )
    })?;
    Some(
        rows.iter()
            .filter(|row| pids.contains(&row.dwOwningPid))
            .take(limit)
            .map(tcp6_observation)
            .collect(),
    )
}

fn tcp6_observation(row: &MIB_TCP6ROW_OWNER_PID) -> SocketObservation {
    SocketObservation {
        pid: row.dwOwningPid,
        protocol: "tcp/ipv6",
        local_addr: scoped_ipv6(row.ucLocalAddr, row.dwLocalScopeId),
        local_port: port_from_mib(row.dwLocalPort),
        remote_addr: scoped_ipv6(row.ucRemoteAddr, row.dwRemoteScopeId),
        remote_port: port_from_mib(row.dwRemotePort),
        state: tcp_state_name(row.dwState),
    }
}

fn udp4_connections_for_pids(pids: &HashSet<u32>, limit: usize) -> Option<Vec<SocketObservation>> {
    let buffer = query_network_table(|buffer, size| unsafe {
        GetExtendedUdpTable(
            buffer,
            size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    })?;
    let rows = (unsafe {
        rows_from_counted_table::<MIB_UDPROW_OWNER_PID>(
            &buffer,
            mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
        )
    })?;
    Some(
        rows.iter()
            .filter(|row| pids.contains(&row.dwOwningPid))
            .take(limit)
            .map(udp4_observation)
            .collect(),
    )
}

fn udp4_observation(row: &MIB_UDPROW_OWNER_PID) -> SocketObservation {
    SocketObservation {
        pid: row.dwOwningPid,
        protocol: "udp/ipv4",
        local_addr: ipv4_from_mib(row.dwLocalAddr).to_string(),
        local_port: port_from_mib(row.dwLocalPort),
        remote_addr: String::new(),
        remote_port: 0,
        state: "bound",
    }
}

fn udp6_connections_for_pids(pids: &HashSet<u32>, limit: usize) -> Option<Vec<SocketObservation>> {
    let buffer = query_network_table(|buffer, size| unsafe {
        GetExtendedUdpTable(
            buffer,
            size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    })?;
    let rows = (unsafe {
        rows_from_counted_table::<MIB_UDP6ROW_OWNER_PID>(
            &buffer,
            mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
        )
    })?;
    Some(
        rows.iter()
            .filter(|row| pids.contains(&row.dwOwningPid))
            .take(limit)
            .map(udp6_observation)
            .collect(),
    )
}

fn udp6_observation(row: &MIB_UDP6ROW_OWNER_PID) -> SocketObservation {
    SocketObservation {
        pid: row.dwOwningPid,
        protocol: "udp/ipv6",
        local_addr: scoped_ipv6(row.ucLocalAddr, row.dwLocalScopeId),
        local_port: port_from_mib(row.dwLocalPort),
        remote_addr: String::new(),
        remote_port: 0,
        state: "bound",
    }
}

fn ipv4_from_mib(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(addr))
}

fn port_from_mib(port: u32) -> u16 {
    u16::from_be((port & 0xffff) as u16)
}

fn scoped_ipv6(address: [u8; 16], scope_id: u32) -> String {
    let address = Ipv6Addr::from(address);
    if scope_id == 0 {
        address.to_string()
    } else {
        format!("{address}%{scope_id}")
    }
}

fn tcp_state_name(state: u32) -> &'static str {
    match state as i32 {
        value if value == MIB_TCP_STATE_CLOSED.0 => "closed",
        value if value == MIB_TCP_STATE_LISTEN.0 => "listen",
        value if value == MIB_TCP_STATE_SYN_SENT.0 => "syn-sent",
        value if value == MIB_TCP_STATE_SYN_RCVD.0 => "syn-received",
        value if value == MIB_TCP_STATE_ESTAB.0 => "established",
        value if value == MIB_TCP_STATE_FIN_WAIT1.0 => "fin-wait-1",
        value if value == MIB_TCP_STATE_FIN_WAIT2.0 => "fin-wait-2",
        value if value == MIB_TCP_STATE_CLOSE_WAIT.0 => "close-wait",
        value if value == MIB_TCP_STATE_CLOSING.0 => "closing",
        value if value == MIB_TCP_STATE_LAST_ACK.0 => "last-ack",
        value if value == MIB_TCP_STATE_TIME_WAIT.0 => "time-wait",
        value if value == MIB_TCP_STATE_DELETE_TCB.0 => "delete-tcb",
        value if value == MIB_TCP_STATE_RESERVED.0 => "reserved",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::backend::{MappedPath, MappedPathAccess, NetworkPolicy};

    fn minimal_pe(subsystem: u16) -> Vec<u8> {
        let mut image = vec![0u8; 512];
        image[..2].copy_from_slice(b"MZ");
        image[60..64].copy_from_slice(&128u32.to_le_bytes());
        image[128..132].copy_from_slice(b"PE\0\0");
        image[148..150].copy_from_slice(&70u16.to_le_bytes());
        image[152..154].copy_from_slice(&0x020bu16.to_le_bytes());
        image[220..222].copy_from_slice(&subsystem.to_le_bytes());
        image
    }

    #[test]
    fn attribute_list_allocates() {
        let attr_list = unsafe { ProcThreadAttributeList::new(1) }
            .expect("attribute list allocation should succeed");
        assert!(!attr_list.mem.is_null());
        assert!(!attr_list.list.is_invalid());
    }

    #[test]
    fn batch_runtime_capabilities_are_derivable() {
        let batch = build_capability_sids(false, true)
            .expect("batch LPAC capabilities should be available");
        let networked_batch = build_capability_sids(true, true)
            .expect("networked batch LPAC capabilities should be available");
        assert_eq!(batch.len(), 2);
        assert_eq!(networked_batch.len(), 3);
    }

    #[test]
    fn start_in_sandbox_rejects_non_null_terminated_cmdline() {
        let mut cmdline = "notepad.exe".encode_utf16().collect::<Vec<u16>>();
        let caps = SECURITY_CAPABILITIES::default();

        let err = start_with_security_capabilities(&mut cmdline, &caps)
            .expect_err("expected invalid-argument error");
        assert_eq!(err.code(), E_INVALIDARG);
    }

    #[test]
    fn start_in_sandbox_with_default_caps_fails() {
        let mut cmdline = "C:\\Windows\\System32\\notepad.exe\0"
            .encode_utf16()
            .collect::<Vec<u16>>();
        let caps = SECURITY_CAPABILITIES::default();

        let result = start_with_security_capabilities(&mut cmdline, &caps);
        assert!(
            result.is_err(),
            "default SECURITY_CAPABILITIES should not produce a valid appcontainer launch"
        );
    }

    #[test]
    fn batch_launch_streams_every_command_and_adds_a_final_newline() {
        let path =
            std::env::temp_dir().join(format!("foxhole-batch-launch-{}.bat", std::process::id()));
        let source = b"echo \"Hello world\"\r\n\r\nstart calc.exe";
        fs::write(&path, source).expect("failed to create temporary batch target");

        let target = pin_target(path.to_str().expect("temporary path should be UTF-8"))
            .expect("batch target should be pinned");
        let launch = prepare_windows_launch(target, &[]).expect("batch launch should be prepared");

        assert!(
            launch
                .application_name
                .to_ascii_lowercase()
                .ends_with("cmd.exe")
        );
        assert!(launch.command_line.contains("/D"));
        let mut stdin = launch.stdin.expect("batch source should be streamed");
        assert!(stdin.append_final_newline);
        assert!(
            fs::remove_file(&path).is_err(),
            "batch file should remain pinned while the launch exists"
        );
        let mut bytes = Vec::new();
        stdin
            .target
            .file
            .read_to_end(&mut bytes)
            .expect("failed to read pinned batch input");
        assert_eq!(bytes, source);
        drop(stdin);
        fs::remove_file(&path).expect("failed to remove temporary batch target");
    }

    #[test]
    fn gui_and_console_pe_targets_are_accepted_for_private_desktop_launch() {
        let path = std::env::temp_dir().join(format!(
            "foxhole-gui-target-{}-{}.exe",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        fs::write(&path, minimal_pe(2)).expect("create GUI PE target");
        let gui = pin_target(path.to_str().expect("temporary path should be UTF-8"))
            .expect("pin GUI target");
        drop(prepare_windows_launch(gui, &[]).expect("accept GUI PE target"));

        fs::write(&path, minimal_pe(3)).expect("replace with console PE target");
        let console = pin_target(path.to_str().expect("temporary path should be UTF-8"))
            .expect("pin console target");
        drop(prepare_windows_launch(console, &[]).expect("accept console PE target"));
        fs::remove_file(path).expect("remove PE target");
    }

    #[test]
    fn output_capture_is_bounded_while_draining_all_input() {
        let input = vec![b'x'; MAX_CAPTURED_STREAM_BYTES + 32_768];
        let mut cursor = std::io::Cursor::new(input);
        let output = read_output_bounded(&mut cursor).expect("bounded capture should succeed");

        assert_eq!(output.bytes.len(), MAX_CAPTURED_STREAM_BYTES);
        assert_eq!(
            output.bytes_seen,
            (MAX_CAPTURED_STREAM_BYTES + 32_768) as u64
        );
        assert_eq!(cursor.position(), output.bytes_seen);
    }

    #[test]
    fn output_capture_summary_is_structured() {
        let reader = thread::spawn(|| {
            Ok(CapturedOutput {
                bytes: b"kept".to_vec(),
                bytes_seen: 12,
            })
        });
        let mut warnings = Vec::new();
        let (text, summary) = finish_output_reader(reader, "stdout", &mut warnings);

        assert_eq!(text, "kept");
        assert_eq!(summary.bytes_seen, 12);
        assert_eq!(summary.bytes_stored, 4);
        assert!(summary.truncated);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn network_snapshot_allocation_rejects_oversized_tables() {
        let mut calls = 0usize;
        let result = query_network_table(|_, size| {
            calls += 1;
            *size = (MAX_NETWORK_SNAPSHOT_BYTES as u32).saturating_add(1);
            ERROR_INSUFFICIENT_BUFFER_CODE
        });

        assert!(result.is_none());
        assert_eq!(calls, 1);
    }

    #[test]
    fn malformed_network_table_count_is_rejected_without_row_reference() {
        let mut buffer = vec![0usize; 1];
        unsafe {
            std::ptr::write_unaligned(buffer.as_mut_ptr() as *mut u32, u32::MAX);
        }

        let rows = unsafe { rows_from_counted_table::<MIB_TCPROW_OWNER_PID>(&buffer, 4) };
        assert!(rows.is_none());
    }

    #[test]
    fn terminal_escape_neutralizes_controls_and_bidi() {
        let (escaped, truncated) = escape_terminal_text("ok\x1b[31m\r\u{202e}\u{2028}txt", 1_024);

        assert!(!truncated);
        assert_eq!(escaped, "ok\\u{001B}[31m\\u{000D}\\u{202E}\\u{2028}txt");
    }

    #[test]
    fn environment_block_excludes_parent_sentinel() {
        let sentinel = "FOXHOLE_SECRET_SENTINEL";
        // SAFETY: this test restores the process environment before returning and does
        // not run concurrently with another test that reads this sentinel name.
        unsafe {
            std::env::set_var(sentinel, "must-not-cross");
        }
        let block = build_sanitized_environment(
            Path::new(r"C:\private"),
            Path::new(
                r"C:\Users\test\AppData\Local\Packages\foxhole.sandbox.00000000000000000000000000000000\AC",
            ),
        )
        .expect("environment block should be built");
        unsafe {
            std::env::remove_var(sentinel);
        }
        let decoded = String::from_utf16_lossy(&block);

        assert!(!decoded.contains(sentinel));
        assert!(!decoded.contains("must-not-cross"));
        assert!(block.ends_with(&[0, 0]));
        assert!(decoded.contains("SystemRoot="));
        assert!(decoded.contains("APPDATA=C:\\private\0"));
        assert!(decoded.contains("TEMP=C:\\private\0"));
        assert!(decoded.contains("USERPROFILE=C:\\Users\\test\\AppData\\Local\\Packages\\foxhole.sandbox.00000000000000000000000000000000\\AC\0"));
        assert!(decoded.contains("LOCALAPPDATA=C:\\Users\\test\\AppData\\Local\\Packages\\foxhole.sandbox.00000000000000000000000000000000\\AC\0"));
        assert!(!decoded.contains("LOCALAPPDATA=C:\\Users\\test\\AppData\\Local\0"));
    }

    #[test]
    fn disposable_profile_names_are_unique_and_strict() {
        let first = disposable_profile_name().expect("first profile name");
        let second = disposable_profile_name().expect("second profile name");

        assert_ne!(first, second);
        assert!(is_disposable_profile_name(&first));
        assert!(!is_disposable_profile_name("foxhole.sandbox.not-hex"));
    }

    #[test]
    fn pinned_target_denies_write_and_delete_until_release() {
        let path = std::env::temp_dir().join(format!(
            "foxhole-pinned-target-{}-{}.exe",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        fs::write(&path, b"test executable bytes").expect("create target");

        let target = pin_target(path.to_str().expect("temporary path should be UTF-8"))
            .expect("target should be pinned");
        assert_eq!(target.len, 21);
        target
            .verify_identity()
            .expect("identity should remain fixed");
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        drop(target);
        fs::remove_file(path).expect("remove released target");
    }

    #[test]
    fn target_size_ceiling_applies_before_launch() {
        let path = std::env::temp_dir().join(format!(
            "foxhole-oversized-target-{}-{}.exe",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        let file = File::create(&path).expect("create sparse target");
        file.set_len(MAX_SANDBOX_TARGET_BYTES + 1)
            .expect("extend sparse target");
        drop(file);

        assert!(pin_target(path.to_str().expect("temporary path should be UTF-8")).is_err());
        fs::remove_file(path).expect("remove oversized target");
    }

    #[test]
    fn target_with_reparse_parent_is_rejected_when_supported() {
        use std::os::windows::fs::symlink_dir;

        let root = std::env::temp_dir().join(format!(
            "foxhole-reparse-target-{}-{}",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        let real = root.join("real");
        let alias = root.join("alias");
        fs::create_dir(&root).expect("create test root");
        fs::create_dir(&real).expect("create real directory");
        fs::write(real.join("target.exe"), b"test").expect("create target");

        if symlink_dir(&real, &alias).is_ok() {
            assert!(
                pin_target(
                    alias
                        .join("target.exe")
                        .to_str()
                        .expect("temporary path should be UTF-8")
                )
                .is_err()
            );
            fs::remove_dir(&alias).expect("remove directory link");
        }
        fs::remove_file(real.join("target.exe")).expect("remove target");
        fs::remove_dir(real).expect("remove real directory");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn target_path_rejects_streams_and_reserved_components() {
        assert!(absolute_target_path(r"C:\sample.exe:payload").is_err());
        assert!(absolute_target_path(r"C:\NUL.exe").is_err());
    }

    #[test]
    fn hard_link_alias_cannot_mutate_a_pinned_identity() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-hardlink-target-{}-{}",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        let first = root.join("first.exe");
        let second = root.join("second.exe");
        fs::create_dir(&root).expect("create test root");
        fs::write(&first, b"test").expect("create target");
        fs::hard_link(&first, &second).expect("create hard link");

        let target = pin_target(first.to_str().expect("temporary path should be UTF-8"))
            .expect("hard-linked target should be pinned by identity");
        assert!(OpenOptions::new().write(true).open(&second).is_err());
        assert!(
            fs::remove_file(&first).is_err(),
            "the exact CreateProcess pathname must remain pinned"
        );
        fs::remove_file(&second).expect("removing an unpinned alias is harmless");
        target.verify_identity().expect("identity remains pinned");
        drop(target);

        fs::remove_file(first).expect("remove first link");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn target_inside_protected_artifact_root_is_rejected() {
        let root = crate::artifact::artifact_root().expect("artifact root");
        let path = root.join(format!(
            "sandbox-target-{}-{}.exe",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        fs::write(&path, b"test").expect("create artifact target");

        assert!(pin_target(path.to_str().expect("artifact path should be UTF-8")).is_err());

        fs::remove_file(path).expect("remove artifact target");
    }

    #[test]
    fn storage_scanner_rejects_named_data_streams_when_supported() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-storage-stream-{}-{}",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        let file = root.join("entry.bin");
        fs::create_dir(&root).expect("create test root");
        fs::write(&file, b"base").expect("create base stream");
        let stream = PathBuf::from(format!("{}:hidden", file.display()));
        if fs::write(&stream, b"hidden bytes").is_ok() {
            assert!(storage_usage(&root).is_err());
        }

        fs::remove_file(file).expect("remove streamed file");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn storage_scanner_allows_a_live_writer_while_snapshotting() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-storage-writer-{}-{}",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        let path = root.join("active.bin");
        fs::create_dir(&root).expect("create test root");
        let mut writer = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("open active writer");
        writer.write_all(b"active").expect("write active data");
        writer.flush().expect("flush active data");

        assert_eq!(storage_usage(&root).expect("scan active writer"), 6);

        drop(writer);
        fs::remove_file(path).expect("remove active file");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn storage_scanner_fails_closed_on_an_active_directory_writer() {
        const FILE_SHARE_DELETE_VALUE: u32 = 0x0000_0004;
        const GENERIC_WRITE: u32 = 0x4000_0000;

        let root = std::env::temp_dir().join(format!(
            "foxhole-storage-directory-writer-{}-{}",
            std::process::id(),
            disposable_profile_name().expect("random suffix")
        ));
        let child = root.join("mutable");
        fs::create_dir(&root).expect("create test root");
        fs::create_dir(&child).expect("create child directory");
        let writer = OpenOptions::new()
            .access_mode(GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE_VALUE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(&child)
            .expect("open directory writer");

        assert!(
            storage_usage(&root).is_err(),
            "the scanner must reject a handle that could mutate a directory into a reparse point"
        );
        drop(writer);
        assert_eq!(storage_usage(&root).expect("scan stable tree"), 0);

        fs::remove_dir(child).expect("remove child directory");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn backend_state_machine_rejects_out_of_order_operations() {
        let request = SandboxRequest::restricted(std::env::current_exe().unwrap());
        let mut backend = RestrictedProcessBackend::default();
        assert!(backend.execute(&request).is_err());
        assert!(backend.cleanup().is_ok());
        assert_eq!(backend.state, BackendState::Finished);

        let mut invalid = RestrictedProcessBackend::default();
        let mut invalid_request = request.clone();
        invalid_request.timeout_secs = 0;
        assert!(invalid.prepare(&invalid_request).is_err());
        assert_eq!(invalid.state, BackendState::Failed);
        assert!(invalid.cleanup().is_ok());

        let mut missing_plan = RestrictedProcessBackend {
            state: BackendState::Ready,
            ..Default::default()
        };
        assert!(missing_plan.execute(&request).is_err());
    }

    #[test]
    fn dry_run_backend_covers_prepare_execute_cleanup_and_reentry_failures() {
        let mut request = SandboxRequest::restricted(std::env::current_exe().unwrap());
        request.dry_run = true;
        request.mitigation_profile = MitigationProfile::Maximum;
        let mut backend = RestrictedProcessBackend::default();
        backend.prepare(&request).unwrap();
        assert_eq!(backend.state, BackendState::Ready);
        assert!(backend.prepare(&request).is_err());
        let result = backend.execute(&request).unwrap();
        assert_eq!(result.pid, 0);
        assert_eq!(result.integrity_level, "untrusted");
        assert!(backend.execute(&request).is_err());
        assert!(backend.cleanup().is_ok());
        assert!(backend.cleanup().is_ok());
    }

    #[test]
    fn live_non_enforcing_network_modes_launch_a_restricted_process() {
        for (policy, profile) in [
            (NetworkPolicy::CaptureOnly, MitigationProfile::Compatible),
            (NetworkPolicy::AllowInternet, MitigationProfile::Strict),
        ] {
            let mut request = SandboxRequest::restricted(std::env::current_exe().unwrap());
            request.arguments = vec!["--help".to_string()];
            request.timeout_secs = 15;
            request.network_policy = policy;
            request.mitigation_profile = profile;
            let run = start_with_request(request).expect("live sandbox launch");
            assert!(run.result.exit_code.is_some());
            assert!(!run.result.timed_out);
            assert!(run.result.pid > 0);
            assert!(run.result.cleanup.attempted);
            assert!(run.result.cleanup.success);
        }
    }

    #[test]
    fn enforcing_network_modes_either_run_or_fail_closed_at_wfp() {
        for policy in [
            NetworkPolicy::DenyAll,
            NetworkPolicy::AllowList(vec!["127.0.0.1/32".parse().unwrap()]),
        ] {
            let mut request = SandboxRequest::restricted(std::env::current_exe().unwrap());
            request.arguments = vec!["--version".to_string()];
            request.timeout_secs = 15;
            request.network_policy = policy;
            match start_with_request(request) {
                Ok(run) => assert!(run.result.exit_code.is_some()),
                Err(error) => {
                    assert_eq!(error.stage, "network_filters");
                    assert!(
                        error.to_string().contains("WFP") || error.to_string().contains("status")
                    );
                }
            }
        }
    }

    #[test]
    fn launch_target_and_path_helpers_reject_malformed_inputs() {
        assert!(is_batch_target(Path::new("sample.BAT")));
        assert!(is_batch_target(Path::new("sample.cmd")));
        assert!(!is_batch_target(Path::new("sample.exe")));
        assert!(!is_batch_target(Path::new("sample")));

        for bytes in [vec![], b"not-a-pe".to_vec(), b"MZ".to_vec()] {
            let path = std::env::temp_dir().join(format!(
                "foxhole-malformed-pe-{}-{}.exe",
                std::process::id(),
                disposable_profile_name().unwrap()
            ));
            fs::write(&path, bytes).unwrap();
            let mut target = pin_target(path.to_str().unwrap()).unwrap();
            assert!(ensure_supported_pe_target(&mut target).is_err());
            drop(target);
            fs::remove_file(path).unwrap();
        }

        assert!(absolute_target_path(r"C:\").is_err());
        assert!(absolute_target_path(r"\\server\share\sample.exe").is_err());
        assert!(reject_nonlocal_path(Path::new(r"\\server\share")).is_err());
        assert!(local_drive_root(Path::new("relative")).is_err());
    }

    #[test]
    fn terminal_capture_helpers_cover_truncation_and_reader_failures() {
        let mut value = "ééé".to_string();
        truncate_string_at_boundary(&mut value, 3);
        assert_eq!(value, "é");
        assert_eq!(terminal_safe_text("a\n\u{202e}"), "a\\u{000A}\\u{202E}");
        let (escaped, truncated) = escape_terminal_text("abcdef", 3);
        assert_eq!(escaped, "abc");
        assert!(truncated);
        assert!(is_unicode_format_control('\u{200e}'));
        assert!(!is_unicode_format_control('a'));
        assert_eq!(empty_capture_summary().bytes_seen, 0);
        log_captured_output("stdout", "line one\nline two");

        let reader = thread::spawn(|| -> std::io::Result<CapturedOutput> {
            Err(std::io::Error::other("reader failed"))
        });
        let mut warnings = Vec::new();
        let (_, summary) = finish_output_reader(reader, "stderr", &mut warnings);
        assert_eq!(summary.bytes_stored, 0);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("reader failed"))
        );

        let reader =
            thread::spawn(|| -> std::io::Result<CapturedOutput> { panic!("reader panic") });
        let _ = finish_output_reader(reader, "stdout", &mut warnings);
        assert!(warnings.iter().any(|warning| warning.contains("panicked")));
    }

    #[test]
    fn network_and_process_observation_helpers_cover_edge_values() {
        assert_eq!(
            ipv4_from_mib(u32::from_ne_bytes([127, 0, 0, 1])),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(port_from_mib(u16::to_be(443) as u32), 443);
        assert_eq!(scoped_ipv6(Ipv6Addr::LOCALHOST.octets(), 0), "::1");
        assert_eq!(scoped_ipv6(Ipv6Addr::LOCALHOST.octets(), 7), "::1%7");
        assert_eq!(utf16_array_to_string(&[65, 66, 0, 67]), "AB");
        assert!(elapsed_ms(Instant::now()) <= 1_000);

        for (state, name) in [
            (MIB_TCP_STATE_CLOSED.0, "closed"),
            (MIB_TCP_STATE_LISTEN.0, "listen"),
            (MIB_TCP_STATE_SYN_SENT.0, "syn-sent"),
            (MIB_TCP_STATE_SYN_RCVD.0, "syn-received"),
            (MIB_TCP_STATE_ESTAB.0, "established"),
            (MIB_TCP_STATE_FIN_WAIT1.0, "fin-wait-1"),
            (MIB_TCP_STATE_FIN_WAIT2.0, "fin-wait-2"),
            (MIB_TCP_STATE_CLOSE_WAIT.0, "close-wait"),
            (MIB_TCP_STATE_CLOSING.0, "closing"),
            (MIB_TCP_STATE_LAST_ACK.0, "last-ack"),
            (MIB_TCP_STATE_TIME_WAIT.0, "time-wait"),
            (MIB_TCP_STATE_DELETE_TCB.0, "delete-tcb"),
            (MIB_TCP_STATE_RESERVED.0, "reserved"),
        ] {
            assert_eq!(tcp_state_name(state as u32), name);
        }
        assert_eq!(tcp_state_name(u32::MAX), "unknown");

        let processes = process_tree(std::process::id());
        assert!(
            processes
                .iter()
                .any(|process| process.pid == std::process::id())
        );
        let empty = HashSet::new();
        let (connections, _, _) = network_connections_for_pids(&empty);
        assert!(connections.is_empty());
    }

    #[test]
    fn counted_sid_and_network_table_validation_fail_closed() {
        assert!(counted_sid_attributes(&[]).is_err());
        let mut tiny = vec![0usize; 1];
        unsafe {
            std::ptr::write_unaligned(tiny.as_mut_ptr().cast::<u32>(), 1);
        }
        assert!(counted_sid_attributes(&tiny).is_err());

        let result = query_network_table(|_, _| 5);
        assert!(result.is_none());
        let mut calls = 0;
        let result = query_network_table(|buffer, size| {
            calls += 1;
            if buffer.is_none() {
                *size = 16;
                ERROR_INSUFFICIENT_BUFFER_CODE
            } else {
                0
            }
        });
        assert!(result.is_some());
        assert_eq!(calls, 2);
    }

    #[test]
    fn live_batch_launch_and_timeout_paths_are_covered() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-live-batch-{}-{}",
            std::process::id(),
            disposable_profile_name().unwrap()
        ));
        fs::create_dir(&root).unwrap();

        let success = root.join("success.bat");
        fs::write(&success, b"@echo batch-coverage\r\n").unwrap();
        let mut request = SandboxRequest::restricted(&success);
        request.network_policy = NetworkPolicy::CaptureOnly;
        request.timeout_secs = 10;
        let run = start_with_request(request).expect("batch launch");
        assert_eq!(run.result.exit_code, Some(0));
        assert!(run.result.stdout.contains("batch-coverage"));

        let timeout_target = root.join("timeout.bat");
        fs::write(
            &timeout_target,
            b"@for /L %i in (1,1,2147483647) do @rem\r\n",
        )
        .unwrap();
        let mut request = SandboxRequest::restricted(&timeout_target);
        request.network_policy = NetworkPolicy::CaptureOnly;
        request.timeout_secs = 1;
        let run = start_with_request(request).expect("timed batch launch");
        assert!(run.result.timed_out);

        fs::remove_file(success).unwrap();
        fs::remove_file(timeout_target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn live_launch_stages_read_only_and_read_write_mappings() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-live-mapping-{}-{}",
            std::process::id(),
            disposable_profile_name().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let read_only = root.join("read-only.txt");
        let read_write = root.join("read-write");
        fs::write(&read_only, b"read only").unwrap();
        fs::create_dir(&read_write).unwrap();
        fs::write(read_write.join("nested.txt"), b"nested").unwrap();

        let mut request = SandboxRequest::restricted(std::env::current_exe().unwrap());
        request.arguments = vec!["--help".into()];
        request.network_policy = NetworkPolicy::CaptureOnly;
        request.timeout_secs = 15;
        request.mapped_paths = vec![
            MappedPath {
                host_path: read_only.clone(),
                guest_name: "ro".into(),
                access: MappedPathAccess::ReadOnly,
            },
            MappedPath {
                host_path: read_write.clone(),
                guest_name: "rw".into(),
                access: MappedPathAccess::ReadWrite,
            },
        ];
        let run = start_with_request(request).expect("mapped launch");
        assert_eq!(run.result.mapped_paths.len(), 2);
        assert!(run.result.exit_code.is_some());

        fs::remove_file(read_only).unwrap();
        fs::remove_dir_all(read_write).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn capability_sid_and_trusted_windows_path_helpers_succeed() {
        let none = build_capability_sids(false, false).unwrap();
        assert!(none.is_empty());
        let mut internet = build_capability_sids(true, false).unwrap();
        assert_eq!(internet.len(), 1);
        let attributes = sid_attributes(&mut internet);
        assert_eq!(attributes.len(), 1);
        let sid_text = sid_to_string_text(internet[0].as_psid()).unwrap();
        assert!(sid_text.starts_with("S-1-"));
        assert!(sid_to_string(PSID::default()).is_err());

        let paths = trusted_windows_paths().unwrap();
        assert!(paths.windows.is_absolute());
        assert!(paths.system.is_absolute());
        assert!(paths.system.starts_with(&paths.windows));
    }

    #[test]
    fn job_storage_and_token_query_helpers_cover_success_and_failure() {
        let job = create_limited_job(1, &ResourceLimits::default()).expect("limited job");
        assert!(!job.get().is_invalid());
        drop(job);

        let root = std::env::temp_dir().join(format!(
            "foxhole-storage-limit-{}-{}",
            std::process::id(),
            disposable_profile_name().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let oversized = File::create(root.join("oversized.bin")).unwrap();
        oversized.set_len(MAX_STORAGE_BYTES + 1).unwrap();
        drop(oversized);
        assert!(storage_limit_violation(&root).unwrap().contains("exceeded"));
        assert!(
            storage_limit_violation(&root.join("missing"))
                .unwrap()
                .contains("validation failed")
        );
        fs::remove_dir_all(root).unwrap();

        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(Threading::GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .unwrap();
        let token = WinHandle::new(token);
        let _ = token_u32(token.get(), TokenIsAppContainer).unwrap();
        let groups = token_information(token.get(), TokenGroups).unwrap();
        assert!(!groups.is_empty());
        assert!(token_information(HANDLE::default(), TokenGroups).is_err());
        assert!(token_u32(HANDLE::default(), TokenIsAppContainer).is_err());
        let _ = token_has_enabled_well_known_group(token.get(), WinBuiltinAnyPackageSid).unwrap();
    }

    #[test]
    fn socket_observation_builders_and_snapshot_limits_are_covered() {
        let tcp6 = MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: u16::to_be(80) as u32,
            ucRemoteAddr: Ipv6Addr::LOCALHOST.octets(),
            dwRemoteScopeId: 2,
            dwRemotePort: u16::to_be(443) as u32,
            dwState: MIB_TCP_STATE_ESTAB.0 as u32,
            dwOwningPid: 42,
        };
        let observation = tcp6_observation(&tcp6);
        assert_eq!(observation.pid, 42);
        assert_eq!(observation.remote_port, 443);

        let udp4 = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: u16::to_be(53) as u32,
            dwOwningPid: 7,
        };
        assert_eq!(udp4_observation(&udp4).local_port, 53);
        let udp6 = MIB_UDP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalScopeId: 3,
            dwLocalPort: u16::to_be(5353) as u32,
            dwOwningPid: 8,
        };
        assert_eq!(udp6_observation(&udp6).local_addr, "::1%3");

        let sample = SocketObservation {
            pid: 1,
            protocol: "tcp/ipv4",
            local_addr: "127.0.0.1".into(),
            local_port: 1,
            remote_addr: String::new(),
            remote_port: 0,
            state: "closed",
        };
        let mut output = vec![sample.clone(); MAX_NETWORK_ROWS_PER_SNAPSHOT - 1];
        let mut truncated = false;
        append_network_rows(&mut output, &mut truncated, vec![sample.clone(), sample]);
        assert_eq!(output.len(), MAX_NETWORK_ROWS_PER_SNAPSHOT);
        assert!(truncated);

        let pids = HashSet::from([std::process::id()]);
        assert!(tcp4_connections_for_pids(&pids, 0).is_some());
        assert!(tcp6_connections_for_pids(&pids, 0).is_some());
        assert!(udp4_connections_for_pids(&pids, 0).is_some());
        assert!(udp6_connections_for_pids(&pids, 0).is_some());
    }

    #[test]
    fn every_pe_header_and_batch_launch_security_rejection_is_explicit() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-launch-validation-{}-{}",
            std::process::id(),
            disposable_profile_name().unwrap()
        ));
        fs::create_dir(&root).unwrap();

        let invalid_images = [
            {
                let mut image = minimal_pe(3);
                image[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
                image
            },
            {
                let mut image = minimal_pe(3);
                image[128..132].copy_from_slice(b"BAD!");
                image
            },
            {
                let mut image = minimal_pe(3);
                image[148..150].copy_from_slice(&0u16.to_le_bytes());
                image
            },
            {
                let mut image = minimal_pe(3);
                image[152..154].copy_from_slice(&0u16.to_le_bytes());
                image
            },
            minimal_pe(99),
        ];
        for (index, image) in invalid_images.into_iter().enumerate() {
            let path = root.join(format!("invalid-{index}.exe"));
            fs::write(&path, image).unwrap();
            let mut target = pin_target(path.to_str().unwrap()).unwrap();
            assert!(ensure_supported_pe_target(&mut target).is_err());
            drop(target);
            fs::remove_file(path).unwrap();
        }

        let empty_batch = root.join("empty.bat");
        fs::write(&empty_batch, []).unwrap();
        let launch =
            prepare_windows_launch(pin_target(empty_batch.to_str().unwrap()).unwrap(), &[])
                .unwrap();
        assert!(launch.stdin.unwrap().append_final_newline);

        let argument_batch = root.join("argument.bat");
        fs::write(&argument_batch, b"@echo safe\r\n").unwrap();
        assert!(
            prepare_windows_launch(
                pin_target(argument_batch.to_str().unwrap()).unwrap(),
                &["forbidden".into()]
            )
            .is_err()
        );

        let oversized_batch = root.join("oversized.bat");
        let oversized = File::create(&oversized_batch).unwrap();
        oversized.set_len(MAX_BATCH_INPUT_BYTES + 1).unwrap();
        drop(oversized);
        assert!(
            prepare_windows_launch(pin_target(oversized_batch.to_str().unwrap()).unwrap(), &[])
                .is_err()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_pinning_and_directory_query_failure_paths_are_explicit() {
        unsafe fn zero_directory(_: Option<&mut [u16]>) -> u32 {
            0
        }
        unsafe fn relative_directory(buffer: Option<&mut [u16]>) -> u32 {
            let value = "relative".encode_utf16().collect::<Vec<_>>();
            if let Some(buffer) = buffer {
                buffer[..value.len()].copy_from_slice(&value);
            }
            value.len() as u32
        }
        unsafe fn resized_directory(buffer: Option<&mut [u16]>) -> u32 {
            let value = r"C:\Windows".encode_utf16().collect::<Vec<_>>();
            let Some(buffer) = buffer else {
                return 600;
            };
            if buffer.len() <= 512 {
                return 600;
            }
            buffer[..value.len()].copy_from_slice(&value);
            value.len() as u32
        }

        assert!(query_windows_directory(zero_directory, "test directory").is_err());
        assert!(query_windows_directory(relative_directory, "test directory").is_err());
        assert_eq!(
            query_windows_directory(resized_directory, "test directory").unwrap(),
            PathBuf::from(r"C:\Windows")
        );

        assert!(absolute_target_path(r"folder\..\target.exe").is_err());
        let current = std::env::current_exe().unwrap();
        let dotted = format!(r".\{}", current.file_name().unwrap().to_string_lossy());
        assert!(absolute_target_path(&dotted).unwrap().is_absolute());

        let root = std::env::temp_dir().join(format!(
            "foxhole-pinning-errors-{}-{}",
            std::process::id(),
            disposable_profile_name().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let file_path = root.join("file.bin");
        fs::write(&file_path, b"data").unwrap();
        let file = File::open(&file_path).unwrap();
        assert!(ensure_plain_directory_handle(&file, &file_path).is_err());
        let directory = open_pinned_directory(&root).unwrap();
        assert!(ensure_plain_disk_file(&directory, &root).is_err());
        assert!(verify_final_handle_path(&file, &root.join("different.bin")).is_err());
        assert!(ensure_directory_not_reparse(&file_path).is_err());
        assert_eq!(unsafe { pwstr_to_string(PWSTR::null()) }, "");
        drop(file);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn marker_scavenging_guards_and_network_query_retries_are_covered() {
        let (directory, _pins) = profile_marker_dir().unwrap();
        let fake_name = format!("{APP_CONTAINER_NAME_PREFIX}{}", "a".repeat(32));
        let marker = directory.join(fake_name);
        fs::write(&marker, b"stale").unwrap();
        scavenge_stale_app_container_profiles();
        if marker.exists() {
            fs::remove_file(marker).unwrap();
        }

        let mut retries = 0;
        assert!(
            query_network_table(|buffer, size| {
                retries += 1;
                *size = 16;
                if buffer.is_none() || retries < 5 {
                    ERROR_INSUFFICIENT_BUFFER_CODE
                } else {
                    0
                }
            })
            .is_none()
        );
        assert_eq!(retries, 4);

        let mut calls = 0;
        assert!(
            query_network_table(|buffer, size| {
                calls += 1;
                *size = 16;
                if buffer.is_none() {
                    ERROR_INSUFFICIENT_BUFFER_CODE
                } else {
                    5
                }
            })
            .is_none()
        );
        assert_eq!(calls, 2);

        let profile = AppContainerProfile {
            sid: PSID::default(),
            name: "already-deleted".into(),
            name_wide: vec![0],
            marker: None,
            marker_path: PathBuf::new(),
            _marker_directory_pins: Vec::new(),
            deleted: true,
        };
        let mut profile = profile;
        profile.delete().unwrap();
    }

    #[test]
    fn real_socket_tables_and_monitor_capture_current_process_activity() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

        let pids = HashSet::from([std::process::id()]);
        let tcp = tcp4_connections_for_pids(&pids, 32).unwrap();
        assert!(tcp.iter().any(|row| row.pid == std::process::id()));
        let udp_rows = udp4_connections_for_pids(&pids, 32).unwrap();
        assert!(udp_rows.iter().any(|row| row.pid == std::process::id()));

        let stop = Arc::new(AtomicBool::new(true));
        let monitor = monitor_activity(std::process::id(), stop, Instant::now());
        assert!(
            monitor
                .processes
                .iter()
                .any(|process| process.pid == std::process::id())
        );
        assert!(
            monitor
                .network_connections
                .iter()
                .any(|connection| connection.pid == std::process::id())
        );

        drop((client, server, listener, udp));
    }

    #[test]
    fn prepared_live_request_mismatch_and_armed_guard_fail_safely() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "exit 0"])
            .spawn()
            .unwrap();
        let guard = ProcessTerminationGuard::new(HANDLE(child.as_raw_handle()));
        child.wait().unwrap();
        drop(guard);

        let mut request = SandboxRequest::restricted(std::env::current_exe().unwrap());
        request.network_policy = NetworkPolicy::CaptureOnly;
        request.timeout_secs = 15;
        let mut backend = RestrictedProcessBackend::default();
        backend.prepare(&request).unwrap();
        let mut different = request.clone();
        different.arguments.push("different".into());
        let error = backend.execute(&different).unwrap_err();
        assert_eq!(error.stage, "execute");
        backend.cleanup().unwrap();
    }

    #[test]
    fn storage_stream_metadata_parser_rejects_every_malformed_shape() {
        fn buffer_with_stream(name: &str, next: u32, minimum_bytes: usize) -> Vec<usize> {
            let header = mem::offset_of!(FILE_STREAM_INFO, StreamName);
            let name = name.encode_utf16().collect::<Vec<_>>();
            let bytes = minimum_bytes.max(header + name.len() * mem::size_of::<u16>());
            let mut buffer = vec![0usize; bytes.div_ceil(mem::size_of::<usize>())];
            unsafe {
                let raw = buffer.as_mut_ptr().cast::<u8>();
                std::ptr::write_unaligned(raw.cast::<u32>(), next);
                std::ptr::write_unaligned(
                    raw.add(4).cast::<u32>(),
                    (name.len() * mem::size_of::<u16>()) as u32,
                );
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    raw.add(header).cast::<u16>(),
                    name.len(),
                );
            }
            buffer
        }

        let path = Path::new("storage.bin");
        assert!(validate_storage_stream_buffer(&[0usize], path).is_err());

        let mut invalid_length = vec![0usize; 8];
        unsafe {
            std::ptr::write_unaligned(
                invalid_length
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(4)
                    .cast::<u32>(),
                3,
            );
        }
        assert!(validate_storage_stream_buffer(&invalid_length, path).is_err());

        let mut truncated_name = vec![0usize; 8];
        unsafe {
            std::ptr::write_unaligned(
                truncated_name
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(4)
                    .cast::<u32>(),
                1_000,
            );
        }
        assert!(validate_storage_stream_buffer(&truncated_name, path).is_err());
        assert!(
            validate_storage_stream_buffer(&buffer_with_stream(":evil:$DATA", 0, 64), path)
                .is_err()
        );
        assert!(
            validate_storage_stream_buffer(&buffer_with_stream("::$DATA", 1, 64), path).is_err()
        );
        assert!(
            validate_storage_stream_buffer(&buffer_with_stream("::$DATA", 0, 64), path).is_ok()
        );

        let header = mem::offset_of!(FILE_STREAM_INFO, StreamName);
        let name = "::$DATA".encode_utf16().collect::<Vec<_>>();
        let entry_bytes = header + name.len() * mem::size_of::<u16>();
        let stride = entry_bytes.next_multiple_of(mem::align_of::<FILE_STREAM_INFO>());
        let mut many = vec![
            0usize;
            (stride * (MAX_STREAMS_PER_STORAGE_ENTRY + 1))
                .div_ceil(mem::size_of::<usize>())
        ];
        for index in 0..MAX_STREAMS_PER_STORAGE_ENTRY {
            unsafe {
                let raw = many.as_mut_ptr().cast::<u8>().add(index * stride);
                std::ptr::write_unaligned(raw.cast::<u32>(), stride as u32);
                std::ptr::write_unaligned(
                    raw.add(4).cast::<u32>(),
                    (name.len() * mem::size_of::<u16>()) as u32,
                );
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    raw.add(header).cast::<u16>(),
                    name.len(),
                );
            }
        }
        assert!(validate_storage_stream_buffer(&many, path).is_err());
    }

    #[test]
    fn writer_wait_and_storage_error_helpers_are_reported() {
        let mut warnings = Vec::new();
        finish_input_writer(
            thread::spawn(|| Err(std::io::Error::other("injected writer failure"))),
            &mut warnings,
        );
        finish_input_writer(
            thread::spawn(|| -> std::io::Result<()> { panic!("injected writer panic") }),
            &mut warnings,
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("writer failure"))
        );
        assert!(warnings.iter().any(|warning| warning.contains("panicked")));

        assert!(
            wait_for_process(
                HANDLE::default(),
                HANDLE::default(),
                1,
                &std::env::temp_dir()
            )
            .is_err()
        );

        let root = std::env::temp_dir().join(format!(
            "foxhole-storage-errors-{}-{}",
            std::process::id(),
            disposable_profile_name().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let file_path = root.join("not-a-root.bin");
        fs::write(&file_path, b"file").unwrap();
        assert!(storage_usage(&file_path).is_err());
        let file = File::open(&file_path).unwrap();
        assert!(verify_storage_handle_path(&file, &root.join("changed.bin")).is_err());
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }
}
