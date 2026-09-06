use crate::filesystem::GuestWorkspace;
use crate::runner::{AgentError, AgentResult};
use foxhole::sandbox::hyperv::guest_protocol::{
    GuestExecutionProfile, GuestMitigationProfile, GuestNetworkPolicy, GuestRunRequest,
};
use foxhole::sandbox::sandbox_utils::{
    build_windows_command_line, to_wide_null, win32_path_string,
};
use foxhole::structs::{CleanupStatus, ProcessObservation, SandboxRunResult, StreamCaptureSummary};
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::Read;
use std::mem;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserExists, NERR_UserNotFound, NetUserAdd, NetUserDel,
    UF_DONT_EXPIRE_PASSWD, UF_NORMAL_ACCOUNT, UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_ACCOUNT_FLAGS,
    USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateTokenEx, GetTokenInformation,
    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW, PSID, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SecurityImpersonation, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN, TOKEN_QUERY, TOKEN_USER, TokenElevationType,
    TokenElevationTypeFull, TokenImpersonation, TokenLinkedToken, TokenPrimary, TokenUser,
    WinBuiltinAdministratorsSid,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, OpenProcessToken,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{LoadUserProfileW, PROFILEINFOW, UnloadUserProfile};
use windows::core::{BOOL, PCWSTR, PWSTR};

const MAX_CAPTURED_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACCOUNT_SECRET_BYTES: u64 = 1024;
const NORMAL_USERNAME_ENV: &str = "FOXHOLE_GUEST_NORMAL_USERNAME";
const NORMAL_PASSWORD_FILE_ENV: &str = "FOXHOLE_GUEST_NORMAL_PASSWORD_FILE";
const TEMPORARY_ACCOUNT_CREATE_ATTEMPTS: usize = 8;

pub fn execute(
    request: &GuestRunRequest,
    workspace: &GuestWorkspace,
) -> AgentResult<SandboxRunResult> {
    if request.execution_profile == GuestExecutionProfile::Restricted {
        return Err(AgentError::new(
            "execution",
            "invalid_native_profile",
            "the restricted profile must use the AppContainer guest runner",
        ));
    }
    if request.mitigation_profile != GuestMitigationProfile::Compatible {
        return Err(AgentError::new(
            "execution",
            "unsupported_native_mitigation",
            "normal and admin profiles currently require the compatible mitigation profile",
        ));
    }

    let started = Instant::now();
    let mut identity = launch_identity(request.execution_profile)?;
    if let Some(sid) = identity.normal_user_sid.as_deref() {
        grant_normal_user_workspace_access(workspace, sid)?;
    }

    let launch = build_launch(&workspace.target, &request.arguments)?;
    let environment = build_environment(&workspace.work, identity.username.as_deref())?;
    let mut stdout_pipe = output_pipe()?;
    let mut stderr_pipe = output_pipe()?;
    let mut stdin_pipe = input_pipe()?;
    let start_info = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: stdout_pipe.writer.get(),
        hStdError: stderr_pipe.writer.get(),
        hStdInput: stdin_pipe.reader.get(),
        ..Default::default()
    };

    let application = to_wide_null(&launch.application);
    let mut command_line = to_wide_null(&launch.command_line);
    let working_directory = to_wide_null(&win32_path_string(&workspace.work));
    let mut process_info = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessAsUserW(
            Some(identity.token.get()),
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
            Some(environment.as_ptr().cast::<c_void>()),
            PCWSTR(working_directory.as_ptr()),
            &start_info,
            &mut process_info,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "execution",
            "create_native_process",
            "create the guest-native target process",
            error,
        )
    })?;

    let process = OwnedHandle::new(process_info.hProcess);
    let thread_handle = OwnedHandle::new(process_info.hThread);
    let job = create_job(request)?;
    unsafe { AssignProcessToJobObject(job.get(), process.get()) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "assign_native_job",
            "assign the guest-native process to its cleanup job",
            error,
        )
    })?;

    stdout_pipe.writer.close();
    stderr_pipe.writer.close();
    stdin_pipe.reader.close();
    stdin_pipe.writer.close();
    let stdout_reader = spawn_reader(stdout_pipe.reader);
    let stderr_reader = spawn_reader(stderr_pipe.reader);

    let resume = unsafe { ResumeThread(thread_handle.get()) };
    if resume == u32::MAX {
        let _ = unsafe { TerminateJobObject(job.get(), 1) };
        return Err(AgentError::with_source(
            "execution",
            "resume_native_process",
            "resume the guest-native target process",
            windows::core::Error::from_thread(),
        ));
    }

    let timed_out = wait_bounded(process.get(), job.get(), request.timeout_seconds)?;
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process.get(), &mut exit_code) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "query_native_exit_code",
            "query the guest-native target exit code",
            error,
        )
    })?;

    // Kill-on-close terminates any descendants that survived the root process,
    // then releases inherited output handles so both readers reach EOF.
    drop(job);
    let mut warnings = Vec::new();
    let (stdout, stdout_capture) = finish_reader(stdout_reader, "stdout", &mut warnings);
    let (stderr, stderr_capture) = finish_reader(stderr_reader, "stderr", &mut warnings);

    let mut result = SandboxRunResult {
        backend: "guest_native".to_string(),
        network_policy: network_policy_name(request.network_policy).to_string(),
        integrity_level: identity.integrity_level.to_string(),
        mitigation_profile: "compatible".to_string(),
        pid: process_info.dwProcessId,
        exit_code: Some(exit_code),
        timed_out,
        working_dir: Some(workspace.work.display().to_string()),
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        stdout,
        stderr,
        stdout_capture,
        stderr_capture,
        processes: vec![ProcessObservation {
            pid: process_info.dwProcessId,
            parent_pid: unsafe { GetCurrentProcessId() },
            image: workspace
                .target
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "target".to_string()),
            observed_at_ms: 0,
        }],
        network_connections: Vec::new(),
        file_observations: Vec::new(),
        registry_observations: Vec::new(),
        mapped_paths: Vec::new(),
        monitor_warnings: warnings,
        cleanup: CleanupStatus {
            attempted: true,
            success: true,
            warnings: Vec::new(),
            leftover_resources: Vec::new(),
        },
    };
    if let Some(warning) = identity.cleanup_temporary_account() {
        result.cleanup.success = false;
        result.cleanup.warnings.push(warning);
    }
    Ok(result)
}

struct LaunchIdentity {
    token: OwnedHandle,
    _loaded_profile: Option<LoadedUserProfile>,
    temporary_account: Option<TemporaryLocalAccount>,
    integrity_level: &'static str,
    username: Option<String>,
    normal_user_sid: Option<String>,
}

fn launch_identity(profile: GuestExecutionProfile) -> AgentResult<LaunchIdentity> {
    match profile {
        GuestExecutionProfile::Restricted => unreachable!("validated by caller"),
        GuestExecutionProfile::Admin => {
            let mut current = HANDLE::default();
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                    &mut current,
                )
            }
            .map_err(|error| {
                AgentError::with_source(
                    "execution",
                    "open_admin_token",
                    "open the guest-agent service token",
                    error,
                )
            })?;
            let current = OwnedHandle::new(current);
            let sid = token_user_sid(current.get())?;
            if sid != "S-1-5-18" {
                return Err(AgentError::new(
                    "execution",
                    "admin_profile_requires_system_service",
                    "admin profile requires the guest-agent service to run as LocalSystem",
                ));
            }
            Ok(LaunchIdentity {
                token: duplicate_primary_token(current.get())?,
                _loaded_profile: None,
                temporary_account: None,
                integrity_level: "system",
                username: None,
                normal_user_sid: None,
            })
        }
        GuestExecutionProfile::Normal => normal_identity(),
    }
}

fn normal_identity() -> AgentResult<LaunchIdentity> {
    let username = std::env::var(NORMAL_USERNAME_ENV);
    let password_path = std::env::var_os(NORMAL_PASSWORD_FILE_ENV);
    match (username, password_path) {
        (Err(std::env::VarError::NotPresent), None) => temporary_normal_identity(),
        (Ok(username), Some(password_path)) => configured_normal_identity(username, password_path),
        (Err(std::env::VarError::NotPresent), Some(_)) => Err(AgentError::new(
            "configuration",
            "missing_normal_username",
            format!("{NORMAL_PASSWORD_FILE_ENV} is configured without {NORMAL_USERNAME_ENV}"),
        )),
        (Ok(_), None) => Err(AgentError::new(
            "configuration",
            "missing_normal_password_file",
            format!("{NORMAL_USERNAME_ENV} is configured without {NORMAL_PASSWORD_FILE_ENV}"),
        )),
        (Err(std::env::VarError::NotUnicode(_)), _) => Err(AgentError::new(
            "configuration",
            "invalid_normal_username",
            format!("{NORMAL_USERNAME_ENV} is not valid Unicode"),
        )),
    }
}

fn configured_normal_identity(
    username: String,
    password_path: std::ffi::OsString,
) -> AgentResult<LaunchIdentity> {
    if username.is_empty() || username.len() > 128 || username.contains(['\0', '\\', '/', ':']) {
        return Err(AgentError::new(
            "configuration",
            "invalid_normal_username",
            "normal-profile username is empty or contains an unsafe character",
        ));
    }
    let mut password = read_secret(&PathBuf::from(password_path))?;
    identity_from_credentials(username, &mut password, None)
}

fn temporary_normal_identity() -> AgentResult<LaunchIdentity> {
    let (account, mut password) = TemporaryLocalAccount::create()?;
    identity_from_credentials(account.username.clone(), &mut password, Some(account))
}

fn identity_from_credentials(
    username: String,
    password: &mut str,
    temporary_account: Option<TemporaryLocalAccount>,
) -> AgentResult<LaunchIdentity> {
    let mut username_wide = to_wide_null(&username);
    let domain_wide = to_wide_null(".");
    let mut password_wide = to_wide_null(password);
    let mut logged_on = HANDLE::default();
    let result = unsafe {
        LogonUserW(
            PCWSTR(username_wide.as_ptr()),
            PCWSTR(domain_wide.as_ptr()),
            PCWSTR(password_wide.as_ptr()),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut logged_on,
        )
    };
    password_wide.fill(0);
    unsafe { password.as_bytes_mut().fill(0) };
    result.map_err(|error| {
        AgentError::with_source(
            "execution",
            "logon_normal_user",
            "log on the configured guest standard account",
            error,
        )
    })?;
    let logged_on = OwnedHandle::new(logged_on);
    let loaded_profile = load_user_profile(logged_on, &mut username_wide)?;
    let linked = linked_standard_token(loaded_profile.token.get())?;
    let source = linked
        .as_ref()
        .map(OwnedHandle::get)
        .unwrap_or_else(|| loaded_profile.token.get());
    let token = duplicate_primary_token(source)?;
    if token_has_enabled_admin_group(token.get())? {
        return Err(AgentError::new(
            "execution",
            "normal_profile_is_elevated",
            "the configured normal account did not provide a filtered standard-user token; use admin profile or enable UAC token filtering",
        ));
    }
    let sid = token_user_sid(token.get())?;
    Ok(LaunchIdentity {
        token,
        _loaded_profile: Some(loaded_profile),
        temporary_account,
        integrity_level: "medium",
        username: Some(username),
        normal_user_sid: Some(sid),
    })
}

impl LaunchIdentity {
    fn cleanup_temporary_account(&mut self) -> Option<String> {
        let account = self.temporary_account.take()?;
        self.token.close();
        drop(self._loaded_profile.take());
        account.delete().err().map(|error| error.to_string())
    }
}

struct TemporaryLocalAccount {
    username: String,
    username_wide: Vec<u16>,
    active: bool,
}

impl TemporaryLocalAccount {
    fn create() -> AgentResult<(Self, String)> {
        for _ in 0..TEMPORARY_ACCOUNT_CREATE_ATTEMPTS {
            let mut random = [0u8; 20];
            fill_secure_random(&mut random)?;
            let (username, password) = temporary_account_material(&random);
            let mut username_wide = to_wide_null(&username);
            let mut password_wide = to_wide_null(&password);
            let mut comment_wide = to_wide_null("Disposable Foxhole normal-profile account");
            let information = USER_INFO_1 {
                usri1_name: PWSTR(username_wide.as_mut_ptr()),
                usri1_password: PWSTR(password_wide.as_mut_ptr()),
                usri1_priv: USER_PRIV_USER,
                usri1_comment: PWSTR(comment_wide.as_mut_ptr()),
                usri1_flags: USER_ACCOUNT_FLAGS(
                    UF_SCRIPT.0
                        | UF_NORMAL_ACCOUNT
                        | UF_DONT_EXPIRE_PASSWD.0
                        | UF_PASSWD_CANT_CHANGE.0,
                ),
                ..Default::default()
            };
            let mut parameter_error = 0u32;
            let status = unsafe {
                NetUserAdd(
                    PCWSTR::null(),
                    1,
                    (&information as *const USER_INFO_1).cast(),
                    Some(&mut parameter_error),
                )
            };
            password_wide.fill(0);
            if status == NERR_Success {
                return Ok((
                    Self {
                        username,
                        username_wide,
                        active: true,
                    },
                    password,
                ));
            }
            if status != NERR_UserExists {
                return Err(AgentError::new(
                    "configuration",
                    "create_temporary_normal_account",
                    format!(
                        "Windows rejected the disposable normal-profile account (status {status}, parameter {parameter_error})"
                    ),
                ));
            }
        }
        Err(AgentError::new(
            "configuration",
            "temporary_normal_account_collision",
            "could not allocate a unique disposable normal-profile account",
        ))
    }

    fn delete(mut self) -> AgentResult<()> {
        let status = unsafe { NetUserDel(PCWSTR::null(), PCWSTR(self.username_wide.as_ptr())) };
        if status == NERR_Success || status == NERR_UserNotFound {
            self.active = false;
            Ok(())
        } else {
            Err(AgentError::new(
                "cleanup",
                "delete_temporary_normal_account",
                format!(
                    "Windows could not delete disposable normal-profile account {} (status {status})",
                    self.username
                ),
            ))
        }
    }
}

impl Drop for TemporaryLocalAccount {
    fn drop(&mut self) {
        if self.active {
            let _ = unsafe { NetUserDel(PCWSTR::null(), PCWSTR(self.username_wide.as_ptr())) };
        }
    }
}

fn fill_secure_random(output: &mut [u8]) -> AgentResult<()> {
    let status = unsafe { BCryptGenRandom(None, output, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_ok() {
        Ok(())
    } else {
        Err(AgentError::new(
            "configuration",
            "generate_temporary_normal_password",
            format!(
                "Windows secure random generation failed with status 0x{:08x}",
                status.0
            ),
        ))
    }
}

fn lowercase_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn temporary_account_material(random: &[u8; 20]) -> (String, String) {
    (
        format!("foxhole-{}", lowercase_hex(&random[..6])),
        format!("Fh1!{}", lowercase_hex(&random[6..])),
    )
}

struct LoadedUserProfile {
    token: OwnedHandle,
    profile: HANDLE,
}

impl Drop for LoadedUserProfile {
    fn drop(&mut self) {
        let _ = unsafe { UnloadUserProfile(self.token.get(), self.profile) };
    }
}

fn load_user_profile(
    token: OwnedHandle,
    username_wide: &mut [u16],
) -> AgentResult<LoadedUserProfile> {
    let mut profile = PROFILEINFOW {
        dwSize: mem::size_of::<PROFILEINFOW>() as u32,
        // PI_NOUI: fail instead of presenting service-hosted UI.
        dwFlags: 1,
        lpUserName: PWSTR(username_wide.as_mut_ptr()),
        ..Default::default()
    };
    unsafe { LoadUserProfileW(token.get(), &mut profile) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "load_normal_user_profile",
            "load the configured guest standard account profile",
            error,
        )
    })?;
    if profile.hProfile.is_invalid() {
        return Err(AgentError::new(
            "execution",
            "invalid_normal_user_profile",
            "Windows loaded the normal account without returning a profile handle",
        ));
    }
    Ok(LoadedUserProfile {
        token,
        profile: profile.hProfile,
    })
}

fn token_has_enabled_admin_group(token: HANDLE) -> AgentResult<bool> {
    let token = duplicate_impersonation_token(token)?;
    let words = (SECURITY_MAX_SID_SIZE as usize).div_ceil(mem::size_of::<usize>());
    let mut storage = vec![0usize; words];
    let mut length = SECURITY_MAX_SID_SIZE;
    let sid = PSID(storage.as_mut_ptr().cast());
    unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut length) }
        .map_err(|error| {
            AgentError::with_source(
                "execution",
                "create_admin_group_sid",
                "create the built-in Administrators SID",
                error,
            )
        })?;
    let mut member = BOOL(0);
    unsafe { CheckTokenMembership(Some(token.get()), sid, &mut member) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "check_normal_admin_membership",
            "verify that the normal-profile token is not elevated",
            error,
        )
    })?;
    Ok(member.as_bool())
}

fn duplicate_impersonation_token(source: HANDLE) -> AgentResult<OwnedHandle> {
    let mut impersonation = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            source,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut impersonation,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "execution",
            "duplicate_membership_token",
            "duplicate the normal-profile token for group membership validation",
            error,
        )
    })?;
    Ok(OwnedHandle::new(impersonation))
}

fn read_secret(path: &Path) -> AgentResult<String> {
    if !path.is_absolute() {
        return Err(AgentError::new(
            "configuration",
            "unsafe_normal_password_file",
            "normal-profile password file must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AgentError::with_source(
            "configuration",
            "inspect_normal_password_file",
            "inspect the configured normal-profile password file",
            error,
        )
    })?;
    #[cfg(target_os = "windows")]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x0000_0400 != 0
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || reparse
        || metadata.len() == 0
        || metadata.len() > MAX_ACCOUNT_SECRET_BYTES
    {
        return Err(AgentError::new(
            "configuration",
            "unsafe_normal_password_file",
            "normal-profile password file is not a plain bounded file",
        ));
    }
    let mut password = fs::read_to_string(path).map_err(|error| {
        AgentError::with_source(
            "configuration",
            "read_normal_password_file",
            "read the configured normal-profile password file",
            error,
        )
    })?;
    while password.ends_with(['\r', '\n']) {
        password.pop();
    }
    if password.is_empty() || password.contains('\0') {
        return Err(AgentError::new(
            "configuration",
            "invalid_normal_password",
            "normal-profile password is empty or contains NUL",
        ));
    }
    Ok(password)
}

fn linked_standard_token(token: HANDLE) -> AgentResult<Option<OwnedHandle>> {
    let elevation: TOKEN_ELEVATION_TYPE = token_scalar(token, TokenElevationType)?;
    if elevation != TokenElevationTypeFull {
        return Ok(None);
    }
    let linked: TOKEN_LINKED_TOKEN = token_scalar(token, TokenLinkedToken)?;
    if linked.LinkedToken.is_invalid() {
        return Err(AgentError::new(
            "execution",
            "invalid_linked_normal_token",
            "Windows returned an invalid linked standard-user token",
        ));
    }
    Ok(Some(OwnedHandle::new(linked.LinkedToken)))
}

fn token_scalar<T: Default>(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> AgentResult<T> {
    let mut value = T::default();
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some((&mut value as *mut T).cast()),
            mem::size_of::<T>() as u32,
            &mut returned,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "execution",
            "query_profile_token",
            "query the guest profile token",
            error,
        )
    })?;
    if returned as usize != mem::size_of::<T>() {
        return Err(AgentError::new(
            "execution",
            "truncated_profile_token",
            "Windows returned truncated guest profile token information",
        ));
    }
    Ok(value)
}

fn duplicate_primary_token(source: HANDLE) -> AgentResult<OwnedHandle> {
    let mut primary = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            source,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "execution",
            "duplicate_profile_token",
            "duplicate the guest profile primary token",
            error,
        )
    })?;
    Ok(OwnedHandle::new(primary))
}

fn token_user_sid(token: HANDLE) -> AgentResult<String> {
    let mut required = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
    if required == 0 {
        return Err(AgentError::new(
            "execution",
            "query_profile_sid_size",
            "Windows did not return a profile-token SID buffer size",
        ));
    }
    let words = (required as usize).div_ceil(mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "execution",
            "query_profile_sid",
            "query the guest profile token SID",
            error,
        )
    })?;
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut text) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "format_profile_sid",
            "format the guest profile token SID",
            error,
        )
    })?;
    let text_guard = LocalString(text);
    let mut length = 0usize;
    while unsafe { *text_guard.0.0.add(length) } != 0 {
        length = length.saturating_add(1);
        if length > 256 {
            return Err(AgentError::new(
                "execution",
                "profile_sid_too_long",
                "guest profile SID exceeds 256 UTF-16 characters",
            ));
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text_guard.0.0, length) }).map_err(
        |error| {
            AgentError::with_source(
                "execution",
                "decode_profile_sid",
                "decode the guest profile token SID",
                error,
            )
        },
    )
}

fn grant_normal_user_workspace_access(workspace: &GuestWorkspace, sid: &str) -> AgentResult<()> {
    if !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
    {
        return Err(AgentError::new(
            "execution",
            "invalid_normal_sid",
            "normal-profile token returned an unsafe SID",
        ));
    }
    let input = workspace.target.parent().ok_or_else(|| {
        AgentError::new(
            "execution",
            "missing_native_input",
            "staged target has no input directory",
        )
    })?;
    for directory in [&workspace.root, input, &workspace.work] {
        run_icacls(directory, &format!("*{sid}:(OI)(CI)M"))?;
    }
    run_icacls(&workspace.target, &format!("*{sid}:RX"))
}

fn run_icacls(path: &Path, grant: &str) -> AgentResult<()> {
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        AgentError::new(
            "configuration",
            "missing_system_root",
            "SystemRoot is unavailable",
        )
    })?;
    let icacls = PathBuf::from(system_root)
        .join("System32")
        .join("icacls.exe");
    let status = std::process::Command::new(&icacls)
        .arg(path)
        .args(["/grant", grant, "/Q"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            AgentError::with_source(
                "execution",
                "start_workspace_acl",
                "start icacls for the normal-profile workspace",
                error,
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AgentError::new(
            "execution",
            "grant_workspace_acl",
            format!("icacls rejected the normal-profile workspace ACL with {status}"),
        ))
    }
}

struct LaunchPlan {
    application: String,
    command_line: String,
}

fn build_launch(target: &Path, arguments: &[String]) -> AgentResult<LaunchPlan> {
    let target = win32_path_string(target);
    let is_batch = Path::new(&target)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
        });
    if !is_batch {
        return Ok(LaunchPlan {
            application: target.clone(),
            command_line: build_windows_command_line(&target, arguments),
        });
    }
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        AgentError::new(
            "configuration",
            "missing_system_root",
            "SystemRoot is unavailable",
        )
    })?;
    let cmd = PathBuf::from(system_root).join("System32").join("cmd.exe");
    let cmd = win32_path_string(&cmd);
    let batch_command = build_windows_command_line(&target, arguments);
    Ok(LaunchPlan {
        application: cmd.clone(),
        command_line: build_windows_command_line(
            &cmd,
            &[
                "/D".to_string(),
                "/S".to_string(),
                "/C".to_string(),
                batch_command,
            ],
        ),
    })
}

fn build_environment(work: &Path, username: Option<&str>) -> AgentResult<Vec<u16>> {
    let system_root = std::env::var("SystemRoot").map_err(|_| {
        AgentError::new(
            "configuration",
            "missing_system_root",
            "SystemRoot is unavailable",
        )
    })?;
    let system32 = PathBuf::from(&system_root).join("System32");
    let system_drive: String = system_root.chars().take(2).collect();
    let mut values = std::collections::BTreeMap::new();
    values.insert("COMSPEC", system32.join("cmd.exe").display().to_string());
    values.insert("PATH", system32.display().to_string());
    values.insert("SYSTEMDRIVE", system_drive.clone());
    values.insert("SYSTEMROOT", system_root.clone());
    values.insert("TEMP", work.display().to_string());
    values.insert("TMP", work.display().to_string());
    values.insert("WINDIR", system_root);
    if let Some(username) = username {
        let home_path = PathBuf::from(r"\Users").join(username);
        let profile = PathBuf::from(&system_drive).join(&home_path);
        values.insert(
            "APPDATA",
            profile.join(r"AppData\Roaming").display().to_string(),
        );
        values.insert(
            "LOCALAPPDATA",
            profile.join(r"AppData\Local").display().to_string(),
        );
        values.insert("USERPROFILE", profile.display().to_string());
        values.insert("USERNAME", username.to_string());
        values.insert("HOMEDRIVE", system_drive);
        values.insert("HOMEPATH", home_path.display().to_string());
    } else {
        let profile = system32.join(r"config\systemprofile");
        values.insert(
            "APPDATA",
            profile.join(r"AppData\Roaming").display().to_string(),
        );
        values.insert(
            "LOCALAPPDATA",
            profile.join(r"AppData\Local").display().to_string(),
        );
        values.insert("USERPROFILE", profile.display().to_string());
        values.insert("USERNAME", "SYSTEM".to_string());
        values.insert("HOMEDRIVE", system_drive);
        values.insert(
            "HOMEPATH",
            r"\Windows\System32\config\systemprofile".to_string(),
        );
    }
    let mut block = Vec::new();
    for (key, value) in values {
        if value.contains(['\0', '=']) {
            return Err(AgentError::new(
                "configuration",
                "invalid_native_environment",
                "guest-native environment contains an unsafe value",
            ));
        }
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn create_job(request: &GuestRunRequest) -> AgentResult<OwnedHandle> {
    let handle = OwnedHandle::new(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(
        |error| {
            AgentError::with_source(
                "execution",
                "create_native_job",
                "create the guest-native cleanup job",
                error,
            )
        },
    )?);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = request.resource_limits.active_process_limit;
    limits.ProcessMemoryLimit = request.resource_limits.process_memory_bytes as usize;
    limits.JobMemoryLimit = request.resource_limits.job_memory_bytes as usize;
    unsafe {
        SetInformationJobObject(
            handle.get(),
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const c_void,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "execution",
            "limit_native_job",
            "apply guest-native job limits",
            error,
        )
    })?;
    Ok(handle)
}

fn wait_bounded(process: HANDLE, job: HANDLE, timeout_seconds: u64) -> AgentResult<bool> {
    let started = Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            unsafe { TerminateJobObject(job, 1) }.map_err(|error| {
                AgentError::with_source(
                    "execution",
                    "terminate_native_timeout",
                    "terminate the timed-out guest-native process tree",
                    error,
                )
            })?;
            let _ = unsafe { WaitForSingleObject(process, u32::MAX) };
            return Ok(true);
        }
        let wait_ms = remaining.as_millis().clamp(1, 250) as u32;
        let wait = unsafe { WaitForSingleObject(process, wait_ms) };
        if wait == WAIT_OBJECT_0 {
            return Ok(false);
        }
        if wait == WAIT_FAILED {
            return Err(AgentError::with_source(
                "execution",
                "wait_native_process",
                "wait for the guest-native target process",
                windows::core::Error::from_thread(),
            ));
        }
        if wait != WAIT_TIMEOUT {
            return Err(AgentError::new(
                "execution",
                "unexpected_native_wait",
                format!("unexpected native process wait result: {}", wait.0),
            ));
        }
    }
}

struct CapturedOutput {
    bytes: Vec<u8>,
    bytes_seen: u64,
}

struct OutputPipe {
    reader: File,
    writer: OwnedHandle,
}

struct InputPipe {
    reader: OwnedHandle,
    writer: OwnedHandle,
}

fn output_pipe() -> AgentResult<OutputPipe> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut reader = HANDLE::default();
    let mut writer = HANDLE::default();
    unsafe { CreatePipe(&mut reader, &mut writer, Some(&attributes), 0) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "create_native_output_pipe",
            "create a guest-native output pipe",
            error,
        )
    })?;
    let reader = OwnedHandle::new(reader);
    unsafe { SetHandleInformation(reader.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.map_err(
        |error| {
            AgentError::with_source(
                "execution",
                "protect_native_output_pipe",
                "disable inheritance on a guest-native output reader",
                error,
            )
        },
    )?;
    let raw = reader.into_raw();
    Ok(OutputPipe {
        reader: unsafe { File::from_raw_handle(raw.0) },
        writer: OwnedHandle::new(writer),
    })
}

fn input_pipe() -> AgentResult<InputPipe> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut reader = HANDLE::default();
    let mut writer = HANDLE::default();
    unsafe { CreatePipe(&mut reader, &mut writer, Some(&attributes), 0) }.map_err(|error| {
        AgentError::with_source(
            "execution",
            "create_native_input_pipe",
            "create the guest-native input pipe",
            error,
        )
    })?;
    let writer = OwnedHandle::new(writer);
    unsafe { SetHandleInformation(writer.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.map_err(
        |error| {
            AgentError::with_source(
                "execution",
                "protect_native_input_pipe",
                "disable inheritance on the guest-native input writer",
                error,
            )
        },
    )?;
    Ok(InputPipe {
        reader: OwnedHandle::new(reader),
        writer,
    })
}

fn spawn_reader(mut reader: File) -> thread::JoinHandle<std::io::Result<CapturedOutput>> {
    thread::spawn(move || {
        let mut output = CapturedOutput {
            bytes: Vec::with_capacity(64 * 1024),
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
            output
                .bytes
                .extend_from_slice(&buffer[..remaining.min(count)]);
        }
        Ok(output)
    })
}

fn finish_reader(
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
            (String::from_utf8_lossy(&output.bytes).into_owned(), summary)
        }
        Ok(Err(error)) => {
            warnings.push(format!("failed to capture {stream}: {error}"));
            (String::new(), empty_capture())
        }
        Err(_) => {
            warnings.push(format!("{stream} capture thread panicked"));
            (String::new(), empty_capture())
        }
    }
}

fn empty_capture() -> StreamCaptureSummary {
    StreamCaptureSummary {
        bytes_seen: 0,
        bytes_stored: 0,
        truncated: false,
    }
}

fn network_policy_name(policy: GuestNetworkPolicy) -> &'static str {
    match policy {
        GuestNetworkPolicy::DenyAll => "deny_all",
        GuestNetworkPolicy::HostServer => "host_server",
        GuestNetworkPolicy::AllowList => "allow_list",
        GuestNetworkPolicy::AllowInternet => "allow_internet",
        GuestNetworkPolicy::CaptureOnly => "capture_only",
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn get(&self) -> HANDLE {
        self.0
    }

    fn close(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
            self.0 = HANDLE::default();
        }
    }

    fn into_raw(mut self) -> HANDLE {
        let raw = self.0;
        self.0 = HANDLE::default();
        raw
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        self.close();
    }
}

struct LocalString(PWSTR);

impl Drop for LocalString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0.cast())));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_launch_plan_supports_executables_and_batch_files() {
        let exe = build_launch(Path::new(r"C:\work\sample.exe"), &["one two".to_string()])
            .expect("exe launch");
        assert!(exe.command_line.contains("sample.exe"));
        assert!(exe.command_line.contains("one two"));

        let batch = build_launch(Path::new(r"C:\work\sample.bat"), &[]).expect("batch launch");
        assert!(batch.application.ends_with("cmd.exe"));
        assert!(batch.command_line.contains("/C"));
    }

    #[test]
    fn native_environment_is_minimal_and_omits_agent_secrets() {
        let environment =
            build_environment(Path::new(r"C:\work"), Some("SampleUser")).expect("environment");
        let text = String::from_utf16_lossy(&environment);
        assert!(text.contains("TEMP=C:\\work"));
        assert!(text.contains("USERNAME=SampleUser"));
        assert!(text.contains("HOMEPATH=\\Users\\SampleUser"));
        assert!(!text.contains("FOXHOLE_GUEST_NORMAL_PASSWORD"));

        let system_environment =
            build_environment(Path::new(r"C:\work"), None).expect("system environment");
        let system_text = String::from_utf16_lossy(&system_environment);
        assert!(system_text.contains("USERNAME=SYSTEM"));
        assert!(system_text.contains("systemprofile"));
    }

    #[test]
    fn disposable_normal_account_material_is_bounded_and_complex() {
        let (username, password) = temporary_account_material(&[0xab; 20]);
        assert_eq!(username, "foxhole-abababababab");
        assert_eq!(username.len(), 20);
        assert_eq!(password, "Fh1!abababababababababababababab");
        assert_eq!(password.len(), 32);
        assert!(password.bytes().any(|byte| byte.is_ascii_uppercase()));
        assert!(password.bytes().any(|byte| byte.is_ascii_lowercase()));
        assert!(password.bytes().any(|byte| byte.is_ascii_digit()));
        assert!(password.bytes().any(|byte| !byte.is_ascii_alphanumeric()));
        assert!(!password.contains(username.as_str()));
    }
}
