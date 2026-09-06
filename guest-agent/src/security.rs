use crate::runner::{AgentError, AgentResult};
use std::fs;
use std::path::{Component, Path};

const MAX_FLAT_LAYOUT_ENTRIES: usize = 128;

/// The guest agent cannot know the disposable AppContainer SID before the
/// restricted-process backend creates it. Broker directories therefore remain
/// agent/SYSTEM/Administrators-only. The restricted backend is responsible for
/// copying the target into its per-run workspace and granting that exact SID
/// read/execute access there.
pub const SANDBOX_ACL_DELEGATION_NOTICE: &str = "guest broker paths are protected for the agent, \
SYSTEM, and Administrators; the restricted backend grants read/execute access only to its \
disposable AppContainer SID after creating that identity";

pub fn prepare_broker_directory(path: &Path) -> AgentResult<()> {
    validate_absolute_normalized(path, "broker directory")?;

    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                reject_non_plain_directory(cursor, &metadata)?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    AgentError::new(
                        "filesystem",
                        "missing_directory_root",
                        "broker directory has no existing ancestor",
                    )
                })?;
            }
            Err(error) => {
                return Err(AgentError::with_source(
                    "filesystem",
                    "inspect_directory_ancestor",
                    format!("inspect broker directory ancestor {}", cursor.display()),
                    error,
                ));
            }
        }
    }

    for directory in missing.iter().rev() {
        fs::create_dir(directory).map_err(|error| {
            AgentError::with_source(
                "filesystem",
                "create_broker_directory",
                format!("create broker directory {}", directory.display()),
                error,
            )
        })?;
        validate_existing_directory(directory)?;
        harden_broker_path(directory, PathKind::Directory)?;
    }

    validate_existing_directory_tree(path)?;
    harden_broker_path(path, PathKind::Directory)
}

pub fn validate_existing_directory_tree(path: &Path) -> AgentResult<()> {
    validate_absolute_normalized(path, "directory")?;
    validate_existing_directory(path)?;

    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            AgentError::with_source(
                "filesystem",
                "inspect_directory_ancestor",
                format!("inspect directory ancestor {}", ancestor.display()),
                error,
            )
        })?;
        reject_non_plain_directory(ancestor, &metadata)?;
    }
    Ok(())
}

pub fn harden_run_data_layout(
    root: &Path,
    request: &Path,
    input: &Path,
    output: &Path,
    status: &Path,
) -> AgentResult<()> {
    validate_existing_directory_tree(root)?;
    for directory in [root, input, output, status] {
        validate_existing_directory(directory)?;
        harden_broker_path(directory, PathKind::Directory)?;
    }
    harden_broker_file(request, false)?;
    harden_flat_directory_files(input)?;
    harden_flat_directory_files(status)?;
    Ok(())
}

pub fn harden_broker_directory(path: &Path) -> AgentResult<()> {
    validate_existing_directory_tree(path)?;
    harden_broker_path(path, PathKind::Directory)
}

pub fn harden_broker_file(path: &Path, executable: bool) -> AgentResult<()> {
    validate_absolute_normalized(path, "broker file")?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AgentError::with_source(
            "filesystem",
            "inspect_broker_file",
            format!("inspect broker file {}", path.display()),
            error,
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(AgentError::new(
            "filesystem",
            "unsafe_broker_file",
            format!(
                "broker file is not a plain regular file: {}",
                path.display()
            ),
        ));
    }
    if let Some(parent) = path.parent() {
        validate_existing_directory_tree(parent)?;
    }
    harden_broker_path(path, PathKind::File { executable })?;

    // Recheck after applying the descriptor so a path substitution is noticed
    // before the file is handed to the restricted-process broker.
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AgentError::with_source(
            "filesystem",
            "reinspect_broker_file",
            format!("reinspect broker file {}", path.display()),
            error,
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(AgentError::new(
            "filesystem",
            "broker_file_changed",
            "broker file changed while its ACL was being hardened",
        ));
    }
    Ok(())
}

fn harden_flat_directory_files(root: &Path) -> AgentResult<()> {
    let mut count = 0usize;
    for entry in fs::read_dir(root).map_err(|error| {
        AgentError::with_source(
            "filesystem",
            "enumerate_broker_directory",
            format!("enumerate broker directory {}", root.display()),
            error,
        )
    })? {
        count = count.saturating_add(1);
        if count > MAX_FLAT_LAYOUT_ENTRIES {
            return Err(AgentError::new(
                "filesystem",
                "too_many_layout_entries",
                format!("broker directory contains more than {MAX_FLAT_LAYOUT_ENTRIES} entries"),
            ));
        }
        let entry = entry.map_err(|error| {
            AgentError::with_source(
                "filesystem",
                "read_broker_entry",
                format!("read an entry below {}", root.display()),
                error,
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AgentError::with_source(
                "filesystem",
                "inspect_broker_entry",
                format!("inspect broker entry {}", path.display()),
                error,
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(AgentError::new(
                "filesystem",
                "unsafe_layout_entry",
                format!(
                    "run-data input and status directories may contain only plain files: {}",
                    path.display()
                ),
            ));
        }
        harden_broker_file(&path, false)?;
    }
    Ok(())
}

fn validate_absolute_normalized(path: &Path, description: &str) -> AgentResult<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AgentError::new(
            "filesystem",
            "unsafe_broker_path",
            format!("{description} must be absolute and lexically normalized"),
        ));
    }
    Ok(())
}

fn validate_existing_directory(path: &Path) -> AgentResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AgentError::with_source(
            "filesystem",
            "inspect_directory",
            format!("inspect directory {}", path.display()),
            error,
        )
    })?;
    reject_non_plain_directory(path, &metadata)
}

fn reject_non_plain_directory(path: &Path, metadata: &fs::Metadata) -> AgentResult<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(metadata) {
        return Err(AgentError::new(
            "filesystem",
            "unsafe_directory",
            format!("directory is not a plain directory: {}", path.display()),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PathKind {
    Directory,
    File { executable: bool },
}

#[cfg(target_os = "windows")]
fn harden_broker_path(path: &Path, kind: PathKind) -> AgentResult<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, LABEL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{PCWSTR, PWSTR};

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: this guard owns a token handle opened below.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalGuard(*mut c_void);

    impl Drop for LocalGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was allocated by a Windows LocalAlloc
                // family API and is released exactly once.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0)));
                }
            }
        }
    }

    fn current_process_sid() -> AgentResult<String> {
        let mut token = HANDLE::default();
        // SAFETY: the output pointer is valid and receives an owned handle.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(
            |error| {
                AgentError::with_source(
                    "filesystem",
                    "open_agent_token",
                    "open the guest-agent process token",
                    error,
                )
            },
        )?;
        let _token_guard = HandleGuard(token);

        let mut required = 0u32;
        // The first call intentionally obtains the required buffer size.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        if required == 0 {
            return Err(AgentError::new(
                "filesystem",
                "query_agent_sid_size",
                "Windows did not return a token-user buffer size",
            ));
        }
        let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        // SAFETY: the word buffer is suitably aligned and at least `required`
        // bytes long.
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
                "filesystem",
                "query_agent_sid",
                "query the guest-agent token SID",
                error,
            )
        })?;
        // SAFETY: GetTokenInformation returned a TOKEN_USER structure in the
        // aligned buffer.
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut raw_sid = PWSTR::null();
        // SAFETY: TOKEN_USER owns a valid SID for the lifetime of `buffer`, and
        // Windows writes a LocalAlloc-owned string pointer.
        unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut raw_sid) }.map_err(|error| {
            AgentError::with_source(
                "filesystem",
                "format_agent_sid",
                "format the guest-agent token SID",
                error,
            )
        })?;
        let _sid_guard = LocalGuard(raw_sid.0.cast());
        let mut length = 0usize;
        // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
        while unsafe { *raw_sid.0.add(length) } != 0 {
            length = length.checked_add(1).ok_or_else(|| {
                AgentError::new(
                    "filesystem",
                    "agent_sid_too_long",
                    "guest-agent SID length overflowed",
                )
            })?;
            if length > 256 {
                return Err(AgentError::new(
                    "filesystem",
                    "agent_sid_too_long",
                    "guest-agent SID exceeds the expected Windows SID length",
                ));
            }
        }
        // SAFETY: the preceding loop found the terminating NUL.
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(raw_sid.0, length) })
            .map_err(|error| {
                AgentError::with_source(
                    "filesystem",
                    "decode_agent_sid",
                    "decode the guest-agent SID",
                    error,
                )
            })?;
        if !is_valid_sid_text(&sid) {
            return Err(AgentError::new(
                "filesystem",
                "invalid_agent_sid",
                "Windows returned an invalid textual SID",
            ));
        }
        Ok(sid)
    }

    let agent_sid = current_process_sid()?;
    let (inheritance, integrity_label) = match kind {
        PathKind::Directory => ("OICI", ""),
        PathKind::File { executable: true } => ("", "S:(ML;;NW;;;ME)"),
        PathKind::File { executable: false } => ("", ""),
    };
    let descriptor = format!(
        "O:{agent_sid}D:P(A;{inheritance};FA;;;{agent_sid})(A;{inheritance};FA;;;SY)\
(A;{inheritance};FA;;;BA){integrity_label}"
    );
    let descriptor = descriptor
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut converted = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the descriptor string is NUL terminated and the output pointer is
    // valid. The returned allocation is owned by `descriptor_guard`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(descriptor.as_ptr()),
            SDDL_REVISION_1,
            &mut converted,
            None,
        )
    }
    .map_err(|error| {
        AgentError::with_source(
            "filesystem",
            "build_broker_acl",
            "build the protected broker security descriptor",
            error,
        )
    })?;
    let _descriptor_guard = LocalGuard(converted.0);
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    if matches!(kind, PathKind::File { executable: true }) {
        information |= LABEL_SECURITY_INFORMATION;
    }
    // SAFETY: both the path and security descriptor remain live for the call.
    unsafe { SetFileSecurityW(PCWSTR(path.as_ptr()), information, converted) }
        .ok()
        .map_err(|error| {
            AgentError::with_source(
                "filesystem",
                "apply_broker_acl",
                "apply the protected broker ACL",
                error,
            )
        })
}

#[cfg(not(target_os = "windows"))]
fn harden_broker_path(_path: &Path, _kind: PathKind) -> AgentResult<()> {
    Ok(())
}

fn is_valid_sid_text(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let mut components = value.split('-');
    if components.next() != Some("S") || components.next() != Some("1") {
        return false;
    }
    let mut saw_authority = false;
    for component in components {
        saw_authority = true;
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    saw_authority
}

#[cfg(target_os = "windows")]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_validation_is_pure_and_rejects_lexical_escape() {
        assert!(validate_absolute_normalized(&std::env::temp_dir(), "test").is_ok());
        assert!(validate_absolute_normalized(Path::new("relative"), "test").is_err());
        let escaped = std::env::temp_dir().join("safe").join("..").join("escape");
        assert!(validate_absolute_normalized(&escaped, "test").is_err());
    }

    #[test]
    fn textual_sid_validation_rejects_sddl_injection() {
        assert!(is_valid_sid_text("S-1-5-18"));
        assert!(is_valid_sid_text("S-1-5-21-123-456-789-1001"));
        for invalid in [
            "",
            "BA",
            "S-2-5-18",
            "S-1-",
            "S-1--18",
            "S-1-5-18)(A;;FA;;;WD",
            "S-1-A",
        ] {
            assert!(!is_valid_sid_text(invalid), "{invalid}");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_broker_acl_application_succeeds_on_new_paths() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let root = std::env::temp_dir().join(format!(
            "foxhole-agent-acl-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let nested = root.join("broker");
        prepare_broker_directory(&nested).expect("protect broker directory");
        let target = nested.join("target.exe");
        fs::write(&target, b"MZ").expect("write target");
        harden_broker_file(&target, true).expect("protect executable target");

        fs::remove_file(target).expect("remove protected target");
        fs::remove_dir(nested).expect("remove protected broker directory");
        fs::remove_dir(root).expect("remove protected root");
    }
}
