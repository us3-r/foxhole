use crate::artifacts::Sha256;
use crate::request::RunLayout;
use crate::runner::{AgentError, AgentResult};
use crate::security;
use foxhole::host_file;
use foxhole::sandbox::hyperv::guest_protocol::{GuestRunRequest, validate_sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_TARGET_BYTES: u64 = 600 * 1024 * 1024;

#[derive(Debug)]
pub struct GuestWorkspace {
    base: PathBuf,
    pub root: PathBuf,
    pub work: PathBuf,
    pub output: PathBuf,
    pub target: PathBuf,
    cleaned: bool,
}

impl GuestWorkspace {
    pub fn stage(
        layout: &RunLayout,
        request: &GuestRunRequest,
        staging_base: &Path,
    ) -> AgentResult<Self> {
        if !staging_base.is_absolute()
            || staging_base
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(AgentError::new(
                "staging",
                "invalid_staging_root",
                "guest-local staging root must be absolute and lexically normalized",
            ));
        }
        security::prepare_broker_directory(staging_base)?;
        let base = staging_base.canonicalize().map_err(|error| {
            AgentError::with_source(
                "staging",
                "canonicalize_staging_root",
                "canonicalize the guest-local staging root",
                error,
            )
        })?;

        let root = base.join(&request.run_id);
        fs::create_dir(&root).map_err(|error| {
            AgentError::with_source(
                "staging",
                "create_workspace",
                "create the exclusive guest-local workspace",
                error,
            )
        })?;
        let mut cleanup = WorkspaceCleanup::new(root.clone());
        security::harden_broker_directory(&root)?;
        let input = root.join("input");
        fs::create_dir(&input).map_err(|error| {
            AgentError::with_source(
                "staging",
                "create_input",
                "create the guest-local input directory",
                error,
            )
        })?;
        security::harden_broker_directory(&input)?;
        let work = root.join("work");
        fs::create_dir(&work).map_err(|error| {
            AgentError::with_source(
                "staging",
                "create_work",
                "create the guest-local working directory",
                error,
            )
        })?;
        security::harden_broker_directory(&work)?;

        let source_path = layout.target_source(request)?;
        let mut source =
            host_file::open_pinned_input(&source_path, MAX_TARGET_BYTES).map_err(|error| {
                AgentError::with_source(
                    "staging",
                    "pin_target",
                    "open and pin the run-data target",
                    error,
                )
            })?;
        let target_name = source_path.file_name().ok_or_else(|| {
            AgentError::new(
                "staging",
                "missing_target_name",
                "target does not have a file name",
            )
        })?;
        let target = input.join(target_name);
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| {
                AgentError::with_source(
                    "staging",
                    "create_staged_target",
                    "create the guest-local target",
                    error,
                )
            })?;

        let mut digest = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = source.file.read(&mut buffer).map_err(|error| {
                AgentError::with_source("staging", "read_target", "read the pinned target", error)
            })?;
            if count == 0 {
                break;
            }
            copied = copied.checked_add(count as u64).ok_or_else(|| {
                AgentError::new(
                    "staging",
                    "target_size_overflow",
                    "target byte count overflowed",
                )
            })?;
            if copied > MAX_TARGET_BYTES {
                return Err(AgentError::new(
                    "staging",
                    "target_too_large",
                    "target exceeded the staging limit",
                ));
            }
            digest.update(&buffer[..count]);
            destination.write_all(&buffer[..count]).map_err(|error| {
                AgentError::with_source(
                    "staging",
                    "write_target",
                    "write the guest-local target",
                    error,
                )
            })?;
        }
        if copied != source.len {
            return Err(AgentError::new(
                "staging",
                "target_changed",
                "pinned target length changed while it was copied",
            ));
        }
        destination
            .flush()
            .and_then(|_| destination.sync_all())
            .map_err(|error| {
                AgentError::with_source(
                    "staging",
                    "flush_target",
                    "flush the guest-local target",
                    error,
                )
            })?;
        drop(destination);

        let actual_digest = digest.finish_hex();
        if let Some(expected_digest) = request.target_sha256.as_deref() {
            validate_sha256(expected_digest).map_err(|error| {
                AgentError::new(
                    "staging",
                    "invalid_target_digest",
                    format!("validate target digest: {error}"),
                )
            })?;
            if !actual_digest.eq_ignore_ascii_case(expected_digest) {
                return Err(AgentError::new(
                    "staging",
                    "target_digest_mismatch",
                    "staged target does not match request target_sha256",
                ));
            }
        }

        security::harden_broker_file(&target, true)?;
        let mut permissions = fs::metadata(&target)
            .map_err(|error| {
                AgentError::with_source(
                    "staging",
                    "inspect_staged_target",
                    "inspect the staged target",
                    error,
                )
            })?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&target, permissions).map_err(|error| {
            AgentError::with_source(
                "staging",
                "protect_staged_target",
                "mark the staged target read-only",
                error,
            )
        })?;

        cleanup.committed = true;
        Ok(Self {
            base,
            root,
            work,
            output: layout.output.clone(),
            target,
            cleaned: false,
        })
    }

    pub fn cleanup(&mut self) -> AgentResult<()> {
        if self.cleaned {
            return Ok(());
        }
        if self.root.parent() != Some(self.base.as_path()) {
            return Err(AgentError::new(
                "cleanup",
                "unsafe_workspace_path",
                "refusing to remove a workspace outside its configured base",
            ));
        }
        match fs::remove_dir_all(&self.root) {
            Ok(()) => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) => Err(AgentError::with_source(
                "cleanup",
                "remove_workspace",
                "remove the guest-local workspace",
                error,
            )),
        }
    }
}

impl Drop for GuestWorkspace {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct WorkspaceCleanup {
    root: PathBuf,
    committed: bool,
}

impl WorkspaceCleanup {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            committed: false,
        }
    }
}

impl Drop for WorkspaceCleanup {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

pub fn ensure_plain_directory(path: &Path) -> AgentResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AgentError::with_source(
            "filesystem",
            "inspect_directory",
            format!("inspect directory {}", path.display()),
            error,
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(AgentError::new(
            "filesystem",
            "unsafe_directory",
            format!("directory is not a plain directory: {}", path.display()),
        ));
    }
    Ok(())
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
    use std::env;
    use std::fs::File;

    #[cfg(target_os = "windows")]
    #[test]
    fn normal_profile_can_write_work_but_cannot_modify_broker_code_or_input() {
        let root = env::temp_dir().join(format!(
            "foxhole-normal-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        security::prepare_broker_directory(&root).unwrap();
        let work = root.join("work");
        let input = root.join("input");
        for directory in [&work, &input] {
            security::prepare_broker_directory(directory).unwrap();
        }
        let target = input.join("target.exe");
        fs::write(&target, b"inert").unwrap();
        security::harden_broker_file(&target, false).unwrap();
        let workspace = GuestWorkspace {
            base: root.clone(),
            root: root.clone(),
            work: work.clone(),
            output: root.join("unused-output"),
            target: target.clone(),
            cleaned: true,
        };
        // A mapped well-known SID exercises icacls and inheritance without
        // creating a local account. Grants apply only to this inert fixture.
        let sid = "S-1-5-32-545";
        crate::native_process::grant_normal_user_workspace_access(&workspace, sid).unwrap();
        let worker = crate::detection::prepare_worker(&root).unwrap();
        fs::write(work.join("ordinary-output.txt"), b"sample output").unwrap();
        // Inspect inherited ACEs for the granted SID, independently of the
        // process running this test (which still owns the broker directories).
        let script = r#"
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.SecurityIdentifier]::new($env:FOXHOLE_ACL_TEST_SID)
function Rights($path) {
  $rights = 0
  $acl = if ([System.IO.Directory]::Exists($path)) { [System.IO.Directory]::GetAccessControl($path) } else { [System.IO.File]::GetAccessControl($path) }
  foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($ace.IdentityReference -eq $sid -and $ace.AccessControlType -eq 'Allow') { $rights = $rights -bor [int]$ace.FileSystemRights }
  }
  return $rights
}
$write = [int]([System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
foreach ($path in @($env:FOXHOLE_ACL_TEST_ROOT, (Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'input'), (Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'input/target.exe'), (Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'scanner'), $env:FOXHOLE_ACL_TEST_WORKER)) {
  if (((Rights $path) -band $write) -ne 0) { throw "sample can modify broker/input path: $path" }
}
$rx = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
foreach ($path in @($env:FOXHOLE_ACL_TEST_ROOT, (Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'input'), (Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'input/target.exe'))) {
  if (((Rights $path) -band $rx) -ne $rx) { throw "sample cannot read/execute target path: $path" }
}
foreach ($path in @((Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'work'), (Join-Path $env:FOXHOLE_ACL_TEST_ROOT 'work/ordinary-output.txt'))) {
  if (((Rights $path) -band 2) -eq 0) { throw "sample cannot write work output: $path" }
}
"#;
        let result = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("FOXHOLE_ACL_TEST_ROOT", &root)
            .env("FOXHOLE_ACL_TEST_SID", sid)
            .env("FOXHOLE_ACL_TEST_WORKER", &worker)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(root.parent(), Some(env::temp_dir().as_path()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plain_directory_check_rejects_a_regular_file() {
        let root = env::temp_dir().join(format!(
            "foxhole-agent-directory-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&root);
        File::create(&root).unwrap();
        assert!(ensure_plain_directory(&root).is_err());
        fs::remove_file(root).unwrap();
    }
}
