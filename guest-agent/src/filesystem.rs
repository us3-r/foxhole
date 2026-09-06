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
