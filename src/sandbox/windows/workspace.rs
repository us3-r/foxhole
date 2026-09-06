use crate::sandbox::backend::{
    MappedPath, MappedPathAccess, SandboxError, SandboxRequest, SandboxResult,
};
use crate::structs::{FileObservation, MappedPathObservation};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};

const SDDL_REVISION_1: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const MAX_MAPPED_FILES: usize = 4_096;
const MAX_MAPPED_ENTRIES: usize = 4_096;
const MAX_MAPPED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_OBSERVATIONS: usize = 4_096;
const SE_FILE_OBJECT: i32 = 1;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        security_descriptor: *const u16,
        revision: u32,
        converted: *mut *mut c_void,
        converted_size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorOwner(
        security_descriptor: *const c_void,
        owner: *mut *mut c_void,
        owner_defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        security_descriptor: *const c_void,
        dacl_present: *mut i32,
        dacl: *mut *mut c_void,
        dacl_defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorSacl(
        security_descriptor: *const c_void,
        sacl_present: *mut i32,
        sacl: *mut *mut c_void,
        sacl_defaulted: *mut i32,
    ) -> i32;
    fn SetSecurityInfo(
        handle: *mut c_void,
        object_type: i32,
        security_information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[derive(Debug)]
pub(super) struct Workspace {
    pub(super) root: PathBuf,
    pub(super) work: PathBuf,
    pub(super) output: PathBuf,
    pub(super) target: PathBuf,
    pub(super) mappings: Vec<MappedPathObservation>,
    _target_guard: Option<File>,
}

impl Workspace {
    pub(super) fn create(
        run_root: &Path,
        target_source: &File,
        target_name: &std::ffi::OsStr,
        sandbox_sid: &str,
        request: &SandboxRequest,
    ) -> SandboxResult<Self> {
        validate_run_root(run_root)?;
        let input = run_root.join("input");
        let work = run_root.join("work");
        let output = run_root.join("output");
        let logs = run_root.join("logs");
        let mapped = run_root.join("mapped");
        for path in [&input, &work, &output, &logs, &mapped] {
            fs::create_dir(path)
                .map_err(|error| workspace_io("create workspace directory", error))?;
            reject_reparse(path)?;
        }

        let current_user = crate::artifact::current_user_sid_string()
            .map_err(|error| workspace_io("resolve the broker SID", error))?;
        apply_directory_acl(run_root, sandbox_sid, Access::ReadExecute, &current_user)?;
        apply_directory_acl(&input, sandbox_sid, Access::ReadExecute, &current_user)?;
        apply_directory_acl(&work, sandbox_sid, Access::Modify, &current_user)?;
        apply_directory_acl(&output, sandbox_sid, Access::Modify, &current_user)?;
        apply_directory_acl(&mapped, sandbox_sid, Access::ReadExecute, &current_user)?;
        apply_host_only_acl(&logs, &current_user)?;

        let target = input.join(target_name);
        let staged_target = copy_pinned_file(target_source, &target)?;
        apply_executable_acl(&target, &staged_target, sandbox_sid, &current_user)?;
        let mut permissions = staged_target
            .metadata()
            .map_err(|error| workspace_io("inspect staged target", error))?
            .permissions();
        permissions.set_readonly(true);
        staged_target
            .set_permissions(permissions)
            .map_err(|error| workspace_io("mark staged target read-only", error))?;
        let target_guard = open_staged_target_guard(&target, staged_target)?;

        let mut mappings = Vec::with_capacity(request.mapped_paths.len());
        let mut budget = CopyBudget::default();
        for mapping in &request.mapped_paths {
            let destination = mapping_destination(&mapped, &mapping.guest_name)?;
            stage_mapping(mapping, &destination, &mut budget)?;
            match mapping.access {
                MappedPathAccess::ReadOnly => {
                    apply_tree_acl(
                        &destination,
                        sandbox_sid,
                        Access::ReadExecute,
                        &current_user,
                    )?;
                }
                MappedPathAccess::ReadWrite => {
                    apply_tree_acl(&destination, sandbox_sid, Access::Modify, &current_user)?;
                }
            }
            mappings.push(MappedPathObservation {
                source_name: mapping
                    .host_path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "<redacted>".to_string()),
                sandbox_path: format!("mapped/{}", mapping.guest_name),
                access: match mapping.access {
                    MappedPathAccess::ReadOnly => "read_only".to_string(),
                    MappedPathAccess::ReadWrite => "read_write".to_string(),
                },
            });
        }

        let workspace = Self {
            root: run_root.to_path_buf(),
            work,
            output,
            target,
            mappings,
            _target_guard: Some(target_guard),
        };
        workspace.write_metadata(request, &current_user)?;
        Ok(workspace)
    }

    fn write_metadata(&self, request: &SandboxRequest, current_user: &str) -> SandboxResult<()> {
        #[derive(serde::Serialize)]
        struct Metadata<'a> {
            backend: &'static str,
            network_policy: &'static str,
            mitigation_profile: String,
            timeout_seconds: u64,
            target: String,
            mappings: &'a [MappedPathObservation],
        }

        let path = self.root.join("metadata.json");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| workspace_io("create workspace metadata", error))?;
        let mut writer = BufWriter::new(file);
        let metadata = Metadata {
            backend: "restricted_process",
            network_policy: request.network_policy.name(),
            mitigation_profile: request.mitigation_profile.to_string(),
            timeout_seconds: request.timeout_secs,
            target: format!(
                "input/{}",
                self.target
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            ),
            mappings: &self.mappings,
        };
        serde_json::to_writer_pretty(&mut writer, &metadata).map_err(|error| {
            SandboxError::with_source("workspace", "serialize workspace metadata", error)
        })?;
        writer
            .write_all(b"\n")
            .and_then(|_| writer.flush())
            .map_err(|error| workspace_io("write workspace metadata", error))?;
        apply_host_only_acl(&path, current_user)
    }

    pub(super) fn file_observations(
        &self,
        observed_at_ms: u64,
    ) -> (Vec<FileObservation>, Vec<String>) {
        let mut observations = Vec::new();
        let mut warnings = Vec::new();
        for root in [&self.work, &self.output] {
            for entry in walkdir::WalkDir::new(root).min_depth(1).follow_links(false) {
                if observations.len() >= MAX_FILE_OBSERVATIONS {
                    warnings.push(format!(
                        "file observation limit reached at {MAX_FILE_OBSERVATIONS} entries"
                    ));
                    return (observations, warnings);
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        warnings.push(format!("workspace observation failed: {error}"));
                        continue;
                    }
                };
                let metadata = match fs::symlink_metadata(entry.path()) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        warnings.push(format!(
                            "workspace observation could not inspect an entry: {error}"
                        ));
                        continue;
                    }
                };
                if metadata.file_type().is_symlink() || is_reparse(&metadata) {
                    warnings.push(format!(
                        "workspace observation rejected a reparse entry: {}",
                        entry.path().display()
                    ));
                    continue;
                }
                let relative_path = entry
                    .path()
                    .strip_prefix(&self.root)
                    .map(|path| path.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| "<invalid>".to_string());
                observations.push(FileObservation {
                    relative_path,
                    size_bytes: metadata.len(),
                    kind: if metadata.is_dir() {
                        "directory".to_string()
                    } else {
                        "file".to_string()
                    },
                    observed_at_ms,
                    sha256: None,
                    hash_source: None,
                });
            }
        }
        (observations, warnings)
    }
}

#[derive(Default)]
struct CopyBudget {
    entries: usize,
    files: usize,
    bytes: u64,
}

impl CopyBudget {
    fn add_entry(&mut self) -> SandboxResult<()> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_MAPPED_ENTRIES {
            return Err(SandboxError::new(
                "workspace",
                format!("mapped paths exceed the {MAX_MAPPED_ENTRIES}-entry limit"),
            ));
        }
        Ok(())
    }
}

fn mapping_destination(root: &Path, guest_name: &str) -> SandboxResult<PathBuf> {
    let guest_name_path = Path::new(guest_name);
    let mut components = guest_name_path.components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || crate::artifact::validate_windows_file_name_component(std::ffi::OsStr::new(guest_name))
            .is_err()
    {
        return Err(SandboxError::new(
            "workspace",
            format!("mapped path has an unsafe guest name: {guest_name}"),
        ));
    }

    let destination = root.join(guest_name_path);
    if destination.parent() != Some(root) {
        return Err(SandboxError::new(
            "workspace",
            "mapped-path destination escaped the workspace",
        ));
    }
    Ok(destination)
}

fn stage_mapping(
    mapping: &MappedPath,
    destination: &Path,
    budget: &mut CopyBudget,
) -> SandboxResult<()> {
    budget.add_entry()?;
    let supplied_path = if mapping.host_path.is_absolute() {
        mapping.host_path.clone()
    } else {
        std::env::current_dir()
            .map_err(|error| workspace_io("resolve mapped path from current directory", error))?
            .join(&mapping.host_path)
    };
    crate::artifact::validate_absolute_local_path(&supplied_path)
        .map_err(|error| workspace_io("validate supplied mapped path", error))?;
    let supplied_metadata = fs::symlink_metadata(&supplied_path)
        .map_err(|error| workspace_io("inspect supplied mapped path", error))?;
    if supplied_metadata.file_type().is_symlink() || is_reparse(&supplied_metadata) {
        return Err(SandboxError::new(
            "workspace",
            format!(
                "mapped path is a reparse point: {}",
                supplied_path.display()
            ),
        ));
    }

    if supplied_metadata.is_file() {
        let source = supplied_path.canonicalize().map_err(|error| {
            SandboxError::with_source(
                "workspace",
                format!("canonicalize mapped path {}", supplied_path.display()),
                error,
            )
        })?;
        reject_dangerous_mapping_root(&source)?;
        // open_pinned_input performs component-by-component no-follow checks and
        // copies from the resulting file handle, so a pathname swap cannot redirect
        // the staged bytes through a junction or final-component reparse point.
        copy_mapped_file(&supplied_path, destination, budget)?;
    } else if supplied_metadata.is_dir() {
        // Retain no-follow handles for every root component until the tree copy
        // completes. The handles deny delete sharing, preventing the checked root
        // or an ancestor from being replaced by a junction during staging.
        let _source_pins = crate::host_file::pin_input_directory_tree(&supplied_path)
            .map_err(|error| workspace_io("pin mapped directory tree", error))?;
        let source = supplied_path.canonicalize().map_err(|error| {
            SandboxError::with_source(
                "workspace",
                format!("canonicalize mapped path {}", supplied_path.display()),
                error,
            )
        })?;
        reject_dangerous_mapping_root(&source)?;
        fs::create_dir(destination)
            .map_err(|error| workspace_io("create mapped directory", error))?;
        copy_mapped_directory(&source, destination, budget)?;
    } else {
        return Err(SandboxError::new(
            "workspace",
            "mapped paths must be regular files or directories",
        ));
    }
    Ok(())
}

fn copy_mapped_directory(
    source_root: &Path,
    destination_root: &Path,
    budget: &mut CopyBudget,
) -> SandboxResult<()> {
    for entry in walkdir::WalkDir::new(source_root).follow_links(false) {
        let entry = entry.map_err(|error| {
            SandboxError::new("workspace", format!("walk mapped directory: {error}"))
        })?;
        if entry.path() == source_root {
            continue;
        }
        let relative = entry.path().strip_prefix(source_root).map_err(|_| {
            SandboxError::new("workspace", "mapped directory traversal escaped its root")
        })?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(SandboxError::new(
                "workspace",
                "mapped directory contains an unsafe path component",
            ));
        }
        budget.add_entry()?;
        let destination = destination_root.join(relative);
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| workspace_io("inspect mapped entry", error))?;
        if metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(SandboxError::new(
                "workspace",
                format!(
                    "mapped tree contains a reparse point: {}",
                    entry.path().display()
                ),
            ));
        }
        if metadata.is_dir() {
            fs::create_dir(&destination)
                .map_err(|error| workspace_io("create staged mapped directory", error))?;
        } else if metadata.is_file() {
            copy_mapped_file(entry.path(), &destination, budget)?;
        } else {
            return Err(SandboxError::new(
                "workspace",
                "mapped tree contains a non-file entry",
            ));
        }
    }
    Ok(())
}

fn copy_mapped_file(
    source: &Path,
    destination: &Path,
    budget: &mut CopyBudget,
) -> SandboxResult<()> {
    budget.files = budget.files.saturating_add(1);
    if budget.files > MAX_MAPPED_FILES {
        return Err(SandboxError::new(
            "workspace",
            format!("mapped paths exceed the {MAX_MAPPED_FILES}-file limit"),
        ));
    }
    let mut source = crate::host_file::open_pinned_input(source, MAX_MAPPED_BYTES)
        .map_err(|error| workspace_io("pin mapped input file", error))?;
    budget.bytes = budget
        .bytes
        .checked_add(source.len)
        .ok_or_else(|| SandboxError::new("workspace", "mapped-path byte count overflowed"))?;
    if budget.bytes > MAX_MAPPED_BYTES {
        return Err(SandboxError::new(
            "workspace",
            format!("mapped paths exceed the {MAX_MAPPED_BYTES}-byte limit"),
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| workspace_io("create staged mapped file", error))?;
    io::copy(&mut source.file, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|error| workspace_io("copy mapped input file", error))?;
    Ok(())
}

fn copy_pinned_file(source: &File, destination: &Path) -> SandboxResult<File> {
    let mut source = source
        .try_clone()
        .map_err(|error| workspace_io("clone pinned target handle", error))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| workspace_io("rewind pinned target", error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .create_new(true)
        .open(destination)
        .map_err(|error| workspace_io("create staged target", error))?;
    io::copy(&mut source, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|error| workspace_io("copy pinned target", error))?;
    Ok(output)
}

fn open_staged_target_guard(path: &Path, writer: File) -> SandboxResult<File> {
    // Hand the staged image from its writer to a strict read pin without ever allowing delete
    // sharing. The intermediate read handle permits the writer to close before the final pin
    // starts denying both new writers and deleters.
    let handoff = OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            SandboxError::with_source(
                "workspace",
                format!("retain staged target {}", path.display()),
                error,
            )
        })?;
    drop(writer);
    let guard = OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            SandboxError::with_source(
                "workspace",
                format!("pin staged target {}", path.display()),
                error,
            )
        })?;
    drop(handoff);
    Ok(guard)
}

fn validate_run_root(path: &Path) -> SandboxResult<()> {
    if !path.is_absolute() {
        return Err(SandboxError::new(
            "workspace",
            "per-run workspace root is not absolute",
        ));
    }
    reject_reparse(path)
}

fn reject_reparse(path: &Path) -> SandboxResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| workspace_io("inspect workspace path", error))?;
    if metadata.file_type().is_symlink() || is_reparse(&metadata) {
        Err(SandboxError::new(
            "workspace",
            format!("workspace path is a reparse point: {}", path.display()),
        ))
    } else {
        Ok(())
    }
}

fn reject_dangerous_mapping_root(path: &Path) -> SandboxResult<()> {
    let mut dangerous = path.parent().is_none() || path.components().count() <= 1;
    for variable in ["USERPROFILE", "WINDIR", "ProgramData", "ProgramFiles"] {
        if let Some(root) = std::env::var_os(variable)
            && crate::artifact::windows_paths_equal(path, &PathBuf::from(root))
        {
            dangerous = true;
        }
    }
    if dangerous {
        Err(SandboxError::new(
            "workspace",
            format!("refusing to map a dangerous host root: {}", path.display()),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[derive(Clone, Copy)]
enum Access {
    ReadExecute,
    Modify,
}

fn apply_tree_acl(
    root: &Path,
    sandbox_sid: &str,
    access: Access,
    current_user: &str,
) -> SandboxResult<()> {
    let metadata =
        fs::metadata(root).map_err(|error| workspace_io("inspect staged tree", error))?;
    if metadata.is_dir() {
        apply_directory_acl(root, sandbox_sid, access, current_user)?;
        for entry in walkdir::WalkDir::new(root).min_depth(1).follow_links(false) {
            let entry = entry.map_err(|error| {
                SandboxError::new("workspace", format!("walk staged ACL tree: {error}"))
            })?;
            if entry.file_type().is_dir() {
                apply_directory_acl(entry.path(), sandbox_sid, access, current_user)?;
            } else {
                apply_file_acl(entry.path(), sandbox_sid, access, current_user)?;
                if matches!(access, Access::ReadExecute) {
                    let mut permissions = fs::metadata(entry.path())
                        .map_err(|error| workspace_io("inspect read-only mapping", error))?
                        .permissions();
                    permissions.set_readonly(true);
                    fs::set_permissions(entry.path(), permissions)
                        .map_err(|error| workspace_io("mark mapping read-only", error))?;
                }
            }
        }
    } else {
        apply_file_acl(root, sandbox_sid, access, current_user)?;
    }
    Ok(())
}

fn apply_directory_acl(
    path: &Path,
    sandbox_sid: &str,
    access: Access,
    current_user: &str,
) -> SandboxResult<()> {
    let sandbox_mask = match access {
        Access::ReadExecute => "0x1200a9",
        Access::Modify => "0x1301bf",
    };
    let descriptor = format!(
        "O:{current_user}D:P(A;OICI;FA;;;{current_user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{sandbox_mask};;;{sandbox_sid})S:(ML;OICI;NW;;;LW)"
    );
    apply_acl(path, &descriptor, true)
}

fn apply_file_acl(
    path: &Path,
    sandbox_sid: &str,
    access: Access,
    current_user: &str,
) -> SandboxResult<()> {
    let sandbox_mask = match access {
        Access::ReadExecute => "0x1200a9",
        Access::Modify => "0x1301bf",
    };
    let descriptor = format!(
        "O:{current_user}D:P(A;;FA;;;{current_user})(A;;FA;;;SY)(A;;FA;;;BA)(A;;{sandbox_mask};;;{sandbox_sid})S:(ML;;NW;;;LW)"
    );
    apply_acl(path, &descriptor, true)
}

fn apply_executable_acl(
    path: &Path,
    object: &File,
    sandbox_sid: &str,
    current_user: &str,
) -> SandboxResult<()> {
    let sandbox_mask = "0x1200a9";
    // Keep executable images at medium integrity so the strict
    // IMAGE_LOAD_NO_LOW_LABEL mitigation remains compatible. The LPAC token can
    // read medium objects, while the no-write-up label and RX DACL prevent it
    // from modifying the staged image.
    let descriptor = format!(
        "O:{current_user}D:P(A;;FA;;;{current_user})(A;;FA;;;SY)(A;;FA;;;BA)(A;;{sandbox_mask};;;{sandbox_sid})S:(ML;;NW;;;ME)"
    );
    apply_acl_to_handle(path, object, &descriptor, true)
}

fn apply_host_only_acl(path: &Path, current_user: &str) -> SandboxResult<()> {
    let inheritance = if fs::metadata(path)
        .map_err(|error| workspace_io("inspect host-only path", error))?
        .is_dir()
    {
        "OICI"
    } else {
        ""
    };
    let descriptor = format!(
        "O:{current_user}D:P(A;{inheritance};FA;;;{current_user})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)"
    );
    apply_acl(path, &descriptor, false)
}

fn apply_acl(path: &Path, descriptor: &str, low_integrity: bool) -> SandboxResult<()> {
    let object = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            SandboxError::with_source(
                "workspace",
                format!("open workspace ACL target {}", path.display()),
                error,
            )
        })?;
    apply_acl_to_handle(path, &object, descriptor, low_integrity)
}

fn apply_acl_to_handle(
    path: &Path,
    object: &File,
    descriptor: &str,
    low_integrity: bool,
) -> SandboxResult<()> {
    let descriptor = descriptor
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut converted = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            SDDL_REVISION_1,
            &mut converted,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(workspace_io(
            "build workspace security descriptor",
            io::Error::last_os_error(),
        ));
    }
    let converted_guard = LocalDescriptor(converted);
    let mut information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    if low_integrity {
        information |= LABEL_SECURITY_INFORMATION;
    }

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(converted_guard.0, &mut owner, &mut owner_defaulted) }
        == 0
    {
        return Err(workspace_io(
            "read workspace ACL owner",
            io::Error::last_os_error(),
        ));
    }
    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            converted_guard.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(workspace_io(
            "read workspace DACL",
            io::Error::last_os_error(),
        ));
    }
    if owner.is_null() || dacl_present == 0 || dacl.is_null() {
        return Err(SandboxError::new(
            "workspace",
            "workspace security descriptor has no owner or DACL",
        ));
    }

    let mut sacl = std::ptr::null_mut();
    if low_integrity {
        let mut sacl_present = 0;
        let mut sacl_defaulted = 0;
        if unsafe {
            GetSecurityDescriptorSacl(
                converted_guard.0,
                &mut sacl_present,
                &mut sacl,
                &mut sacl_defaulted,
            )
        } == 0
        {
            return Err(workspace_io(
                "read workspace mandatory label",
                io::Error::last_os_error(),
            ));
        }
        if sacl_present == 0 || sacl.is_null() {
            return Err(SandboxError::new(
                "workspace",
                "workspace security descriptor has no mandatory label",
            ));
        }
    }

    let status = unsafe {
        SetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
            owner,
            std::ptr::null_mut(),
            dacl,
            sacl,
        )
    };
    if status != 0 {
        return Err(SandboxError::with_source(
            "workspace",
            format!("apply restrictive workspace ACL to {}", path.display()),
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    Ok(())
}

struct LocalDescriptor(*mut c_void);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn workspace_io(
    operation: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> SandboxError {
    SandboxError::with_source("workspace", operation, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "foxhole-workspace-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&path).expect("create temporary directory");
        path
    }

    #[test]
    fn run_root_must_be_absolute_existing_and_not_reparse() {
        assert!(validate_run_root(Path::new("relative")).is_err());
        let missing = std::env::temp_dir().join("foxhole-workspace-definitely-missing");
        assert!(validate_run_root(&missing).is_err());

        let root = temporary_directory("plain-root");
        assert!(validate_run_root(&root).is_ok());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn dangerous_host_roots_are_rejected() {
        assert!(reject_dangerous_mapping_root(Path::new(r"C:\")).is_err());
        let profile = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
        assert!(reject_dangerous_mapping_root(&profile).is_err());

        let safe = temporary_directory("safe-map");
        assert!(reject_dangerous_mapping_root(&safe).is_ok());
        fs::remove_dir(safe).unwrap();
    }

    #[test]
    fn copy_budget_limits_fail_before_unsafe_expansion() {
        let root = temporary_directory("budget");
        let source = root.join("source.bin");
        let destination = root.join("destination.bin");
        fs::write(&source, b"data").unwrap();

        let mut files_exhausted = CopyBudget {
            entries: 0,
            files: MAX_MAPPED_FILES,
            bytes: 0,
        };
        assert!(copy_mapped_file(&source, &destination, &mut files_exhausted).is_err());

        let mut bytes_overflow = CopyBudget {
            entries: 0,
            files: 0,
            bytes: u64::MAX,
        };
        assert!(copy_mapped_file(&source, &destination, &mut bytes_overflow).is_err());

        fs::remove_file(source).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn mapped_destinations_require_one_safe_windows_component() {
        let root = Path::new(r"C:\sandbox\mapped");
        assert_eq!(
            mapping_destination(root, "safe-name_1.json").unwrap(),
            root.join("safe-name_1.json")
        );
        for guest_name in [
            "C:escape",
            "file:stream",
            "CON",
            "NUL.txt",
            "trailing.",
            "trailing ",
            ".",
            "..",
            r"nested\name",
        ] {
            assert!(
                mapping_destination(root, guest_name).is_err(),
                "unsafe mapping name should fail at the workspace boundary: {guest_name}"
            );
        }
    }

    #[test]
    fn empty_directories_consume_the_mapped_entry_budget() {
        let root = temporary_directory("entry-budget");
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("empty-child")).unwrap();
        let mapping = MappedPath {
            host_path: source,
            guest_name: "bounded".into(),
            access: MappedPathAccess::ReadOnly,
        };
        let mut budget = CopyBudget {
            entries: MAX_MAPPED_ENTRIES - 1,
            ..CopyBudget::default()
        };

        let error = stage_mapping(&mapping, &destination, &mut budget)
            .expect_err("the empty child must exceed the total entry budget");
        assert!(error.to_string().contains("entry limit"));
        assert!(!destination.join("empty-child").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stages_file_and_directory_mappings_and_observes_outputs() {
        let root = temporary_directory("staging");
        let mapped_file = root.join("mapped-file.txt");
        let mapped_dir = root.join("mapped-dir");
        fs::write(&mapped_file, b"file").unwrap();
        fs::create_dir(&mapped_dir).unwrap();
        fs::write(mapped_dir.join("nested.txt"), b"nested").unwrap();

        let staged_file = root.join("staged-file.txt");
        let staged_dir = root.join("staged-dir");
        let mut budget = CopyBudget::default();
        stage_mapping(
            &MappedPath {
                host_path: mapped_file.clone(),
                guest_name: "file".into(),
                access: MappedPathAccess::ReadOnly,
            },
            &staged_file,
            &mut budget,
        )
        .unwrap();
        stage_mapping(
            &MappedPath {
                host_path: mapped_dir.clone(),
                guest_name: "dir".into(),
                access: MappedPathAccess::ReadWrite,
            },
            &staged_dir,
            &mut budget,
        )
        .unwrap();
        assert_eq!(fs::read(&staged_file).unwrap(), b"file");
        assert_eq!(fs::read(staged_dir.join("nested.txt")).unwrap(), b"nested");
        assert_eq!(budget.files, 2);

        let current_user = crate::artifact::current_user_sid_string().unwrap();
        apply_tree_acl(
            &staged_dir,
            &current_user,
            Access::ReadExecute,
            &current_user,
        )
        .unwrap();
        assert!(
            fs::metadata(staged_dir.join("nested.txt"))
                .unwrap()
                .permissions()
                .readonly()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn workspace_creation_applies_acls_metadata_and_observations() {
        let root = temporary_directory("create");
        let run_root = root.join("run");
        fs::create_dir(&run_root).unwrap();
        let target_path = root.join("target.exe");
        fs::write(&target_path, b"target").unwrap();
        let target = File::open(&target_path).unwrap();
        let mapping_path = root.join("mapping.txt");
        fs::write(&mapping_path, b"mapping").unwrap();

        let mut request = SandboxRequest::restricted(&target_path);
        request.mapped_paths.push(MappedPath {
            host_path: mapping_path,
            guest_name: "data".into(),
            access: MappedPathAccess::ReadOnly,
        });
        let sid = crate::artifact::current_user_sid_string().unwrap();
        let workspace = Workspace::create(
            &run_root,
            &target,
            std::ffi::OsStr::new("target.exe"),
            &sid,
            &request,
        )
        .expect("workspace creation");
        assert!(workspace.target.exists());
        assert!(
            fs::remove_file(&workspace.target).is_err(),
            "the staged target must remain deletion-pinned until launch preparation finishes"
        );
        assert!(workspace.root.join("metadata.json").exists());
        assert_eq!(workspace.mappings.len(), 1);

        fs::write(workspace.work.join("created.txt"), b"created").unwrap();
        fs::create_dir(workspace.output.join("folder")).unwrap();
        let (observations, warnings) = workspace.file_observations(123);
        assert!(warnings.is_empty());
        assert!(
            observations
                .iter()
                .any(|item| item.relative_path == "work/created.txt")
        );
        assert!(observations.iter().all(|item| item.observed_at_ms == 123));

        drop(workspace);
        drop(target);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_acl_and_missing_tree_fail_closed() {
        let root = temporary_directory("acl-failure");
        assert!(apply_directory_acl(&root, "not-a-sid", Access::Modify, "not-a-sid").is_err());
        assert!(
            apply_tree_acl(&root.join("missing"), "S-1-1-0", Access::Modify, "S-1-1-0").is_err()
        );
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn workspace_acl_supports_a_long_handle_path() {
        let root = temporary_directory("long-acl");
        let mut nested = root.clone();
        while nested.as_os_str().len() < 300 {
            nested.push("appcontainer-profile-storage-component");
        }
        fs::create_dir_all(&nested).unwrap();
        let sid = crate::artifact::current_user_sid_string().unwrap();
        apply_directory_acl(&nested, &sid, Access::Modify, &sid)
            .expect("apply ACL through a canonical long path");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlink_mapping_is_rejected_when_available() {
        use std::os::windows::fs::symlink_file;

        let root = temporary_directory("symlink");
        let target = root.join("target.txt");
        let link = root.join("link.txt");
        fs::write(&target, b"target").unwrap();
        if symlink_file(&target, &link).is_ok() {
            let mut budget = CopyBudget::default();
            let mapping = MappedPath {
                host_path: link.clone(),
                guest_name: "link".into(),
                access: MappedPathAccess::ReadOnly,
            };
            assert!(stage_mapping(&mapping, &root.join("staged"), &mut budget).is_err());
            fs::remove_file(link).unwrap();
        }
        fs::remove_file(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn symlinked_mapping_directory_and_ancestor_are_rejected_when_available() {
        use std::os::windows::fs::symlink_dir;

        let root = temporary_directory("directory-symlink");
        let target = root.join("real-parent");
        let nested = target.join("nested");
        let link = root.join("linked-parent");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("input.txt"), b"target").unwrap();

        if symlink_dir(&target, &link).is_ok() {
            for host_path in [link.clone(), link.join("nested")] {
                let mapping = MappedPath {
                    host_path,
                    guest_name: "linked".into(),
                    access: MappedPathAccess::ReadOnly,
                };
                assert!(
                    stage_mapping(&mapping, &root.join("staged"), &mut CopyBudget::default())
                        .is_err(),
                    "both a reparse root and a reparse ancestor must fail closed"
                );
            }
            fs::remove_dir(link).unwrap();
        }

        fs::remove_dir_all(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn mapping_and_acl_error_paths_are_explicit() {
        let root = temporary_directory("more-errors");
        let missing_mapping = MappedPath {
            host_path: root.join("missing"),
            guest_name: "missing".into(),
            access: MappedPathAccess::ReadOnly,
        };
        assert!(
            stage_mapping(
                &missing_mapping,
                &root.join("destination"),
                &mut CopyBudget::default()
            )
            .is_err()
        );

        let file = root.join("file.txt");
        fs::write(&file, b"file").unwrap();
        let occupied = root.join("occupied.txt");
        fs::write(&occupied, b"occupied").unwrap();
        assert!(copy_mapped_file(&file, &occupied, &mut CopyBudget::default()).is_err());
        let pinned = File::open(&file).unwrap();
        assert!(copy_pinned_file(&pinned, &occupied).is_err());
        let sid = crate::artifact::current_user_sid_string().unwrap();
        apply_tree_acl(&file, &sid, Access::Modify, &sid).unwrap();
        apply_tree_acl(&file, &sid, Access::ReadExecute, &sid).unwrap();
        apply_host_only_acl(&file, &sid).unwrap();
        assert!(apply_acl(&root.join("missing"), &format!("D:P(A;;GA;;;{sid})"), false).is_err());

        let workspace = Workspace {
            root: root.clone(),
            work: root.join("missing-work"),
            output: root.join("missing-output"),
            target: file.clone(),
            mappings: Vec::new(),
            _target_guard: None,
        };
        let (observations, warnings) = workspace.file_observations(1);
        assert!(observations.is_empty());
        assert!(!warnings.is_empty());

        drop(pinned);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn observation_rejects_reparse_entries_when_available() {
        use std::os::windows::fs::symlink_file;

        let root = temporary_directory("observe-link");
        let work = root.join("work");
        let output = root.join("output");
        fs::create_dir(&work).unwrap();
        fs::create_dir(&output).unwrap();
        let outside = root.join("outside.txt");
        let link = work.join("link.txt");
        fs::write(&outside, b"outside").unwrap();
        let workspace = Workspace {
            root: root.clone(),
            work,
            output,
            target: root.join("target.exe"),
            mappings: Vec::new(),
            _target_guard: None,
        };
        if symlink_file(&outside, &link).is_ok() {
            let (_, warnings) = workspace.file_observations(1);
            assert!(warnings.iter().any(|warning| warning.contains("reparse")));
            fs::remove_file(link).unwrap();
        }
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
