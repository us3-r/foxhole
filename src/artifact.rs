use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_VIRUSTOTAL_RESULT_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum number of regular files retained below Foxhole's protected artifact root.
/// In-progress sibling temporary files count toward this ceiling.
pub const MAX_ARTIFACT_FILES: u64 = 512;
/// Maximum aggregate logical size of regular files below the protected artifact root.
/// In-progress sibling temporary files count toward this ceiling.
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

// Bound traversal even if the protected tree is unexpectedly pre-populated with directories or
// unsupported entries.
const MAX_ARTIFACT_TREE_ENTRIES: u64 = 4_096;
const ARTIFACT_LIMITS: ArtifactLimits = ArtifactLimits {
    maximum_files: MAX_ARTIFACT_FILES,
    maximum_bytes: MAX_ARTIFACT_BYTES,
    maximum_entries: MAX_ARTIFACT_TREE_ENTRIES,
};

// Prevent concurrent writers in this process from validating the same usage snapshot.
static ARTIFACT_PUBLICATION_LOCK: Mutex<()> = Mutex::new(());
static CONFIGURED_ARTIFACT_ROOT: OnceLock<PathBuf> = OnceLock::new();

const APPLICATION_DIRECTORY: &str = "Foxhole";
const ARTIFACT_DIRECTORY: &str = "artifacts";

#[cfg(target_os = "windows")]
fn local_app_data_path() -> io::Result<PathBuf> {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // FOLDERID_LocalAppData: {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
    const FOLDER_ID_LOCAL_APP_DATA: Guid = Guid {
        data1: 0xf1b3_2785,
        data2: 0x6fba,
        data3: 0x4fcf,
        data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
    };

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHGetKnownFolderPath(
            folder_id: *const Guid,
            flags: u32,
            token: *mut c_void,
            path: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoTaskMemFree(memory: *mut c_void);
    }

    let mut value = std::ptr::null_mut();
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDER_ID_LOCAL_APP_DATA,
            0,
            std::ptr::null_mut(),
            &mut value,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "SHGetKnownFolderPath(FOLDERID_LocalAppData) failed with HRESULT 0x{:08x}",
            status as u32
        )));
    }
    if value.is_null() {
        return Err(io::Error::other(
            "SHGetKnownFolderPath returned an empty LocalAppData path",
        ));
    }

    let mut length = 0usize;
    while length < 32_768 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    let result = if length == 32_768 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LocalAppData path is not null terminated",
        ))
    } else {
        let wide = unsafe { std::slice::from_raw_parts(value, length) };
        Ok(PathBuf::from(OsString::from_wide(wide)))
    };
    unsafe {
        CoTaskMemFree(value.cast());
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn local_app_data_path() -> io::Result<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "LOCALAPPDATA is unavailable; refusing to write artifacts to a fallback directory",
            )
        })
}

#[cfg(target_os = "windows")]
pub(crate) fn verify_local_fixed_volume(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const DRIVE_FIXED: u32 = 3;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetVolumePathNameW(file_name: *const u16, volume_path: *mut u16, length: u32) -> i32;
        fn GetDriveTypeW(root_path: *const u16) -> u32;
    }

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut volume = vec![0u16; 32_768];
    if unsafe { GetVolumePathNameW(path.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { GetDriveTypeW(volume.as_ptr()) } != DRIVE_FIXED {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Foxhole's artifact root must be on a fixed local volume",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn verify_local_fixed_volume(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Returns Foxhole's application-owned artifact root.
///
/// Keeping broker-written data below LocalAppData prevents an AppContainer target from choosing
/// or pre-seeding the destination. Every component is checked for links/reparse points before it
/// is used.
pub fn artifact_root() -> io::Result<PathBuf> {
    if let Some(root) = CONFIGURED_ARTIFACT_ROOT.get() {
        return prepare_artifact_root(root.clone());
    }

    let local_app_data = local_app_data_path()?;
    validate_absolute_local_path(&local_app_data)?;
    verify_local_fixed_volume(&local_app_data)?;
    let _base_pins = pin_safe_directory_tree(&local_app_data, false)?;

    let application_root = local_app_data.join(APPLICATION_DIRECTORY);
    let root = application_root.join(ARTIFACT_DIRECTORY);
    // Parent FILE_DELETE_CHILD rights can otherwise remove a protected child, so the
    // application-owned parent and the artifact root must both be protected while pinned.
    let _application_pins = pin_safe_directory_tree(&application_root, true)?;
    harden_artifact_acl(&application_root)?;
    prepare_artifact_root(root)
}

/// Use a caller-selected directory as Foxhole's artifact and log root.
///
/// This is intentionally process-wide: all artifact-producing subsystems resolve their paths
/// through `artifact_root`, so configuring it once at CLI startup keeps reports, Hyper-V run
/// data, and cleanup logs together.
pub fn configure_artifact_root(path: &Path) -> io::Result<()> {
    validate_absolute_local_path(path)?;
    verify_local_fixed_volume(path)?;
    let path = path.to_path_buf();
    match CONFIGURED_ARTIFACT_ROOT.set(path.clone()) {
        Ok(()) => Ok(()),
        Err(_) if CONFIGURED_ARTIFACT_ROOT.get() == Some(&path) => Ok(()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Foxhole's artifact root was already configured to a different path",
        )),
    }
}

fn prepare_artifact_root(root: PathBuf) -> io::Result<PathBuf> {
    validate_absolute_local_path(&root)?;
    verify_local_fixed_volume(&root)?;
    let _root_pins = pin_safe_directory_tree(&root, true)?;
    harden_artifact_acl(&root)?;
    Ok(root)
}

/// Remove the default artifact and log directories only.
///
/// This deliberately does not consult `CONFIGURED_ARTIFACT_ROOT`, so `--clean-up --output X`
/// always leaves X untouched. The default Foxhole application directory and unrelated files in
/// LocalAppData are preserved.
#[cfg(target_os = "windows")]
pub fn clean_default_artifacts_and_logs() -> io::Result<Vec<PathBuf>> {
    let local_app_data = local_app_data_path()?;
    validate_absolute_local_path(&local_app_data)?;
    verify_local_fixed_volume(&local_app_data)?;
    let _base_pins = pin_safe_directory_tree(&local_app_data, false)?;

    let default_root = local_app_data.join(APPLICATION_DIRECTORY);
    clean_artifacts_and_logs_at(&default_root)
}

#[cfg(not(target_os = "windows"))]
pub fn clean_default_artifacts_and_logs() -> io::Result<Vec<PathBuf>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "default Foxhole cleanup is supported only on Windows because safe recursive deletion relies on Windows handle pinning",
    ))
}

fn clean_artifacts_and_logs_at(default_root: &Path) -> io::Result<Vec<PathBuf>> {
    validate_absolute_local_path(default_root)?;

    match fs::symlink_metadata(default_root) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    // Hold the entire application-owned ancestry without delete sharing for the duration of the
    // cleanup. This rejects an attacker-created intermediate junction and prevents a validated
    // component from being exchanged before either recursive removal completes.
    let _application_pins = pin_safe_directory_tree(default_root, false)?;
    verify_local_fixed_volume(default_root)?;

    let mut removed = Vec::new();
    for name in [ARTIFACT_DIRECTORY, "logs"] {
        let path = default_root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_directory_metadata(&path, &metadata)?;
                fs::remove_dir_all(&path)?;
                removed.push(path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(removed)
}

/// Atomically replace a generated file below a pinned, link-free output root.
///
/// Analysis reports are intentionally reproducible and therefore replace prior generated output.
/// The unpredictable create-new temporary file prevents pre-positioned links, while the pinned
/// directory ancestry prevents a checked parent from being redirected before publication.
pub(crate) fn secure_replace_in<F>(
    root: &Path,
    relative: &Path,
    maximum_bytes: u64,
    write: F,
) -> io::Result<PathBuf>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    validate_absolute_local_path(root)?;
    validate_relative_artifact_path(relative)?;
    if maximum_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "generated output size limit must be greater than zero",
        ));
    }

    let destination = root.join(relative);
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "generated output destination has no parent directory",
        )
    })?;
    let _pins = pin_safe_directory_tree(parent, true)?;
    let (temporary_path, temporary_file) = create_temporary_file(parent)?;
    let mut cleanup = TemporaryFileGuard::new(temporary_path.clone());
    let mut writer = LimitedWriter::new(temporary_file, maximum_bytes);
    write(&mut writer)?;
    writer.flush()?;
    writer.file.sync_all()?;
    drop(writer);

    move_file_replace(&temporary_path, &destination)?;
    cleanup.committed = true;
    Ok(destination)
}

pub fn report_destination(requested: Option<&Path>, target: &Path) -> io::Result<PathBuf> {
    let relative = match requested {
        Some(path) => {
            validate_relative_artifact_path(path)?;
            path.to_path_buf()
        }
        None => {
            let stem = target
                .file_stem()
                .and_then(OsStr::to_str)
                .map(sanitize_stem)
                .filter(|stem| !stem.is_empty())
                .unwrap_or_else(|| "sample".to_string());
            PathBuf::from(format!("fh_{stem}_{}.json", random_hex(12)?))
        }
    };

    Ok(artifact_root()?.join("reports").join(relative))
}

pub fn virustotal_result_destination() -> io::Result<PathBuf> {
    Ok(artifact_root()?
        .join("virustotal")
        .join(format!("vt_result_{}.json", random_hex(12)?)))
}

pub(crate) fn ensure_canonical_path_outside_artifact_root(
    input: &Path,
    description: &str,
) -> io::Result<()> {
    let root = artifact_root()?.canonicalize()?;
    if path_is_within(input, &root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{description} cannot be inside Foxhole's artifact root ({})",
                root.display()
            ),
        ));
    }
    Ok(())
}

pub fn secure_write_new<F>(destination: &Path, maximum_bytes: u64, write: F) -> io::Result<PathBuf>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    let root = artifact_root()?;
    let relative = destination.strip_prefix(&root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("artifact destination must be inside {}", root.display()),
        )
    })?;
    secure_write_new_in(&root, relative, maximum_bytes, write)
}

fn secure_write_new_in<F>(
    root: &Path,
    relative: &Path,
    maximum_bytes: u64,
    write: F,
) -> io::Result<PathBuf>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    secure_write_new_in_with_limits(root, relative, maximum_bytes, ARTIFACT_LIMITS, write)
}

#[derive(Clone, Copy)]
struct ArtifactLimits {
    maximum_files: u64,
    maximum_bytes: u64,
    maximum_entries: u64,
}

fn secure_write_new_in_with_limits<F>(
    root: &Path,
    relative: &Path,
    maximum_bytes: u64,
    limits: ArtifactLimits,
    write: F,
) -> io::Result<PathBuf>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    validate_absolute_local_path(root)?;
    validate_relative_artifact_path(relative)?;

    let destination = root.join(relative);
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact destination has no parent directory",
        )
    })?;

    // These handles intentionally omit FILE_SHARE_DELETE on Windows. Holding them until the
    // final move pins the checked directory chain so it cannot be swapped for a junction.
    let _pins = pin_safe_directory_tree(parent, true)?;
    harden_owned_directory_chain(root, parent)?;
    let _publication_guard = ARTIFACT_PUBLICATION_LOCK
        .lock()
        .map_err(|_| io::Error::other("artifact publication lock is poisoned"))?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to overwrite existing artifact {}",
                    destination.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (temporary_path, temporary_file) = create_temporary_file(parent)?;
    let mut cleanup = TemporaryFileGuard::new(temporary_path.clone());
    if let Err(error) = harden_artifact_acl(&temporary_path) {
        // TemporaryFileGuard unlinks by path. Close the share-mode-zero handle first so its
        // cleanup cannot silently fail and leave an orphan when ACL hardening is rejected.
        drop(temporary_file);
        return Err(error);
    }
    let mut writer = LimitedWriter::new(temporary_file, maximum_bytes);

    write(&mut writer)?;
    writer.flush()?;
    writer.file.sync_all()?;
    drop(writer);

    // The temporary file is deliberately included: renaming it does not change the protected
    // tree's file count or byte usage. On rejection, TemporaryFileGuard removes only this
    // unpublished temporary file and preserves every existing user-visible artifact.
    enforce_artifact_ceiling(root, limits)?;
    move_file_no_replace(&temporary_path, &destination)?;
    cleanup.committed = true;
    Ok(destination)
}

fn enforce_artifact_ceiling(root: &Path, limits: ArtifactLimits) -> io::Result<()> {
    if limits.maximum_files == 0 || limits.maximum_bytes == 0 || limits.maximum_entries == 0 {
        return Err(io::Error::other(
            "artifact retention limits must be greater than zero",
        ));
    }

    let mut directories = vec![root.to_path_buf()];
    let mut directory_pins = Vec::new();
    let mut entry_count = 0u64;
    let mut file_count = 0u64;
    let mut total_bytes = 0u64;

    while let Some(directory) = directories.pop() {
        let pin = pin_plain_directory(&directory)?;
        directory_pins.push(pin);

        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            validate_file_name_component(&entry.file_name())?;
            entry_count = entry_count.checked_add(1).ok_or_else(|| {
                io::Error::other("artifact tree entry count overflowed while enforcing retention")
            })?;
            if entry_count > limits.maximum_entries {
                return Err(io::Error::other(format!(
                    "artifact tree contains more than {} entries; refusing publication",
                    limits.maximum_entries
                )));
            }

            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            reject_reparse_or_symlink(&path, &metadata)?;
            if metadata.is_dir() {
                directories.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "artifact tree contains an unsupported entry: {}",
                        path.display()
                    ),
                ));
            }

            file_count = file_count.checked_add(1).ok_or_else(|| {
                io::Error::other("artifact file count overflowed while enforcing retention")
            })?;
            total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                io::Error::other("artifact byte count overflowed while enforcing retention")
            })?;
            if file_count > limits.maximum_files || total_bytes > limits.maximum_bytes {
                return Err(io::Error::other(format!(
                    "artifact retention ceiling exceeded (files: {file_count}/{}, bytes: {total_bytes}/{})",
                    limits.maximum_files, limits.maximum_bytes
                )));
            }
        }
    }

    // Make the intended handle lifetime explicit: every traversed directory remains pinned until
    // the complete usage snapshot has been accepted.
    drop(directory_pins);
    Ok(())
}

fn pin_plain_directory(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    validate_directory_metadata(path, &metadata)?;
    let expected_path = fs::canonicalize(path)?;
    let pin = open_directory_pin(path)?;
    verify_directory_handle_path(&pin, &expected_path)?;
    validate_directory_metadata(path, &fs::symlink_metadata(path)?)?;
    Ok(pin)
}

fn reject_reparse_or_symlink(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("artifact tree contains a symbolic link: {}", path.display()),
        ));
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("artifact tree contains a reparse point: {}", path.display()),
            ));
        }
    }

    Ok(())
}

fn create_temporary_file(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..32 {
        let path = parent.join(format!(".foxhole-{}.tmp", random_hex(16)?));
        match open_exclusive_temporary_file(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique artifact temporary file",
    ))
}

#[cfg(target_os = "windows")]
fn open_exclusive_temporary_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
}

#[cfg(not(target_os = "windows"))]
fn open_exclusive_temporary_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn validate_relative_artifact_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path must be a non-empty relative path",
        ));
    }

    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                validate_file_name_component(name)?;
                saw_component = true;
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "artifact paths cannot contain roots, prefixes, '.' or '..'",
                ));
            }
        }
    }

    if !saw_component {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path must contain a file name",
        ));
    }
    Ok(())
}

pub(crate) fn validate_file_name_component(name: &OsStr) -> io::Result<()> {
    validate_file_name_component_common(name)?;

    #[cfg(target_os = "windows")]
    validate_windows_file_name_rules(name)?;

    Ok(())
}

pub(crate) fn validate_windows_file_name_component(name: &OsStr) -> io::Result<()> {
    validate_file_name_component_common(name)?;
    validate_windows_file_name_rules(name)
}

fn validate_file_name_component_common(name: &OsStr) -> io::Result<()> {
    let value = name.to_string_lossy();
    let contains_terminal_control = value.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    });
    if value.is_empty() || value.len() > 240 || contains_terminal_control {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path contains an invalid component",
        ));
    }

    Ok(())
}

fn validate_windows_file_name_rules(name: &OsStr) -> io::Result<()> {
    let value = name.to_string_lossy();
    if value.contains(['<', '>', '"', ':', '|', '?', '*']) || value.ends_with(['.', ' ']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path contains a Windows device/stream component",
        ));
    }

    let base = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || base
        .strip_prefix("COM")
        .or_else(|| base.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            (suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
                || matches!(suffix, "¹" | "²" | "³")
        });
    if reserved {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path uses a reserved Windows device name",
        ));
    }
    Ok(())
}

pub(crate) fn validate_absolute_local_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not absolute: {}", path.display()),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute artifact paths cannot contain '.' or '..'",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        use std::path::Prefix;

        let prefix = path.components().next();
        let is_local_drive = matches!(
            prefix,
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        );
        if !is_local_drive {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact root must be on a local drive",
            ));
        }
    }

    Ok(())
}

pub(crate) fn pin_safe_directory_tree(path: &Path, create_missing: bool) -> io::Result<Vec<File>> {
    validate_absolute_local_path(path)?;
    let mut current = PathBuf::new();
    let mut pins = Vec::new();

    for component in path.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create_missing => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                fs::symlink_metadata(&current)?
            }
            Err(error) => return Err(error),
        };
        validate_directory_metadata(&current, &metadata)?;

        let expected_path = fs::canonicalize(&current)?;
        let pin = open_directory_pin(&current)?;
        verify_directory_handle_path(&pin, &expected_path)?;
        // Recheck after opening. Since the pin denies delete-sharing on Windows, a validated
        // component cannot be replaced for the remainder of the write.
        validate_directory_metadata(&current, &fs::symlink_metadata(&current)?)?;
        pins.push(pin);
    }

    Ok(pins)
}

/// Open one existing regular file without following a final link or allowing its checked parent
/// to be exchanged during the open. The returned handle remains bound to the checked object.
pub(crate) fn open_safe_regular_file(path: &Path) -> io::Result<File> {
    validate_absolute_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file path has no parent directory",
        )
    })?;
    let _pins = pin_safe_directory_tree(parent, false)?;
    let before = fs::symlink_metadata(path)?;
    reject_reparse_or_symlink(path, &before)?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("path is not a regular file: {}", path.display()),
        ));
    }

    let expected_path = fs::canonicalize(path)?;
    let file = open_regular_file_no_follow(path)?;
    let opened = file.metadata()?;
    reject_reparse_or_symlink(path, &opened)?;
    if !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened path is not a regular file: {}", path.display()),
        ));
    }
    reject_multiple_links(&file, path)?;
    verify_file_handle_path(&file, &expected_path)?;
    Ok(file)
}

/// Open a single-link regular file for deletion by its verified handle. This is Windows-specific
/// security machinery used by Hyper-V cleanup; other platforms retain a checked best-effort path.
pub(crate) fn open_safe_regular_file_for_delete(path: &Path) -> io::Result<File> {
    validate_absolute_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file path has no parent directory",
        )
    })?;
    let _pins = pin_safe_directory_tree(parent, false)?;
    let before = fs::symlink_metadata(path)?;
    reject_reparse_or_symlink(path, &before)?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("path is not a regular file: {}", path.display()),
        ));
    }
    let expected_path = fs::canonicalize(path)?;
    let file = open_regular_file_for_delete(path)?;
    let opened = file.metadata()?;
    reject_reparse_or_symlink(path, &opened)?;
    if !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened path is not a regular file: {}", path.display()),
        ));
    }
    reject_multiple_links(&file, path)?;
    verify_file_handle_path(&file, &expected_path)?;
    Ok(file)
}

/// Pin a regular file while an external subsystem inspects it by pathname. The Windows handle
/// deliberately shares DELETE so an inspector such as Hyper-V can request whatever access it
/// needs; callers must subsequently reopen for deletion and compare file identities.
pub(crate) fn open_safe_regular_file_for_external_inspection(path: &Path) -> io::Result<File> {
    validate_absolute_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file path has no parent directory",
        )
    })?;
    let _pins = pin_safe_directory_tree(parent, false)?;
    let before = fs::symlink_metadata(path)?;
    reject_reparse_or_symlink(path, &before)?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("path is not a regular file: {}", path.display()),
        ));
    }

    let expected_path = fs::canonicalize(path)?;
    let file = open_regular_file_for_external_inspection(path)?;
    let opened = file.metadata()?;
    reject_reparse_or_symlink(path, &opened)?;
    if !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened path is not a regular file: {}", path.display()),
        ));
    }
    reject_multiple_links(&file, path)?;
    verify_file_handle_path(&file, &expected_path)?;
    Ok(file)
}

/// Reopen a previously inspected pathname with delete access and prove that it still identifies
/// the same file. This closes the path-swap window without holding DELETE access during external
/// VHD inspection.
pub(crate) fn open_safe_regular_file_for_delete_matching(
    path: &Path,
    inspected: &File,
) -> io::Result<File> {
    let file = open_safe_regular_file_for_delete(path)?;
    if !same_file_identity(inspected, &file)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "file identity changed after external inspection: {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(target_os = "windows")]
fn reject_multiple_links(file: &File, path: &Path) -> io::Result<()> {
    if windows_number_of_links(file)? != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened file has multiple links: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn reject_multiple_links(file: &File, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if file.metadata()?.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened file has multiple links: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", unix)))]
fn reject_multiple_links(_file: &File, _path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WindowsFileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WindowsFileInformation {
    file_attributes: u32,
    creation_time: WindowsFileTime,
    last_access_time: WindowsFileTime,
    last_write_time: WindowsFileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(target_os = "windows")]
fn windows_file_information(file: &File) -> io::Result<WindowsFileInformation> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut WindowsFileInformation,
        ) -> i32;
    }

    let mut information = WindowsFileInformation::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

#[cfg(target_os = "windows")]
fn windows_number_of_links(file: &File) -> io::Result<u32> {
    Ok(windows_file_information(file)?.number_of_links)
}

#[cfg(target_os = "windows")]
fn open_regular_file_for_delete(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(target_os = "windows")]
fn open_regular_file_for_external_inspection(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(target_os = "windows"))]
fn open_regular_file_for_external_inspection(path: &Path) -> io::Result<File> {
    open_regular_file_no_follow(path)
}

#[cfg(target_os = "windows")]
fn same_file_identity(left: &File, right: &File) -> io::Result<bool> {
    let left = windows_file_information(left)?;
    let right = windows_file_information(right)?;
    Ok(left.volume_serial_number == right.volume_serial_number
        && left.file_index_high == right.file_index_high
        && left.file_index_low == right.file_index_low)
}

#[cfg(unix)]
fn same_file_identity(left: &File, right: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(any(target_os = "windows", unix)))]
fn same_file_identity(_left: &File, _right: &File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file identity comparison is unavailable on this platform",
    ))
}

#[cfg(not(target_os = "windows"))]
fn open_regular_file_for_delete(path: &Path) -> io::Result<File> {
    open_regular_file_no_follow(path)
}

#[cfg(target_os = "windows")]
pub(crate) fn delete_open_file(file: &File, _path: &Path) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: i32,
    }
    const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            file: *mut c_void,
            information_class: u32,
            information: *const c_void,
            size: u32,
        ) -> i32;
    }

    let disposition = FileDispositionInfo { delete_file: 1 };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FILE_DISPOSITION_INFO_CLASS,
            (&disposition as *const FileDispositionInfo).cast(),
            std::mem::size_of::<FileDispositionInfo>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn delete_open_file(file: &File, path: &Path) -> io::Result<()> {
    let _ = file;
    fs::remove_file(path)
}

#[cfg(target_os = "windows")]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(target_os = "linux")]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    open(path, OFlag::O_RDONLY | OFlag::O_NOFOLLOW, Mode::empty())
        .map(File::from)
        .map_err(io::Error::other)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(target_os = "windows")]
fn verify_file_handle_path(file: &File, expected: &Path) -> io::Result<()> {
    let opened = final_path_by_handle(file)?;
    if !windows_paths_equal(&opened, expected) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "opened file does not match checked path: {}",
                expected.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn verify_file_handle_path(_file: &File, _expected: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn verify_directory_handle_path(directory: &File, expected: &Path) -> io::Result<()> {
    let opened = final_path_by_handle(directory)?;
    if !windows_paths_equal(&opened, expected) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "opened artifact directory does not match checked path: {}",
                expected.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn verify_directory_handle_path(_directory: &File, _expected: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn final_path_by_handle(file: &File) -> io::Result<PathBuf> {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;

    const FILE_NAME_NORMALIZED: u32 = 0;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            file: *mut c_void,
            path: *mut u16,
            path_length: u32,
            flags: u32,
        ) -> u32;
    }

    let mut buffer = vec![0u16; 512];
    loop {
        let written = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                FILE_NAME_NORMALIZED,
            )
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        let written = written as usize;
        if written < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..written])));
        }
        buffer.resize(written.saturating_add(1), 0);
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    fn normalized(path: &Path) -> String {
        let value = path.to_string_lossy().replace('/', "\\");
        let value = value
            .strip_prefix(r"\\?\UNC\")
            .map(|suffix| format!(r"\\{suffix}"))
            .or_else(|| value.strip_prefix(r"\\?\").map(str::to_owned))
            .unwrap_or(value);
        value.trim_end_matches('\\').to_lowercase()
    }

    normalized(left) == normalized(right)
}

fn validate_directory_metadata(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "artifact directory component is not a plain directory: {}",
                path.display()
            ),
        ));
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "artifact directory component is a reparse point: {}",
                    path.display()
                ),
            ));
        }
    }

    Ok(())
}

pub(crate) fn harden_owned_directory_chain(
    root: &Path,
    destination_parent: &Path,
) -> io::Result<()> {
    let relative = destination_parent.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "artifact parent escaped the application-owned root",
        )
    })?;
    harden_artifact_acl(root)?;

    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact directory chain contains a non-normal component",
            ));
        };
        current.push(name);
        harden_artifact_acl(&current)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn harden_artifact_acl(path: &Path) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    const SDDL_REVISION_1: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security_descriptor: *const u16,
            revision: u32,
            converted: *mut *mut c_void,
            converted_size: *mut u32,
        ) -> i32;
        fn SetFileSecurityW(
            file_name: *const u16,
            security_information: u32,
            security_descriptor: *const c_void,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    // Name the actual broker user rather than OWNER RIGHTS. A pre-seeded directory could be owned
    // by an AppContainer SID; granting its owner access would preserve the attacker's control.
    let user_sid = current_user_sid_string()?;
    let descriptor_string =
        format!("O:{user_sid}D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_string.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let succeeded = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    } != 0;
    let error = if succeeded {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    unsafe {
        LocalFree(descriptor);
    }
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn current_user_sid_string() -> io::Result<String> {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process: *mut c_void,
            desired_access: u32,
            token: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            information_class: u32,
            information: *mut c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    }

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
        let mut required = 0u32;
        unsafe {
            GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required == 0 {
            return Err(io::Error::last_os_error());
        }

        // TOKEN_USER contains pointers and must be naturally aligned.
        let word_size = std::mem::size_of::<usize>();
        let words = (required as usize).div_ceil(word_size);
        let mut buffer = vec![0usize; words];
        if unsafe {
            GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token_user = unsafe { &*buffer.as_ptr().cast::<TokenUser>() };

        let mut string_sid = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(token_user.user.sid, &mut string_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if string_sid.is_null() {
            return Err(io::Error::other(
                "ConvertSidToStringSidW returned a null SID string",
            ));
        }

        let mut length = 0usize;
        while length < 256 && unsafe { *string_sid.add(length) } != 0 {
            length += 1;
        }
        let sid_result = if length == 256 {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "current-user SID string is not null terminated",
            ))
        } else {
            let wide = unsafe { std::slice::from_raw_parts(string_sid, length) };
            OsString::from_wide(wide)
                .into_string()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID is not valid UTF-16"))
        };
        unsafe {
            LocalFree(string_sid.cast());
        }
        sid_result
    })();

    unsafe {
        CloseHandle(token);
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn harden_artifact_acl(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_directory_pin(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(target_os = "windows"))]
fn open_directory_pin(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(target_os = "windows")]
fn move_file_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    // Intentionally omit MOVEFILE_REPLACE_EXISTING: an attacker-created final name must make the
    // operation fail, never cause truncation or replacement.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn move_file_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    // hard_link is an atomic no-replace publication when source and destination share a directory.
    fs::hard_link(source, destination)?;
    fs::remove_file(source)
}

#[cfg(target_os = "windows")]
fn move_file_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn move_file_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

fn sanitize_stem(stem: &str) -> String {
    stem.chars()
        .take(80)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn path_is_within(path: &Path, root: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let path = path.to_string_lossy().replace('/', "\\").to_lowercase();
        let root = root
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase();
        path == root
            || path
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('\\'))
    }

    #[cfg(not(target_os = "windows"))]
    {
        path.starts_with(root)
    }
}

pub(crate) fn random_hex(byte_count: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; byte_count];
    fill_random(&mut bytes)?;
    let mut value = String::with_capacity(byte_count * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(value)
}

#[cfg(target_os = "windows")]
fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    use std::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_length: u32,
            flags: u32,
        ) -> i32;
    }

    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "random request is too large"))?;
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed with NTSTATUS 0x{:08x}",
            status as u32
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    use std::io::Read;

    File::open("/dev/urandom")?.read_exact(bytes)
}

struct LimitedWriter {
    file: File,
    written: u64,
    maximum: u64,
}

impl LimitedWriter {
    fn new(file: File, maximum: u64) -> Self {
        Self {
            file,
            written: 0,
            maximum,
        }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(length) > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!("artifact exceeds the {} byte size limit", self.maximum),
            ));
        }
        let written = self.file.write(buffer)?;
        self.written = self
            .written
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct TemporaryFileGuard {
    path: PathBuf,
    committed: bool,
}

impl TemporaryFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    fn create_directory_link(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(not(target_os = "windows"))]
    fn create_directory_link(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(target_os = "windows")]
    fn remove_directory_link(link: &Path) -> io::Result<()> {
        fs::remove_dir(link)
    }

    #[cfg(not(target_os = "windows"))]
    fn remove_directory_link(link: &Path) -> io::Result<()> {
        fs::remove_file(link)
    }

    fn temporary_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "foxhole-artifact-test-{}-{}",
            std::process::id(),
            random_hex(8).expect("random test suffix")
        ))
    }

    #[test]
    fn refuses_to_overwrite_an_existing_artifact() {
        let root = temporary_root();
        let relative = Path::new("reports").join("result.json");
        let first =
            secure_write_new_in(&root, &relative, 1024, |writer| writer.write_all(b"first"))
                .expect("first write");

        let error =
            secure_write_new_in(&root, &relative, 1024, |writer| writer.write_all(b"second"))
                .expect_err("overwrite must fail");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&first).expect("read artifact"), b"first");

        fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn rejects_parent_traversal() {
        let error = validate_relative_artifact_path(Path::new("reports/../outside.json"))
            .expect_err("parent traversal must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_absolute_and_terminal_control_names() {
        assert!(validate_relative_artifact_path(Path::new(r"C:\outside.json")).is_err());
        assert!(validate_relative_artifact_path(Path::new("report\u{202e}nosj.exe")).is_err());
        assert!(validate_relative_artifact_path(Path::new("report\x1b[2J.json")).is_err());
        assert!(validate_relative_artifact_path(Path::new("COM¹.txt")).is_err());
        assert!(validate_relative_artifact_path(Path::new("LPT²")).is_err());
    }

    #[test]
    fn enforces_artifact_size_limit_without_publishing_partial_file() {
        let root = temporary_root();
        let relative = Path::new("reports").join("large.json");
        let error = secure_write_new_in(&root, &relative, 3, |writer| writer.write_all(b"four"))
            .expect_err("oversized write must fail");
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert!(!root.join(relative).exists());

        fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn aggregate_file_ceiling_preserves_existing_artifacts() {
        let root = temporary_root();
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports directory");
        let existing = reports.join("existing.json");
        fs::write(&existing, b"keep").expect("write existing artifact");
        let relative = Path::new("reports").join("new.json");
        let limits = ArtifactLimits {
            maximum_files: 1,
            maximum_bytes: 1_024,
            maximum_entries: 16,
        };

        let error = secure_write_new_in_with_limits(&root, &relative, 16, limits, |writer| {
            writer.write_all(b"new")
        })
        .expect_err("the sibling temporary file must count toward the file ceiling");
        assert!(error.to_string().contains("retention ceiling"));
        assert_eq!(
            fs::read(&existing).expect("read existing artifact"),
            b"keep"
        );
        assert!(!root.join(relative).exists());
        assert_eq!(
            fs::read_dir(&reports).expect("list reports").count(),
            1,
            "the rejected temporary file must be removed"
        );

        fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn aggregate_byte_ceiling_rejects_before_publication() {
        let root = temporary_root();
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports directory");
        let existing = reports.join("existing.json");
        fs::write(&existing, b"abc").expect("write existing artifact");
        let relative = Path::new("reports").join("new.json");
        let limits = ArtifactLimits {
            maximum_files: 8,
            maximum_bytes: 4,
            maximum_entries: 16,
        };

        let error = secure_write_new_in_with_limits(&root, &relative, 16, limits, |writer| {
            writer.write_all(b"de")
        })
        .expect_err("aggregate bytes, including the temporary file, must be bounded");
        assert!(error.to_string().contains("retention ceiling"));
        assert_eq!(fs::read(&existing).expect("read existing artifact"), b"abc");
        assert!(!root.join(relative).exists());

        fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn retention_scan_has_a_hard_entry_bound() {
        let root = temporary_root();
        fs::create_dir_all(&root).expect("create test root");
        fs::write(root.join("one"), b"1").expect("write first entry");
        fs::write(root.join("two"), b"2").expect("write second entry");
        let limits = ArtifactLimits {
            maximum_files: 8,
            maximum_bytes: 16,
            maximum_entries: 1,
        };

        let error = enforce_artifact_ceiling(&root, limits)
            .expect_err("traversal must stop at the configured entry bound");
        assert!(error.to_string().contains("more than 1 entries"));

        fs::remove_dir_all(root).expect("clean test root");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn retention_scan_rejects_reparse_entries_when_available() {
        use std::os::windows::fs::symlink_file;

        let root = temporary_root();
        fs::create_dir_all(&root).expect("create test root");
        let outside = root.with_extension("outside");
        let link = root.join("linked-artifact");
        fs::write(&outside, b"outside").expect("write outside file");

        if symlink_file(&outside, &link).is_ok() {
            let error = enforce_artifact_ceiling(&root, ARTIFACT_LIMITS)
                .expect_err("reparse entries must be rejected without being followed");
            assert!(error.to_string().contains("symbolic link"));
            fs::remove_file(&link).expect("remove link");
        }

        fs::remove_file(outside).expect("remove outside file");
        fs::remove_dir_all(root).expect("clean test root");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn protected_application_root_accepts_exclusive_writes() {
        let destination = artifact_root()
            .expect("application artifact root")
            .join("self-test")
            .join(format!("{}.txt", random_hex(8).expect("random name")));
        let written = secure_write_new(&destination, 16, |writer| writer.write_all(b"ok"))
            .expect("protected-root write");
        assert_eq!(fs::read(&written).expect("read protected artifact"), b"ok");
        fs::remove_file(written).expect("remove protected-root test artifact");
    }

    #[test]
    fn destinations_are_unique_sanitized_and_below_the_artifact_root() {
        let root = artifact_root().unwrap();
        let explicit =
            report_destination(Some(Path::new("nested/result.json")), Path::new("x.exe")).unwrap();
        assert_eq!(explicit, root.join("reports/nested/result.json"));

        let first = report_destination(None, Path::new("odd target!.exe")).unwrap();
        let second = report_destination(None, Path::new("odd target!.exe")).unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with(root.join("reports")));
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("fh_odd_target__")
        );

        let vt = virustotal_result_destination().unwrap();
        assert!(vt.starts_with(root.join("virustotal")));
    }

    #[test]
    fn artifact_root_containment_is_enforced() {
        let root = artifact_root().unwrap().canonicalize().unwrap();
        assert!(ensure_canonical_path_outside_artifact_root(&root.join("inside"), "test").is_err());
        assert!(ensure_canonical_path_outside_artifact_root(&std::env::temp_dir(), "test").is_ok());
        assert!(
            secure_write_new(&std::env::temp_dir().join("outside.json"), 4, |_| Ok(())).is_err()
        );
    }

    #[test]
    fn invalid_retention_limits_and_writer_errors_leave_no_artifact() {
        let root = temporary_root();
        fs::create_dir_all(&root).unwrap();
        for limits in [
            ArtifactLimits {
                maximum_files: 0,
                maximum_bytes: 1,
                maximum_entries: 1,
            },
            ArtifactLimits {
                maximum_files: 1,
                maximum_bytes: 0,
                maximum_entries: 1,
            },
            ArtifactLimits {
                maximum_files: 1,
                maximum_bytes: 1,
                maximum_entries: 0,
            },
        ] {
            assert!(enforce_artifact_ceiling(&root, limits).is_err());
        }

        let relative = Path::new("reports/error.json");
        let error = secure_write_new_in(&root, relative, 32, |writer| {
            writer.write_all(b"partial")?;
            Err(io::Error::other("intentional writer failure"))
        })
        .expect_err("writer failure must abort publication");
        assert!(error.to_string().contains("intentional"));
        assert!(!root.join(relative).exists());
        assert!(fs::read_dir(root.join("reports")).unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_and_component_validation_covers_windows_security_cases() {
        assert!(validate_relative_artifact_path(Path::new("")).is_err());
        assert!(validate_relative_artifact_path(Path::new(".")).is_err());
        for name in [
            "CON",
            "PRN.txt",
            "AUX",
            "NUL.bin",
            "COM1",
            "LPT9.log",
            "bad:name",
            "bad?name",
            "trailing.",
            "trailing ",
        ] {
            assert!(
                validate_file_name_component(OsStr::new(name)).is_err(),
                "accepted {name}"
            );
        }
        assert!(validate_file_name_component(OsStr::new(&"x".repeat(241))).is_err());
        assert!(validate_file_name_component(OsStr::new("safe-name_1.json")).is_ok());

        assert!(validate_absolute_local_path(Path::new("relative")).is_err());
        assert!(validate_absolute_local_path(Path::new(r"\\server\share\file")).is_err());
        assert!(validate_absolute_local_path(Path::new(r"C:\safe\file")).is_ok());
    }

    #[test]
    fn directory_pinning_and_handle_paths_are_verified() {
        let root = temporary_root();
        let nested = root.join("one/two");
        let pins = pin_safe_directory_tree(&nested, true).expect("create and pin directory chain");
        assert!(!pins.is_empty());
        let final_path = final_path_by_handle(pins.last().unwrap()).unwrap();
        assert!(windows_paths_equal(&final_path, &nested));
        assert!(windows_paths_equal(
            Path::new(r"\\?\C:\Temp\"),
            Path::new(r"c:\temp")
        ));
        assert!(!windows_paths_equal(
            Path::new(r"C:\one"),
            Path::new(r"C:\two")
        ));
        drop(pins);

        let file = root.join("file");
        fs::write(&file, b"file").unwrap();
        assert!(pin_safe_directory_tree(&file.join("child"), false).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_and_generated_writes_reject_redirected_directories() {
        let root = temporary_root();
        let outside = root.join("outside");
        let outside_artifacts = outside.join("artifacts");
        fs::create_dir_all(&outside_artifacts).unwrap();
        let sentinel = outside_artifacts.join("sentinel.txt");
        fs::write(&sentinel, b"keep").unwrap();
        let redirected_application = root.join("Foxhole");
        if let Err(error) = create_directory_link(&outside, &redirected_application) {
            eprintln!("directory-link creation is unavailable; skipping link assertion: {error}");
            fs::remove_dir_all(root).unwrap();
            return;
        }

        assert!(clean_artifacts_and_logs_at(&redirected_application).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep");

        let output_link = root.join("output-link");
        create_directory_link(&outside, &output_link).unwrap();
        assert!(
            secure_replace_in(
                &root,
                Path::new("output-link/report.json"),
                1024,
                |writer| writer.write_all(b"blocked"),
            )
            .is_err()
        );
        assert!(!outside.join("report.json").exists());

        remove_directory_link(&output_link).unwrap();
        remove_directory_link(&redirected_application).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn safe_regular_file_open_rejects_hard_links() {
        let root = temporary_root();
        fs::create_dir_all(&root).unwrap();
        let original = root.join("original.json");
        let alias = root.join("alias.json");
        fs::write(&original, b"{}").unwrap();
        fs::hard_link(&original, &alias).unwrap();

        assert!(open_safe_regular_file(&alias).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn random_stem_containment_and_temporary_guard_helpers_work() {
        assert_eq!(sanitize_stem("a b/c"), "a_b_c");
        assert_eq!(sanitize_stem(&"x".repeat(100)).len(), 80);
        assert_eq!(random_hex(0).unwrap(), "");
        let random = random_hex(16).unwrap();
        assert_eq!(random.len(), 32);
        assert!(random.bytes().all(|byte| byte.is_ascii_hexdigit()));

        assert!(path_is_within(
            Path::new(r"C:\Root\child"),
            Path::new(r"c:\root")
        ));
        assert!(!path_is_within(
            Path::new(r"C:\Rooted"),
            Path::new(r"C:\Root")
        ));

        let root = temporary_root();
        fs::create_dir_all(&root).unwrap();
        let guarded = root.join("guarded.tmp");
        fs::write(&guarded, b"temporary").unwrap();
        drop(TemporaryFileGuard::new(guarded.clone()));
        assert!(!guarded.exists());
        fs::remove_dir(root).unwrap();
    }
}
