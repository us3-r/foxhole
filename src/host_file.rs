use crate::artifact;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub struct PinnedInputFile {
    pub file: File,
    pub len: u64,
}

/// Opens a regular file from a fixed local volume and pins that exact object against writes,
/// deletion, and pathname replacement for the lifetime of the returned handle.
pub fn open_pinned_input(path: &Path, maximum_bytes: u64) -> io::Result<PinnedInputFile> {
    #[cfg(target_os = "windows")]
    {
        open_pinned_input_windows(path, maximum_bytes)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let file = OpenOptions::new().read(true).open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input is not a regular file within the configured size limit",
            ));
        }
        let final_path = path.canonicalize()?;
        artifact::ensure_canonical_path_outside_artifact_root(&final_path, "input file")?;
        Ok(PinnedInputFile {
            file,
            len: metadata.len(),
        })
    }
}

#[cfg(target_os = "windows")]
fn open_pinned_input_windows(path: &Path, maximum_bytes: u64) -> io::Result<PinnedInputFile> {
    use std::ffi::c_void;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_TYPE_DISK: u32 = 0x0000_0001;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileType(file: *mut c_void) -> u32;
    }

    let absolute = absolute_clean_input_path(path)?;
    // Check only the syntactic drive root before opening attacker-influenced descendants.
    // GetVolumePathNameW on the complete path could itself traverse a junction and contact a
    // remote share before the no-follow checks below reject it.
    artifact::verify_local_fixed_volume(&local_drive_root(&absolute)?)?;
    let parent = absolute.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "input path has no parent directory",
        )
    })?;
    let _directory_pins = pin_input_directory_tree(parent)?;

    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&absolute)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "input file is a symlink or reparse point",
        ));
    }
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular disk file",
        ));
    }
    let mut identity = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut identity) }
        .map_err(|error| io::Error::other(format!("cannot query input file identity: {error}")))?;
    if identity.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hard-linked input files are not accepted",
        ));
    }

    let opened = artifact::final_path_by_handle(&file)?;
    if !artifact::windows_paths_equal(&absolute, &opened) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "input path changed while it was being opened",
        ));
    }
    artifact::verify_local_fixed_volume(&opened)?;
    artifact::ensure_canonical_path_outside_artifact_root(&opened, "input file")?;

    if metadata.len() > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!(
                "input is {} bytes; limit is {maximum_bytes} bytes",
                metadata.len()
            ),
        ));
    }

    Ok(PinnedInputFile {
        file,
        len: metadata.len(),
    })
}

#[cfg(target_os = "windows")]
fn local_drive_root(path: &Path) -> io::Result<PathBuf> {
    let mut root = PathBuf::new();
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) => root.push(component.as_os_str()),
            Component::RootDir => {
                root.push(component.as_os_str());
                saw_root = true;
            }
            Component::Normal(_) => break,
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "input paths cannot contain '..'",
                ));
            }
        }
    }
    if !saw_root {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input path has no local drive root",
        ));
    }
    Ok(root)
}

#[cfg(target_os = "windows")]
pub(crate) fn pin_input_directory_tree(path: &Path) -> io::Result<Vec<File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    let mut current = PathBuf::new();
    let mut pins = Vec::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }

        // Open first, without following the final component, and deny both write and delete
        // sharing. That fails closed when another process already has a directory writer and
        // prevents an opened clean directory from being changed in place into a junction.
        let pin = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)?;
        let metadata = pin.metadata()?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "input directory component is not a plain directory: {}",
                    current.display()
                ),
            ));
        }

        let opened = artifact::final_path_by_handle(&pin)?;
        if !artifact::windows_paths_equal(&opened, &current) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "input directory path changed while it was being opened: {}",
                    current.display()
                ),
            ));
        }
        pins.push(pin);
    }
    Ok(pins)
}

#[cfg(target_os = "windows")]
fn absolute_clean_input_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    artifact::validate_absolute_local_path(&absolute)?;

    for component in absolute.components() {
        match component {
            Component::Normal(name) => artifact::validate_file_name_component(name)?,
            Component::Prefix(_) | Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "input paths cannot contain '..'",
                ));
            }
        }
    }
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "foxhole-host-file-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("create test directory");
        path
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn opens_and_caps_a_local_regular_file() {
        let directory = temporary_directory();
        let path = directory.join("input.bin");
        std::fs::write(&path, b"four").expect("write input");

        assert_eq!(open_pinned_input(&path, 4).expect("open input").len, 4);
        assert_eq!(
            open_pinned_input(&path, 3)
                .expect_err("oversized input must fail")
                .kind(),
            io::ErrorKind::FileTooLarge
        );

        std::fs::remove_file(path).expect("remove input");
        std::fs::remove_dir(directory).expect("remove test directory");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_devices_and_remote_paths_before_opening() {
        assert!(open_pinned_input(Path::new("NUL"), 16).is_err());
        assert!(open_pinned_input(Path::new(r"\\server\share\settings.json"), 16).is_err());
        assert!(open_pinned_input(Path::new(r"\\.\pipe\foxhole-test"), 16).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_a_reparse_parent_when_symlinks_are_available() {
        use std::os::windows::fs::symlink_dir;

        let directory = temporary_directory();
        let real = directory.join("real");
        let link = directory.join("link");
        std::fs::create_dir(&real).expect("create real directory");
        std::fs::write(real.join("input.bin"), b"data").expect("write input");

        if symlink_dir(&real, &link).is_ok() {
            assert!(open_pinned_input(&link.join("input.bin"), 16).is_err());
            std::fs::remove_dir(&link).expect("remove link");
        }
        std::fs::remove_file(real.join("input.bin")).expect("remove input");
        std::fs::remove_dir(real).expect("remove real directory");
        std::fs::remove_dir(directory).expect("remove test directory");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_hard_link_aliases() {
        let directory = temporary_directory();
        let first = directory.join("first.bin");
        let second = directory.join("second.bin");
        std::fs::write(&first, b"data").expect("write input");
        std::fs::hard_link(&first, &second).expect("create hard link");

        assert!(open_pinned_input(&first, 16).is_err());
        assert!(open_pinned_input(&second, 16).is_err());

        std::fs::remove_file(first).expect("remove first link");
        std::fs::remove_file(second).expect("remove second link");
        std::fs::remove_dir(directory).expect("remove test directory");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn fails_closed_while_an_ancestor_has_an_active_writer() {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const GENERIC_WRITE: u32 = 0x4000_0000;

        let directory = temporary_directory();
        let path = directory.join("input.bin");
        std::fs::write(&path, b"data").expect("write input");
        let writer = OpenOptions::new()
            .access_mode(GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&directory)
            .expect("open directory writer");

        assert!(
            open_pinned_input(&path, 16).is_err(),
            "the input pin must not coexist with a handle that could mutate a directory into a reparse point"
        );
        assert!(
            pin_input_directory_tree(&directory).is_err(),
            "a mapped-directory pin must reject the same active writer"
        );
        drop(writer);
        assert!(open_pinned_input(&path, 16).is_ok());
        drop(pin_input_directory_tree(&directory).expect("pin clean directory tree"));

        std::fs::remove_file(path).expect("remove input");
        std::fs::remove_dir(directory).expect("remove test directory");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn clean_absolute_paths_and_drive_roots_are_derived_safely() {
        let relative = absolute_clean_input_path(Path::new("Cargo.toml")).unwrap();
        assert!(relative.is_absolute());
        assert!(relative.ends_with("Cargo.toml"));
        assert_eq!(local_drive_root(&relative).unwrap(), PathBuf::from(r"C:\"));

        assert!(local_drive_root(Path::new("relative")).is_err());
        assert!(absolute_clean_input_path(Path::new(r"C:\temp\..\escape.bin")).is_err());
        assert!(absolute_clean_input_path(Path::new(r"\\server\share\input.bin")).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn pins_plain_directory_trees_and_rejects_file_components() {
        let directory = temporary_directory();
        let nested = directory.join("one").join("two");
        std::fs::create_dir_all(&nested).unwrap();
        let pins = pin_input_directory_tree(&nested).unwrap();
        assert!(!pins.is_empty());
        drop(pins);

        let file = directory.join("file");
        std::fs::write(&file, b"file").unwrap();
        assert!(pin_input_directory_tree(&file).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn missing_directories_and_artifact_inputs_fail_closed() {
        let directory = temporary_directory();
        assert!(open_pinned_input(&directory.join("missing.bin"), 16).is_err());
        assert!(open_pinned_input(&directory, 16).is_err());
        std::fs::remove_dir(directory).unwrap();

        let artifact = artifact::artifact_root()
            .unwrap()
            .join("host-file-test.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        assert!(open_pinned_input(&artifact, 16).is_err());
        std::fs::remove_file(artifact).unwrap();
    }
}
