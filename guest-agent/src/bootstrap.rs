use crate::runner::{AgentError, AgentResult};
use std::path::{Component, Path, PathBuf};

/// Host-side `RunDataDiskSpec::label` uses this prefix followed by the first
/// twelve hexadecimal characters of the run identifier.
const RUN_DATA_LABEL_PREFIX: &str = "FOXHOLE_";
const RUN_DATA_LABEL_SUFFIX_LEN: usize = 12;
const RUN_DIRECTORY_NAME: &str = "foxhole-run";
const MAX_ENUMERATED_VOLUMES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
struct VolumeCandidate {
    root: PathBuf,
    label: String,
}

pub fn discover_run_root() -> AgentResult<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let root = select_unique_run_volume(enumerate_windows_volumes()?)?;
        crate::security::validate_existing_directory_tree(&root)?;
        Ok(root)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(AgentError::new(
            "configuration",
            "missing_run_root",
            "set FOXHOLE_RUN_ROOT or pass --run-root outside a Windows guest",
        ))
    }
}

fn select_unique_run_volume(
    candidates: impl IntoIterator<Item = VolumeCandidate>,
) -> AgentResult<PathBuf> {
    let mut matching = Vec::new();
    for candidate in candidates {
        if !is_run_data_label(&candidate.label) {
            continue;
        }
        validate_volume_root(&candidate.root)?;
        matching.push(candidate);
    }

    match matching.as_slice() {
        [] => Err(AgentError::new(
            "configuration",
            "run_data_volume_not_found",
            "no attached volume has a valid FOXHOLE_<12 hex> run-data label",
        )),
        [candidate] => Ok(candidate.root.join(RUN_DIRECTORY_NAME)),
        _ => Err(AgentError::new(
            "configuration",
            "ambiguous_run_data_volume",
            format!(
                "{} attached volumes have valid Foxhole run-data labels",
                matching.len()
            ),
        )),
    }
}

fn is_run_data_label(label: &str) -> bool {
    let Some(suffix) = label.strip_prefix(RUN_DATA_LABEL_PREFIX) else {
        return false;
    };
    suffix.len() == RUN_DATA_LABEL_SUFFIX_LEN
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn validate_volume_root(root: &Path) -> AgentResult<()> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AgentError::new(
            "configuration",
            "invalid_run_data_volume",
            "the discovered run-data volume root is not an absolute normalized path",
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn enumerate_windows_volumes() -> AgentResult<Vec<VolumeCandidate>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, GetVolumeInformationW};
    use windows::core::PCWSTR;

    const VOLUME_LABEL_CAPACITY: usize = 256;

    // A volume-GUID path (\\?\Volume{...}\) is not a Win32 local-drive path
    // and is intentionally rejected by the guest path validator. Enumerate
    // mounted logical roots instead so the selected run root is usable by the
    // staging and restricted-process layers without weakening path checks.
    let required = unsafe { GetLogicalDriveStringsW(None) };
    if required == 0 {
        return Err(AgentError::with_source(
            "configuration",
            "enumerate_run_data_volumes",
            "query Windows logical drives",
            std::io::Error::last_os_error(),
        ));
    }
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|length| length.checked_add(1))
        .filter(|length| *length <= MAX_ENUMERATED_VOLUMES.saturating_mul(8))
        .ok_or_else(|| {
            AgentError::new(
                "configuration",
                "too_many_volumes",
                "Windows logical-drive buffer exceeds the bounded volume limit",
            )
        })?;
    let mut drive_strings = vec![0u16; capacity];
    let written = unsafe { GetLogicalDriveStringsW(Some(&mut drive_strings)) };
    if written == 0 {
        return Err(AgentError::with_source(
            "configuration",
            "enumerate_run_data_volumes",
            "query Windows logical drives",
            std::io::Error::last_os_error(),
        ));
    }
    if usize::try_from(written).unwrap_or(usize::MAX) >= drive_strings.len() {
        return Err(AgentError::new(
            "configuration",
            "logical_drive_list_changed",
            "Windows logical-drive list changed while it was being read",
        ));
    }

    let drive_roots = parse_logical_drive_strings(&drive_strings)?;
    if drive_roots.len() > MAX_ENUMERATED_VOLUMES {
        return Err(AgentError::new(
            "configuration",
            "too_many_volumes",
            format!("more than {MAX_ENUMERATED_VOLUMES} volumes are attached"),
        ));
    }
    let mut candidates = Vec::new();
    for drive_root in drive_roots {
        let volume_root = PathBuf::from(OsString::from_wide(&drive_root));
        validate_volume_root(&volume_root)?;

        let volume_name = drive_root
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut label = vec![0u16; VOLUME_LABEL_CAPACITY];
        // SAFETY: `volume_name` is NUL terminated and both output buffers
        // remain valid for the duration of the call.
        unsafe {
            GetVolumeInformationW(
                PCWSTR(volume_name.as_ptr()),
                Some(&mut label),
                None,
                None,
                None,
                None,
            )
        }
        .map_err(|error| {
            AgentError::with_source(
                "configuration",
                "inspect_run_data_volume",
                format!("read the label for volume {}", volume_root.display()),
                error,
            )
        })?;
        let label_length = nul_terminated_length(&label)?;
        let label = String::from_utf16(&label[..label_length]).map_err(|error| {
            AgentError::with_source(
                "configuration",
                "invalid_volume_label",
                "decode a Windows volume label",
                error,
            )
        })?;
        candidates.push(VolumeCandidate {
            root: volume_root,
            label,
        });
    }
    Ok(candidates)
}

fn parse_logical_drive_strings(buffer: &[u16]) -> AgentResult<Vec<Vec<u16>>> {
    let mut roots = Vec::new();
    let mut offset = 0usize;
    while offset < buffer.len() {
        let remaining = &buffer[offset..];
        let Some(length) = remaining.iter().position(|value| *value == 0) else {
            return Err(AgentError::new(
                "configuration",
                "unterminated_windows_text",
                "Windows returned an unterminated logical-drive list",
            ));
        };
        if length == 0 {
            return Ok(roots);
        }
        roots.push(remaining[..length].to_vec());
        if roots.len() > MAX_ENUMERATED_VOLUMES {
            return Err(AgentError::new(
                "configuration",
                "too_many_volumes",
                format!("more than {MAX_ENUMERATED_VOLUMES} volumes are attached"),
            ));
        }
        offset = offset.checked_add(length + 1).ok_or_else(|| {
            AgentError::new(
                "configuration",
                "drive_list_overflow",
                "logical-drive list offset overflowed",
            )
        })?;
    }
    Err(AgentError::new(
        "configuration",
        "unterminated_windows_text",
        "Windows logical-drive list is missing its final terminator",
    ))
}

#[cfg(target_os = "windows")]
fn nul_terminated_length(buffer: &[u16]) -> AgentResult<usize> {
    buffer.iter().position(|value| *value == 0).ok_or_else(|| {
        AgentError::new(
            "configuration",
            "unterminated_windows_text",
            "Windows returned an unterminated volume name or label",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute_test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn run_data_labels_match_the_host_contract_exactly() {
        assert!(is_run_data_label("FOXHOLE_0123456789AF"));
        for invalid in [
            "foxhole_0123456789AF",
            "FOXHOLE_0123456789af",
            "FOXHOLE_0123456789A",
            "FOXHOLE_0123456789AG",
            "OTHER_0123456789AF",
        ] {
            assert!(!is_run_data_label(invalid), "{invalid}");
        }
    }

    #[test]
    fn volume_selection_requires_exactly_one_valid_candidate() {
        let first = VolumeCandidate {
            root: absolute_test_root("foxhole-volume-a"),
            label: "FOXHOLE_0123456789AB".into(),
        };
        let ignored = VolumeCandidate {
            root: absolute_test_root("ordinary-volume"),
            label: "SYSTEM".into(),
        };
        let selected =
            select_unique_run_volume([ignored, first.clone()]).expect("single matching volume");
        assert_eq!(selected, first.root.join(RUN_DIRECTORY_NAME));

        assert!(select_unique_run_volume(Vec::<VolumeCandidate>::new()).is_err());
        assert!(
            select_unique_run_volume([
                first,
                VolumeCandidate {
                    root: absolute_test_root("foxhole-volume-b"),
                    label: "FOXHOLE_ABCDEF012345".into(),
                },
            ])
            .is_err()
        );
    }

    #[test]
    fn volume_selection_rejects_unsafe_matching_roots() {
        let result = select_unique_run_volume([VolumeCandidate {
            root: PathBuf::from("relative"),
            label: "FOXHOLE_0123456789AB".into(),
        }]);
        assert!(result.is_err());
    }

    #[test]
    fn logical_drive_multistring_parser_is_bounded_and_requires_termination() {
        let encoded = "C:\\\0D:\\\0\0".encode_utf16().collect::<Vec<_>>();
        let roots = parse_logical_drive_strings(&encoded).expect("parse logical drives");
        assert_eq!(roots.len(), 2);
        assert_eq!(String::from_utf16(&roots[0]).unwrap(), "C:\\");
        assert_eq!(String::from_utf16(&roots[1]).unwrap(), "D:\\");

        assert!(parse_logical_drive_strings(&"C:\\".encode_utf16().collect::<Vec<_>>()).is_err());
    }
}
