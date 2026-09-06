use crate::artifact::{self, MAX_VIRUSTOTAL_RESULT_BYTES};
use crate::host_file;
use crate::structs::{COLOR_MAP, Settings, ValiDPathType, ValidatePathResult};
use crate::virustotal_api;
use crate::virustotal_api_structs::VtEndpoint;
use std::error::Error as StdError;
use std::fmt::Arguments;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

type VtResponse = Result<(reqwest::StatusCode, String), Box<dyn StdError>>;
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

pub fn terminal_safe(value: &str) -> String {
    const MAX_TERMINAL_FIELD_BYTES: usize = 16 * 1024;

    let mut escaped = String::with_capacity(value.len().min(MAX_TERMINAL_FIELD_BYTES));
    for character in value.chars() {
        let replacement = if character.is_control()
            || matches!(
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
            ) {
            character.escape_unicode().to_string()
        } else {
            character.to_string()
        };
        if escaped.len().saturating_add(replacement.len()) > MAX_TERMINAL_FIELD_BYTES {
            escaped.push_str("<truncated>");
            break;
        }
        escaped.push_str(&replacement);
    }
    escaped
}

pub fn validate_path(path: &str) -> ValidatePathResult {
    if path.trim().is_empty() {
        return ValidatePathResult {
            is_valid: false,
            type_: ValiDPathType::Invalid,
            error_message: Some("path is empty".to_string()),
        };
    }

    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => ValidatePathResult {
            is_valid: true,
            type_: ValiDPathType::Directory,
            error_message: None,
        },
        Ok(metadata) if metadata.is_file() => ValidatePathResult {
            is_valid: true,
            type_: ValiDPathType::File,
            error_message: None,
        },
        Ok(_) => ValidatePathResult {
            is_valid: false,
            type_: ValiDPathType::Invalid,
            error_message: Some("path is neither a regular file nor a directory".to_string()),
        },
        Err(error) => ValidatePathResult {
            is_valid: false,
            type_: ValiDPathType::Invalid,
            error_message: Some(format!("cannot access {path:?}: {error}")),
        },
    }
}

pub fn debug_print(out: bool, color_code: &str, format: Arguments<'_>) {
    if out {
        let color = COLOR_MAP.get(color_code).copied().unwrap_or("37");
        println!(
            "\x1b[{color}m[debug] {}\x1b[0m",
            terminal_safe(&format.to_string())
        );
    }
}

pub async fn handle_vt_response(
    response: VtResponse,
    debug: bool,
    user_settings: &Settings,
) -> Result<PathBuf, Box<dyn StdError>> {
    let (status, body) = response?;
    debug_print(debug, "yellow", format_args!("response status: {status}"));
    debug_print(
        debug,
        "grey",
        format_args!("response body: {}", terminal_safe(&body)),
    );
    if !status.is_success() {
        return Err(format!("VirusTotal returned HTTP {status}: {body:?}").into());
    }

    let body_json: serde_json::Value = serde_json::from_str(&body)?;
    let analysis_id = body_json
        .pointer("/data/id")
        .and_then(serde_json::Value::as_str)
        .ok_or("VirusTotal response did not contain data.id")?;
    debug_print(
        debug,
        "grey",
        format_args!("analysis ID: {}", terminal_safe(analysis_id)),
    );

    let empty_url = String::new();
    let (analysis_status, analysis_body) = virustotal_api::call_api(
        &user_settings.virus_total_api.analyze_result,
        &user_settings.run_settings.vt_api,
        &VtEndpoint::Analysis,
        None,
        Some(analysis_id),
        &empty_url,
    )
    .await?;
    debug_print(
        debug,
        "yellow",
        format_args!("analysis response status: {analysis_status}"),
    );
    if !analysis_status.is_success() {
        return Err(format!(
            "VirusTotal analysis returned HTTP {analysis_status}: {analysis_body:?}"
        )
        .into());
    }

    let analysis_json: serde_json::Value = serde_json::from_str(&analysis_body)?;
    let pretty_json = serde_json::to_string_pretty(&analysis_json)?;
    Ok(write_json_to_file(&pretty_json)?)
}

pub fn load_settings(settings_path: &str) -> Result<Settings, Box<dyn StdError>> {
    let input =
        host_file::open_pinned_input(std::path::Path::new(settings_path), MAX_SETTINGS_BYTES)
            .map_err(|error| {
                format!("failed to securely open settings file {settings_path:?}: {error}")
            })?;
    let mut settings_data = String::with_capacity(input.len as usize);
    input
        .file
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_string(&mut settings_data)
        .map_err(|error| format!("failed to read settings file {settings_path:?}: {error}"))?;
    serde_json::from_str(&settings_data)
        .map_err(|error| format!("failed to parse settings file {settings_path:?}: {error}").into())
}

pub fn write_json_to_file(content: &str) -> std::io::Result<PathBuf> {
    let destination = artifact::virustotal_result_destination()?;
    artifact::secure_write_new(&destination, MAX_VIRUSTOTAL_RESULT_BYTES, |writer| {
        writer.write_all(content.as_bytes())?;
        writer.write_all(b"\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_invalid_without_exiting() {
        let result = validate_path("");
        assert!(!result.is_valid);
        assert_eq!(result.type_, ValiDPathType::Invalid);
    }

    #[test]
    fn terminal_text_escapes_control_and_directional_characters() {
        assert_eq!(
            terminal_safe("ok\x1b[2J\u{202e}x"),
            "ok\\u{1b}[2J\\u{202e}x"
        );
    }
}
