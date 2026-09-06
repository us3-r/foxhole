use std::path::Path;

pub fn log_outside(message: impl AsRef<str>) {
    println!(
        "[sandbox][outside] {}",
        crate::utils::terminal_safe(message.as_ref())
    );
}

pub fn log_inside(message: impl AsRef<str>) {
    println!(
        "[sandbox][inside] {}",
        crate::utils::terminal_safe(message.as_ref())
    );
}

pub fn log_monitor(message: impl AsRef<str>) {
    println!(
        "[sandbox][monitor] {}",
        crate::utils::terminal_safe(message.as_ref())
    );
}

pub fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn build_windows_command_line(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(quote_windows_arg)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }

    if !arg.chars().any(|c| c.is_whitespace() || c == '"') {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;

    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(c);
            }
        }
    }

    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes * 2));
    }
    quoted.push('"');
    quoted
}

pub fn win32_path_string(path: &Path) -> String {
    let value = path.display().to_string();
    if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{stripped}")
    } else if let Some(stripped) = value.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_windows_args_with_spaces() {
        assert_eq!(
            quote_windows_arg("C:\\Program Files\\app.exe"),
            "\"C:\\Program Files\\app.exe\""
        );
    }

    #[test]
    fn quotes_embedded_quotes() {
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn quotes_empty_plain_and_trailing_backslash_arguments() {
        assert_eq!(quote_windows_arg(""), "\"\"");
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(
            quote_windows_arg(r"C:\path with space\"),
            r#""C:\path with space\\""#
        );
    }

    #[test]
    fn command_line_and_wide_strings_are_constructed_exactly() {
        assert_eq!(
            build_windows_command_line("tool.exe", &["one".into(), "two words".into()]),
            "tool.exe one \"two words\""
        );
        assert_eq!(to_wide_null("A"), [65, 0]);
    }

    #[test]
    fn extended_windows_paths_are_made_human_readable() {
        assert_eq!(
            win32_path_string(Path::new(r"\\?\C:\temp\a.exe")),
            r"C:\temp\a.exe"
        );
        assert_eq!(
            win32_path_string(Path::new(r"\\?\UNC\server\share\a.exe")),
            r"\\server\share\a.exe"
        );
        assert_eq!(
            win32_path_string(Path::new(r"C:\plain.exe")),
            r"C:\plain.exe"
        );
    }

    #[test]
    fn logging_helpers_accept_untrusted_control_text() {
        log_outside("outside\u{1b}");
        log_inside("inside\r");
        log_monitor("monitor\u{202e}");
    }
}
