use clap::Parser;
use dialoguer::Select;
use foxhole::report_analysis::{DiscoveredRun, analyze_run, discover_runs};
use std::error::Error;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "foxhole-analyze")]
#[command(about = "Build deterministic normalized, verdict, and IOC reports for a Foxhole run")]
struct Args {
    /// Foxhole artifact root (containing reports/ and hyperv/) or one Hyper-V run directory
    #[arg(value_name = "RUN_ROOT")]
    run_root: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let runs = discover_runs(&args.run_root)?;
    let selected = if runs.len() > 1 {
        Some(select_run(&runs)?)
    } else {
        None
    };
    let analysis_root = selected
        .map(|run| run.run_directory.clone())
        .unwrap_or(args.run_root);
    let outputs = analyze_run(&analysis_root)?;
    if let Some(run) = selected {
        println!("selected_run={}", clean_path(&run.run_directory));
    }
    println!("normalized={}", clean_path(&outputs.normalized));
    println!("verdict={}", clean_path(&outputs.verdict));
    println!("iocs={}", clean_path(&outputs.iocs));
    let web_path = clean_path(&outputs.web);
    println!("web={web_path}");
    // Keep paths as data. Emitting shell syntax would let a quote in an otherwise valid path
    // become code when a user or wrapper evaluates the convenience line.
    println!("{}", open_web_path_line(&outputs.web));
    Ok(())
}

fn open_web_path_line(path: &Path) -> String {
    format!("open_web_path={}", clean_path(path))
}

fn clean_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(value.as_ref())
        .chars()
        .flat_map(|character| {
            if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn select_run(runs: &[DiscoveredRun]) -> Result<&DiscoveredRun, dialoguer::Error> {
    let items = runs.iter().map(report_label).collect::<Vec<_>>();
    let selected = Select::new()
        .with_prompt("Multiple reports found; select one to analyze")
        .items(&items)
        .default(0)
        .clear(false)
        .interact()?;
    Ok(&runs[selected])
}

fn report_label(run: &DiscoveredRun) -> String {
    format!(
        "{} | {} | {}",
        terminal_safe(&run.report_name),
        terminal_safe(&run.target_name),
        format_unix_ms(run.generated_at_unix_ms)
    )
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn format_unix_ms(timestamp_ms: u64) -> String {
    if timestamp_ms == 0 {
        return "unknown date".to_string();
    }
    let seconds = timestamp_ms / 1_000;
    let days = (seconds / 86_400) as i64;
    let seconds_in_day = seconds % 86_400;
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;
    let (year, month, day) = civil_date_from_unix_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

// Gregorian calendar conversion adapted from the public-domain civil-date algorithm.
fn civil_date_from_unix_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_displayed_as_utc_dates() {
        assert_eq!(format_unix_ms(1_000), "1970-01-01 00:00:01 UTC");
        assert_eq!(format_unix_ms(1_787_784_836_126), "2026-08-26 22:53:56 UTC");
        assert_eq!(format_unix_ms(0), "unknown date");
    }

    #[test]
    fn report_labels_cannot_inject_terminal_controls() {
        let run = DiscoveredRun {
            report_path: PathBuf::new(),
            run_directory: PathBuf::new(),
            report_name: "fh_bad\u{1b}[2J.json".to_string(),
            target_name: "bad\ntarget.exe".to_string(),
            generated_at_unix_ms: 1_000,
        };
        assert_eq!(
            report_label(&run),
            "fh_bad�[2J.json | bad�target.exe | 1970-01-01 00:00:01 UTC"
        );
    }

    #[test]
    fn clean_path_removes_windows_verbatim_prefix() {
        assert_eq!(
            clean_path(&PathBuf::from(r"\\?\C:\Foxhole\web\index.html")),
            r"C:\Foxhole\web\index.html"
        );
        assert_eq!(
            clean_path(&PathBuf::from(r"C:\Foxhole\web\index.html")),
            r"C:\Foxhole\web\index.html"
        );
    }

    #[test]
    fn web_hint_is_single_line_data_even_when_the_path_contains_controls() {
        let line = open_web_path_line(&PathBuf::from(
            "C:\\runs\\attacker'; Write-Output pwned\nopen_web=Start-Process calc\\web\\index.html",
        ));
        assert!(line.starts_with("open_web_path="));
        assert!(!line.starts_with("open_web="));
        assert!(!line.contains(['\r', '\n']));
    }
}
