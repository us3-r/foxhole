mod artifacts;
mod bootstrap;
mod filesystem;
mod monitor;
#[cfg(target_os = "windows")]
mod native_process;
mod network;
mod process;
mod registry;
mod request;
mod result;
mod runner;
mod security;
#[cfg(target_os = "windows")]
mod service;
#[cfg(target_os = "windows")]
mod telemetry;

use crate::process::{SystemGuestExecutor, SystemShutdownController};
use crate::runner::{
    AgentConfig, AgentError, AgentResult, RunSummary, default_staging_root, require_absolute_path,
    validate_version_field,
};
use std::ffi::OsString;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run_main(std::env::args_os().skip(1)) {
        write_stderr(format_args!("[foxhole-agent] {error}"));
        std::process::exit(1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchMode {
    Service,
    Console,
}

fn run_main(arguments: impl IntoIterator<Item = OsString>) -> AgentResult<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = arguments;
        return Err(AgentError::new(
            "startup",
            "unsupported_guest_os",
            "foxhole-agent only executes targets inside a Windows guest",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let (mode, configuration_arguments) = split_launch_mode(arguments)?;
        if mode == LaunchMode::Service {
            return service::run_dispatcher(configuration_arguments);
        }

        let config = parse_configuration(configuration_arguments)?;
        let summary = execute(config)?;
        print_summary(&summary);
        Ok(())
    }
}

fn split_launch_mode(
    arguments: impl IntoIterator<Item = OsString>,
) -> AgentResult<(LaunchMode, Vec<OsString>)> {
    let mut arguments: Vec<_> = arguments.into_iter().collect();
    let mode = match arguments.first().and_then(|argument| argument.to_str()) {
        Some("--console") => {
            arguments.remove(0);
            LaunchMode::Console
        }
        Some("--service") => {
            arguments.remove(0);
            LaunchMode::Service
        }
        Some(argument) if argument.starts_with("--") => {
            return Err(AgentError::new(
                "configuration",
                "missing_launch_mode",
                "select --service for SCM execution or --console for manual execution",
            ));
        }
        Some(_) => {
            return Err(AgentError::new(
                "configuration",
                "invalid_launch_mode",
                "the first guest-agent argument must be --service or --console",
            ));
        }
        None => LaunchMode::Service,
    };
    Ok((mode, arguments))
}

fn execute(config: AgentConfig) -> AgentResult<RunSummary> {
    write_stderr(format_args!(
        "[foxhole-agent] ACL boundary: {}",
        security::SANDBOX_ACL_DELEGATION_NOTICE
    ));
    let mut executor = SystemGuestExecutor;
    let mut shutdown = SystemShutdownController;
    runner::run(&config, &mut executor, &mut shutdown)
}

fn print_summary(summary: &RunSummary) {
    write_stdout(format_args!(
        "[foxhole-agent] run={} outcome={:?} result={}",
        summary.run_id,
        summary.outcome,
        summary.result_path.display()
    ));
}

fn write_stderr(arguments: std::fmt::Arguments<'_>) {
    use std::io::Write;

    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_fmt(arguments);
    let _ = stderr.write_all(b"\n");
}

fn write_stdout(arguments: std::fmt::Arguments<'_>) {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_fmt(arguments);
    let _ = stdout.write_all(b"\n");
}

fn parse_configuration(arguments: impl IntoIterator<Item = OsString>) -> AgentResult<AgentConfig> {
    let mut run_root = std::env::var_os("FOXHOLE_RUN_ROOT").map(PathBuf::from);
    let mut staging_root = std::env::var_os("FOXHOLE_STAGING_ROOT").map(PathBuf::from);
    let mut guest_image_version = std::env::var("FOXHOLE_GUEST_IMAGE_VERSION").ok();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let argument = argument.to_string_lossy();
        match argument.as_ref() {
            "--run-root" => {
                run_root = Some(PathBuf::from(arguments.next().ok_or_else(|| {
                    AgentError::new(
                        "configuration",
                        "missing_value",
                        "--run-root requires a value",
                    )
                })?));
            }
            "--staging-root" => {
                staging_root = Some(PathBuf::from(arguments.next().ok_or_else(|| {
                    AgentError::new(
                        "configuration",
                        "missing_value",
                        "--staging-root requires a value",
                    )
                })?));
            }
            "--guest-image-version" => {
                guest_image_version = Some(
                    arguments
                        .next()
                        .ok_or_else(|| {
                            AgentError::new(
                                "configuration",
                                "missing_value",
                                "--guest-image-version requires a value",
                            )
                        })?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            _ => {
                return Err(AgentError::new(
                    "configuration",
                    "unknown_argument",
                    format!("unknown guest-agent argument: {argument}"),
                ));
            }
        }
    }

    let run_root = run_root.map_or_else(bootstrap::discover_run_root, Ok)?;
    let staging_root = staging_root.map_or_else(default_staging_root, Ok)?;
    let guest_image_version = guest_image_version.unwrap_or_else(|| "unknown".to_string());
    require_absolute_path("run root", &run_root)?;
    require_absolute_path("staging root", &staging_root)?;
    validate_version_field("guest image version", &guest_image_version)?;
    let agent_version = env!("CARGO_PKG_VERSION").to_string();
    validate_version_field("agent version", &agent_version)?;
    Ok(AgentConfig {
        run_root,
        staging_root,
        agent_version,
        guest_image_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_parser_rejects_unknown_and_relative_paths() {
        assert!(parse_configuration(["--unknown".into()]).is_err());
        assert!(
            parse_configuration([
                "--run-root".into(),
                "relative".into(),
                "--staging-root".into(),
                "also-relative".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn launch_mode_is_explicit_for_manual_execution() {
        assert_eq!(
            split_launch_mode(["--console".into(), "--run-root".into(), "X:\\".into()]).unwrap(),
            (
                LaunchMode::Console,
                vec!["--run-root".into(), "X:\\".into()]
            )
        );
        assert_eq!(
            split_launch_mode(["--service".into()]).unwrap(),
            (LaunchMode::Service, Vec::new())
        );
        assert_eq!(
            split_launch_mode(Vec::<OsString>::new()).unwrap(),
            (LaunchMode::Service, Vec::new())
        );
        assert!(split_launch_mode(["--run-root".into(), "X:\\".into()]).is_err());
    }
}
