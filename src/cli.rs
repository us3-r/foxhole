use crate::artifact;
#[cfg(target_os = "windows")]
use crate::report;
use crate::structs::ValiDPathType;
use crate::{sandbox, utils, virustotal_api};
use clap::{Parser, ValueEnum};
use std::error::Error;
#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::io::Read;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;
use walkdir::WalkDir;

#[cfg(target_os = "windows")]
const HYPERV_BASE_IMAGE_ENV: &str = "FOXHOLE_HYPERV_BASE_IMAGE";
#[cfg(target_os = "windows")]
const HYPERV_BASE_MANIFEST_ENV: &str = "FOXHOLE_HYPERV_BASE_MANIFEST";
#[cfg(target_os = "windows")]
const HYPERV_GATEWAY_CONFIG_ENV: &str = "FOXHOLE_HYPERV_GATEWAY_CONFIG";
#[cfg(any(target_os = "windows", test))]
const MAX_GATEWAY_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Parser, Debug)]
#[command(name = "foxhole")]
#[command(version)]
#[command(author = "us3-r")]
#[command(about = "Runs a program in a local sandbox and records observed behavior")]
pub(crate) struct Args {
    /// Program or file to inspect
    #[arg(short = 'p', long, value_name = "PATH")]
    pub(crate) path: Option<String>,

    /// Path to settings used for VirusTotal operations
    #[arg(short = 's', long, default_value = "settings.json")]
    pub(crate) settings: String,

    /// Root directory for all Foxhole artifacts and logs
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub(crate) output: Option<PathBuf>,

    /// Delete artifacts and logs from the default Foxhole location
    #[arg(
        long = "clean-up",
        conflicts_with_all = [
            "path", "sandbox", "vt", "vts", "vtl", "vta", "hyperv_recover_run"
        ]
    )]
    pub(crate) clean_up: bool,

    /// Print diagnostic output
    #[arg(short, long)]
    pub(crate) debug: bool,

    /// Run the target using restricted, Hyper-V, or automatic backend selection
    #[arg(
        long = "sandbox",
        visible_alias = "vm",
        value_enum,
        num_args = 0..=1,
        default_missing_value = "restricted",
        conflicts_with_all = ["vt", "vts", "vtl", "vta"]
    )]
    pub(crate) sandbox: Option<CliSandboxBackend>,

    /// Permit `--sandbox auto` to fall back to weaker same-kernel isolation
    #[arg(long, requires = "sandbox")]
    pub(crate) allow_restricted_fallback: bool,

    /// Read-only Hyper-V base-image VHDX (or FOXHOLE_HYPERV_BASE_IMAGE)
    #[arg(long, value_name = "VHDX", requires = "sandbox")]
    pub(crate) hyperv_base_image: Option<PathBuf>,

    /// Protected sidecar manifest (or FOXHOLE_HYPERV_BASE_MANIFEST)
    #[arg(long, value_name = "JSON", requires = "sandbox")]
    pub(crate) hyperv_base_manifest: Option<PathBuf>,

    /// Protected gateway JSON (or FOXHOLE_HYPERV_GATEWAY_CONFIG)
    #[arg(long, value_name = "JSON", requires = "sandbox")]
    pub(crate) hyperv_gateway_config: Option<PathBuf>,

    /// Virtual processors assigned to a disposable Hyper-V guest
    #[arg(
        long,
        default_value_t = 2,
        value_parser = clap::value_parser!(u16).range(1..=64),
        requires = "sandbox"
    )]
    pub(crate) hyperv_cpu_count: u16,

    /// Startup memory assigned to a disposable Hyper-V guest
    #[arg(
        long,
        default_value_t = 2048,
        value_parser = clap::value_parser!(u64).range(512..=32768),
        requires = "sandbox"
    )]
    pub(crate) hyperv_memory_mib: u64,

    /// Maximum time to wait for the disposable guest to boot
    #[arg(
        long,
        default_value_t = 120,
        value_parser = clap::value_parser!(u64).range(1..=3600),
        requires = "sandbox"
    )]
    pub(crate) hyperv_boot_timeout: u64,

    /// Guest execution profile: restricted AppContainer, normal user, or guest LocalSystem
    #[arg(
        long = "hv-profile",
        value_enum,
        default_value_t = CliHyperVProfile::Restricted,
        requires = "sandbox"
    )]
    pub(crate) hyperv_profile: CliHyperVProfile,

    /// Recover one stale Hyper-V run below Foxhole's protected artifact root
    #[arg(
        long,
        value_name = "PROTECTED_RUN_DIRECTORY",
        conflicts_with_all = ["path", "sandbox", "vt", "vts", "vtl", "vta"]
    )]
    pub(crate) hyperv_recover_run: Option<PathBuf>,

    /// Stop the sandbox after this many seconds
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub(crate) timeout: u64,

    /// Grant the Windows AppContainer outbound internet-client capability
    #[arg(long)]
    pub(crate) allow_network: bool,

    /// Network policy (Hyper-V supports deny-all, host-server, and allow-internet)
    #[arg(long, value_enum, requires = "sandbox")]
    pub(crate) network_policy: Option<CliNetworkPolicy>,

    /// Allow a Hyper-V guest to contact only the configured host HTTP endpoint
    #[arg(long, requires = "sandbox", conflicts_with = "allow_external_network")]
    pub(crate) allow_host_server: bool,

    /// Allow a Hyper-V guest controlled outbound DNS and public internet access
    #[arg(long, requires = "sandbox", conflicts_with = "allow_host_server")]
    pub(crate) allow_external_network: bool,

    /// IPv4/IPv6 address or CIDR permitted by `--network-policy allow-list`
    #[arg(long = "allow-ip", value_name = "IP[/PREFIX]", requires = "sandbox")]
    pub(crate) allowed_networks: Vec<String>,

    /// Windows process-creation mitigation profile
    #[arg(long, value_enum, default_value_t = CliMitigationProfile::Compatible, requires = "sandbox")]
    pub(crate) mitigation_profile: CliMitigationProfile,

    /// Validate setup and write a report without launching the target
    #[arg(long, requires = "sandbox")]
    pub(crate) dry_run: bool,

    /// JSON report path relative to Foxhole's protected artifact directory
    #[arg(long, value_name = "FILE")]
    pub(crate) report: Option<PathBuf>,

    /// Do not write the JSON sandbox report
    #[arg(long, requires = "sandbox")]
    pub(crate) no_report: bool,

    /// Upload --path to VirusTotal (this sends the file to a third party)
    #[arg(long, conflicts_with_all = ["vts", "vtl", "vta"])]
    pub(crate) vt: bool,

    /// Upload a file up to 32 MiB to VirusTotal
    #[arg(long, value_name = "FILE", conflicts_with_all = ["vt", "vtl", "vta"])]
    pub(crate) vts: Option<String>,

    /// Upload a file up to 600 MiB to VirusTotal
    #[arg(long, value_name = "FILE", conflicts_with_all = ["vt", "vts", "vta"])]
    pub(crate) vtl: Option<String>,

    /// Retrieve a VirusTotal analysis by ID
    #[arg(long, value_name = "ID", conflicts_with_all = ["vt", "vts", "vtl"])]
    pub(crate) vta: Option<String>,

    /// Arguments passed to the sandbox target; place them after `--`
    #[arg(last = true)]
    pub(crate) target_args: Vec<String>,

    #[cfg(target_os = "windows")]
    #[arg(skip)]
    host_invocation: Option<report::HostInvocationInfo>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub(crate) enum CliNetworkPolicy {
    DenyAll,
    HostServer,
    AllowList,
    AllowInternet,
    CaptureOnly,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub(crate) enum CliSandboxBackend {
    Restricted,
    #[value(name = "hyperv")]
    HyperV,
    Auto,
}

impl From<CliSandboxBackend> for crate::sandbox::dispatcher::RequestedBackend {
    fn from(value: CliSandboxBackend) -> Self {
        match value {
            CliSandboxBackend::Restricted => Self::Restricted,
            CliSandboxBackend::HyperV => Self::HyperV,
            CliSandboxBackend::Auto => Self::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliMitigationProfile {
    Compatible,
    Strict,
    Maximum,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub(crate) enum CliHyperVProfile {
    #[value(name = "r", alias = "restricted")]
    Restricted,
    #[value(name = "n", alias = "normal")]
    Normal,
    #[value(name = "a", alias = "admin")]
    Admin,
}

pub async fn run_from_env() -> Result<(), Box<dyn Error>> {
    crate::interrupt::install_handler()?;
    #[cfg(target_os = "windows")]
    let raw_arguments = std::env::args_os().collect::<Vec<_>>();
    #[cfg(target_os = "windows")]
    let mut args = Args::parse_from(&raw_arguments);
    #[cfg(target_os = "windows")]
    {
        args.host_invocation = Some(capture_host_invocation(&raw_arguments, &args));
    }
    #[cfg(not(target_os = "windows"))]
    let args = Args::parse();
    if let Some(output) = args.output.as_deref() {
        artifact::configure_artifact_root(output)?;
        eprintln!(
            "[cli] output root: {}",
            utils::terminal_safe(&output.display().to_string())
        );
    }
    if args.clean_up {
        let removed = artifact::clean_default_artifacts_and_logs()?;
        if removed.is_empty() {
            println!("[cli] cleanup: no default artifact or log directories found");
        } else {
            for path in removed {
                println!(
                    "[cli] cleanup: removed {}",
                    utils::terminal_safe(&path.display().to_string())
                );
            }
        }
        return Ok(());
    }
    utils::debug_print(
        args.debug,
        "blue",
        format_args!(
            "arguments parsed: sandbox={}, dry_run={}, allow_network={}, target_arg_count={}, virus_total={}",
            args.sandbox
                .map(|backend| format!("{backend:?}"))
                .unwrap_or_else(|| "none".to_string()),
            args.dry_run,
            args.allow_network,
            args.target_args.len(),
            args.vt || args.vts.is_some() || args.vtl.is_some() || args.vta.is_some()
        ),
    );

    let wants_virus_total =
        args.vt || args.vts.is_some() || args.vtl.is_some() || args.vta.is_some();
    if wants_virus_total {
        let settings = utils::load_settings(&args.settings)?;
        virustotal_api::run_cli(&args, &settings).await?;
        return Ok(());
    }

    if let Some(run_root) = args.hyperv_recover_run.as_deref() {
        #[cfg(target_os = "windows")]
        {
            let outcome =
                sandbox::hyperv::recover_stale_run(run_root, std::time::Duration::from_secs(15))?;
            println!(
                "[hyperv] cleanup recovery: attempted={}, success={}, leftovers={}",
                outcome.attempted,
                outcome.success,
                outcome.leftover_resources.len()
            );
            for warning in &outcome.warnings {
                println!("[hyperv] warning: {}", utils::terminal_safe(warning));
            }
            for leftover in &outcome.leftover_resources {
                println!(
                    "[hyperv] retained resource: {}",
                    utils::terminal_safe(leftover)
                );
            }
            if !outcome.success {
                return Err("Hyper-V cleanup recovery retained resources; review the identifiers above and rerun recovery after correcting the host condition".into());
            }
            return Ok(());
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = run_root;
            return Err("Hyper-V cleanup recovery is available only on Windows hosts".into());
        }
    }

    let Some(path) = args.path.as_deref() else {
        return Err(
            "--path is required unless --vts, --vtl, or --vta supplies its own value".into(),
        );
    };

    // The Windows sandbox pins and validates the target without following links.
    // Do not perform a path-based metadata lookup first: an attacker-controlled
    // reparse point could otherwise make the broker access a remote or host path.
    #[cfg(target_os = "windows")]
    if args.sandbox.is_some() {
        run_sandbox(path, &args)?;
        return Ok(());
    }

    let path_check = utils::validate_path(path);
    if !path_check.is_valid {
        return Err(path_check
            .error_message
            .unwrap_or_else(|| "invalid path".to_string())
            .into());
    }

    #[cfg(not(target_os = "windows"))]
    if args.sandbox.is_some() {
        if path_check.type_ != ValiDPathType::File {
            return Err("sandbox execution requires a regular file target".into());
        }
        run_sandbox(path, &args)?;
        return Ok(());
    }

    match path_check.type_ {
        ValiDPathType::Directory => list_directory(path),
        ValiDPathType::File => {
            println!("[cli] target: {}", utils::terminal_safe(path));
        }
        ValiDPathType::Invalid | ValiDPathType::Url => unreachable!("validated path type"),
    }

    Ok(())
}

fn list_directory(path: &str) {
    println!("[cli] directory scan: {}", utils::terminal_safe(path));
    for entry in WalkDir::new(path) {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                println!(
                    "[cli] file: {}",
                    utils::terminal_safe(&entry.path().display().to_string())
                );
            }
            Ok(_) => {}
            Err(error) => eprintln!(
                "[cli] walk warning: {}",
                utils::terminal_safe(&error.to_string())
            ),
        }
    }
}

#[cfg(target_os = "windows")]
fn run_sandbox(path: &str, args: &Args) -> Result<(), Box<dyn Error>> {
    let report_destination = if args.no_report {
        None
    } else {
        Some(artifact::report_destination(
            args.report.as_deref(),
            Path::new(path),
        )?)
    };
    let requested = requested_backend(args)?;
    let capability = match requested {
        sandbox::dispatcher::RequestedBackend::Restricted => {
            sandbox::dispatcher::HyperVCapabilityEvidence::unavailable(
                "Hyper-V capability was not probed because restricted mode was explicitly requested",
            )
        }
        sandbox::dispatcher::RequestedBackend::HyperV
        | sandbox::dispatcher::RequestedBackend::Auto => hyperv_capability_evidence(),
    };
    let selection = sandbox::dispatcher::resolve_backend(
        requested,
        &capability,
        args.allow_restricted_fallback,
    )?;
    for warning in &selection.warnings {
        eprintln!("[cli] isolation warning: {}", utils::terminal_safe(warning));
    }

    let request = build_sandbox_request(path, args, selection.selected)?;
    match selection.selected {
        sandbox::backend::BackendKind::RestrictedProcess => eprintln!(
            "[cli] security warning: restricted-process isolation shares the Windows kernel; run hostile samples only inside a disposable VM"
        ),
        sandbox::backend::BackendKind::HyperV => {
            eprintln!("[cli] isolation: using a disposable Hyper-V guest with a separate kernel")
        }
    }
    println!(
        "[cli] starting {} with the {} backend",
        utils::terminal_safe(path),
        selection.selected
    );
    let run = execute_windows_backend(request.clone(), args, selection.selected)?;
    println!(
        "[sandbox] pid={} exit={:?} timed_out={} duration_ms={}",
        run.result.pid, run.result.exit_code, run.result.timed_out, run.result.duration_ms
    );

    if let Some(destination) = report_destination {
        let context = report::ReportContext {
            requested_backend: selection.requested.to_string(),
            selected_backend: selection.selected,
            fallback_used: selection.fallback_used,
            selection_warnings: selection.warnings,
            backend_metadata: run.metadata,
            stages: run.stages,
            host_invocation: args.host_invocation.clone(),
        };
        let report = report::AnalysisReport::new_with_context(
            &run.target_path,
            run.target_size_bytes,
            run.target_sha256,
            run.profile_name,
            &request,
            run.result,
            context,
        )?;
        let destination = report::write_report(&report, &destination)?;
        println!(
            "[cli] report written to {}",
            utils::terminal_safe(&destination.display().to_string())
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn capture_host_invocation(raw_arguments: &[OsString], args: &Args) -> report::HostInvocationInfo {
    let target_name = args
        .path
        .as_deref()
        .and_then(|path| Path::new(path).file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<target>".to_string());
    let mut tokens = vec!["foxhole.exe".to_string()];
    let mut after_separator = false;
    let mut redact_next_path = false;

    for raw in raw_arguments.iter().skip(1) {
        let value = raw.to_string_lossy();
        if after_separator {
            tokens.push("<redacted>".to_string());
            continue;
        }
        if value == "--" {
            after_separator = true;
            tokens.push(value.into_owned());
            continue;
        }
        if redact_next_path {
            tokens.push(target_name.clone());
            redact_next_path = false;
            continue;
        }
        if value == "--path" || value == "-p" {
            tokens.push(value.into_owned());
            redact_next_path = true;
            continue;
        }
        if value.starts_with("--path=") {
            tokens.push(format!("--path={target_name}"));
            continue;
        }
        tokens.push(value.into_owned());
    }

    report::HostInvocationInfo {
        format: "powershell",
        command_line: tokens
            .iter()
            .map(|token| powershell_argument(token))
            .collect::<Vec<_>>()
            .join(" "),
        output_root: args
            .output
            .as_deref()
            .map(|path| path.display().to_string()),
        report_path: args
            .report
            .as_deref()
            .map(|path| path.display().to_string()),
        allowed_networks: args.allowed_networks.clone(),
        target_argument_count: args.target_args.len(),
        target_arguments_redacted: !args.target_args.is_empty(),
    }
}

#[cfg(target_os = "windows")]
fn powershell_argument(value: &str) -> String {
    let safe = !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.' | ':' | '/' | '\\' | '?' | '=')
        });
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "''"))
    }
}

#[cfg(target_os = "windows")]
struct CompletedWindowsSandboxRun {
    result: crate::structs::SandboxRunResult,
    target_path: PathBuf,
    target_size_bytes: u64,
    target_sha256: String,
    profile_name: Option<String>,
    metadata: sandbox::backend::BackendMetadata,
    stages: Vec<sandbox::backend::ReportStage>,
}

#[cfg(target_os = "windows")]
fn execute_windows_backend(
    request: sandbox::backend::SandboxRequest,
    args: &Args,
    backend: sandbox::backend::BackendKind,
) -> Result<CompletedWindowsSandboxRun, Box<dyn Error>> {
    println!("[cli debug] in execute_windows_backend");
    match backend {
        sandbox::backend::BackendKind::RestrictedProcess => {
            let sandbox::WindowsSandboxRun {
                result,
                target_path,
                target_size_bytes,
                target_sha256,
                profile_name,
                metadata,
                stages,
            } = sandbox::start_with_request(request)?;
            Ok(CompletedWindowsSandboxRun {
                result,
                target_path,
                target_size_bytes,
                target_sha256,
                profile_name,
                metadata,
                stages,
            })
        }
        sandbox::backend::BackendKind::HyperV => {
            let config = build_hyperv_config(args)?;
            let run = sandbox::hyperv::start_with_request(request, config)?;
            Ok(CompletedWindowsSandboxRun {
                result: run.result,
                target_path: run.target_path,
                target_size_bytes: run.target_size_bytes,
                target_sha256: run.target_sha256,
                profile_name: Some(run.guest_image_version),
                metadata: run.metadata,
                stages: run.stages,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn run_sandbox(path: &str, args: &Args) -> Result<(), Box<dyn Error>> {
    let selection = resolve_non_windows_backend(args)?;
    for warning in &selection.warnings {
        eprintln!("[cli] isolation warning: {}", utils::terminal_safe(warning));
    }
    if selection.selected != sandbox::backend::BackendKind::RestrictedProcess {
        return Err("the selected backend is unavailable on this platform".into());
    }
    let flags = vec![
        crate::structs::UserNixFlags::USR_NEW_PID,
        crate::structs::UserNixFlags::USR_NEW_NET,
        crate::structs::UserNixFlags::USR_NEW_MOUNT,
    ];
    println!("[cli] starting {path} in sandbox");
    sandbox::start_in_sandbox(path, flags)?;
    eprintln!(
        "[cli] warning: structured sandbox reports are currently implemented on Windows only"
    );
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn run_sandbox(_path: &str, args: &Args) -> Result<(), Box<dyn Error>> {
    let selection = resolve_non_windows_backend(args)?;
    for warning in &selection.warnings {
        eprintln!("[cli] isolation warning: {}", utils::terminal_safe(warning));
    }
    Err(format!(
        "the {} backend is unavailable on this platform",
        selection.selected
    )
    .into())
}

#[cfg(not(target_os = "windows"))]
fn resolve_non_windows_backend(
    args: &Args,
) -> sandbox::backend::SandboxResult<sandbox::dispatcher::BackendSelection> {
    let requested = args.sandbox.map(Into::into).ok_or_else(|| {
        sandbox::backend::SandboxError::new(
            "backend_selection",
            "sandbox execution requires --sandbox or --vm",
        )
    })?;
    sandbox::dispatcher::resolve_backend(
        requested,
        &sandbox::dispatcher::HyperVCapabilityEvidence::unavailable(
            "Hyper-V is supported only on Windows hosts",
        ),
        args.allow_restricted_fallback,
    )
}

#[cfg(target_os = "windows")]
fn requested_backend(args: &Args) -> Result<sandbox::dispatcher::RequestedBackend, Box<dyn Error>> {
    let requested = args
        .sandbox
        .map(Into::into)
        .ok_or_else(|| Box::<dyn Error>::from("sandbox execution requires --sandbox or --vm"))?;
    if args.allow_restricted_fallback && requested != sandbox::dispatcher::RequestedBackend::Auto {
        return Err("--allow-restricted-fallback is valid only with --sandbox auto".into());
    }
    if requested == sandbox::dispatcher::RequestedBackend::Restricted
        && (args.hyperv_base_image.is_some()
            || args.hyperv_base_manifest.is_some()
            || args.hyperv_gateway_config.is_some()
            || args.allow_host_server
            || args.allow_external_network)
    {
        return Err(
            "Hyper-V image and gateway options cannot be used with --sandbox restricted".into(),
        );
    }
    Ok(requested)
}

#[cfg(any(target_os = "windows", test))]
fn build_sandbox_request(
    path: &str,
    args: &Args,
    backend: sandbox::backend::BackendKind,
) -> Result<sandbox::backend::SandboxRequest, Box<dyn Error>> {
    use sandbox::backend::{
        HyperVGuestProfile, IpNetwork, MitigationProfile, NetworkPolicy, SandboxRequest,
    };

    if backend != sandbox::backend::BackendKind::HyperV
        && (args.allow_host_server || args.allow_external_network)
    {
        return Err(
            "--allow-host-server and --allow-external-network require the Hyper-V backend".into(),
        );
    }
    if args.allow_host_server && args.allow_network {
        return Err("--allow-host-server conflicts with the legacy --allow-network alias".into());
    }
    let shortcut_policy = if args.allow_host_server {
        Some(CliNetworkPolicy::HostServer)
    } else if args.allow_external_network || args.allow_network {
        Some(CliNetworkPolicy::AllowInternet)
    } else {
        None
    };
    if let (Some(shortcut), Some(explicit)) = (shortcut_policy, args.network_policy)
        && shortcut != explicit
    {
        return Err(
            "the selected network shortcut conflicts with the explicitly supplied --network-policy"
                .into(),
        );
    }
    let selected_policy = shortcut_policy
        .or(args.network_policy)
        .unwrap_or(CliNetworkPolicy::DenyAll);
    if backend != sandbox::backend::BackendKind::HyperV
        && selected_policy == CliNetworkPolicy::HostServer
    {
        return Err("host-server network policy requires the Hyper-V backend".into());
    }
    let network_policy = match selected_policy {
        CliNetworkPolicy::DenyAll => NetworkPolicy::DenyAll,
        CliNetworkPolicy::HostServer => NetworkPolicy::HostServer,
        CliNetworkPolicy::AllowList => {
            if args.allowed_networks.is_empty() {
                return Err(
                    "--network-policy allow-list requires at least one --allow-ip entry".into(),
                );
            }
            NetworkPolicy::AllowList(
                args.allowed_networks
                    .iter()
                    .map(|entry| entry.parse::<IpNetwork>())
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        CliNetworkPolicy::AllowInternet => NetworkPolicy::AllowInternet,
        CliNetworkPolicy::CaptureOnly => NetworkPolicy::CaptureOnly,
    };
    if !matches!(network_policy, NetworkPolicy::AllowList(_)) && !args.allowed_networks.is_empty() {
        return Err("--allow-ip is only valid with --network-policy allow-list".into());
    }
    let mitigation_profile = match args.mitigation_profile {
        CliMitigationProfile::Compatible => MitigationProfile::Compatible,
        CliMitigationProfile::Strict => MitigationProfile::Strict,
        CliMitigationProfile::Maximum => MitigationProfile::Maximum,
    };
    let mut request = match backend {
        sandbox::backend::BackendKind::RestrictedProcess => SandboxRequest::restricted(path),
        sandbox::backend::BackendKind::HyperV => SandboxRequest::hyperv(path),
    };
    request.hyperv_guest_profile = match args.hyperv_profile {
        CliHyperVProfile::Restricted => HyperVGuestProfile::Restricted,
        CliHyperVProfile::Normal => HyperVGuestProfile::Normal,
        CliHyperVProfile::Admin => HyperVGuestProfile::Admin,
    };
    if backend == sandbox::backend::BackendKind::RestrictedProcess
        && request.hyperv_guest_profile != HyperVGuestProfile::Restricted
    {
        return Err("--hv-profile n|a requires the Hyper-V backend".into());
    }
    request.arguments = args.target_args.clone();
    request.timeout_secs = args.timeout;
    request.network_policy = network_policy;
    request.mitigation_profile = mitigation_profile;
    request.dry_run = args.dry_run;
    Ok(request)
}

#[cfg(target_os = "windows")]
fn hyperv_capability_evidence() -> sandbox::dispatcher::HyperVCapabilityEvidence {
    match sandbox::hyperv::detect_capability() {
        Ok(report) => match report.require_available() {
            Ok(()) => sandbox::dispatcher::HyperVCapabilityEvidence::available(),
            Err(error) => {
                sandbox::dispatcher::HyperVCapabilityEvidence::unavailable(error.to_string())
            }
        },
        Err(error) => sandbox::dispatcher::HyperVCapabilityEvidence::unavailable(error.to_string()),
    }
}

#[cfg(target_os = "windows")]
fn build_hyperv_config(args: &Args) -> Result<sandbox::hyperv::HyperVConfig, Box<dyn Error>> {
    let (base_image, base_manifest) = resolve_hyperv_image_paths(args)?;
    let mut config = sandbox::hyperv::HyperVConfig::new(base_image, base_manifest)?;
    config.processor_count = args.hyperv_cpu_count;
    config.startup_memory_bytes = args
        .hyperv_memory_mib
        .checked_mul(1024 * 1024)
        .ok_or("Hyper-V startup-memory value overflowed")?;
    config.boot_timeout_secs = args.hyperv_boot_timeout;
    config.controlled_gateway = configured_gateway_path(args)
        .map(|path| load_gateway_config(&path))
        .transpose()?;
    Ok(config)
}

#[cfg(target_os = "windows")]
fn resolve_hyperv_image_paths(args: &Args) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let base_image = args
        .hyperv_base_image
        .clone()
        .or_else(|| nonempty_environment_path(HYPERV_BASE_IMAGE_ENV))
        .unwrap_or_else(default_hyperv_base_image);
    let base_manifest = args
        .hyperv_base_manifest
        .clone()
        .or_else(|| nonempty_environment_path(HYPERV_BASE_MANIFEST_ENV))
        .unwrap_or_else(|| base_image.with_extension("manifest.json"));
    if !base_image.is_absolute() || !base_manifest.is_absolute() {
        return Err("Hyper-V base-image and manifest paths must be absolute local paths".into());
    }
    Ok((base_image, base_manifest))
}

#[cfg(target_os = "windows")]
fn configured_gateway_path(args: &Args) -> Option<PathBuf> {
    args.hyperv_gateway_config
        .clone()
        .or_else(|| nonempty_environment_path(HYPERV_GATEWAY_CONFIG_ENV))
}

#[cfg(target_os = "windows")]
fn nonempty_environment_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(target_os = "windows")]
fn default_hyperv_base_image() -> PathBuf {
    std::env::var_os("ProgramData")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Foxhole")
        .join("images")
        .join("foxhole-base.vhdx")
}

#[cfg(target_os = "windows")]
fn load_gateway_config(
    path: &Path,
) -> Result<sandbox::hyperv::ControlledGatewayConfig, Box<dyn Error>> {
    if !path.is_absolute() {
        return Err("Hyper-V gateway configuration path must be absolute".into());
    }
    let mut pinned = crate::host_file::open_pinned_input(path, MAX_GATEWAY_CONFIG_BYTES)?;
    let mut bytes = Vec::with_capacity(usize::try_from(pinned.len).unwrap_or(0));
    (&mut pinned.file)
        .take(MAX_GATEWAY_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != pinned.len {
        return Err("Hyper-V gateway configuration changed while it was being read".into());
    }
    Ok(decode_gateway_config(&bytes)?)
}

#[cfg(any(target_os = "windows", test))]
fn decode_gateway_config(
    bytes: &[u8],
) -> sandbox::backend::SandboxResult<sandbox::hyperv::ControlledGatewayConfig> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_GATEWAY_CONFIG_BYTES {
        return Err(sandbox::backend::SandboxError::new(
            "hyperv_configuration",
            "Hyper-V gateway configuration must be non-empty and no larger than 64 KiB",
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| {
        sandbox::backend::SandboxError::with_source(
            "hyperv_configuration",
            "parse strict Hyper-V gateway configuration JSON",
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("foxhole").chain(arguments.iter().copied())).unwrap()
    }

    #[test]
    fn clap_accepts_target_arguments_and_rejects_invalid_dependencies() {
        let args = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "--dry-run",
            "--",
            "--flag",
            "value",
        ]);
        assert_eq!(args.sandbox, Some(CliSandboxBackend::Restricted));
        assert_eq!(args.target_args, ["--flag", "value"]);
        assert!(Args::try_parse_from(["foxhole", "--dry-run"]).is_err());
        assert!(Args::try_parse_from(["foxhole", "--timeout", "0"]).is_err());
        assert!(Args::try_parse_from(["foxhole", "--network-policy", "deny-all"]).is_err());
    }

    #[test]
    fn output_and_cleanup_options_have_their_intended_scope() {
        let args = parse(&[
            "--output",
            r"C:\Foxhole\custom-output",
            "--path",
            "sample.exe",
        ]);
        assert_eq!(
            args.output.as_deref(),
            Some(std::path::Path::new(r"C:\Foxhole\custom-output"))
        );
        assert!(!args.clean_up);

        let cleanup = parse(&["--clean-up", "--output", r"C:\Foxhole\custom-output"]);
        assert!(cleanup.clean_up);
        assert_eq!(
            cleanup.output.as_deref(),
            Some(std::path::Path::new(r"C:\Foxhole\custom-output"))
        );
        assert!(Args::try_parse_from(["foxhole", "--clean-up", "--path", "sample.exe"]).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn recorded_host_invocation_keeps_options_and_redacts_target_inputs() {
        let raw = [
            "foxhole.exe",
            "--path",
            r"C:\Users\analyst\secret\sample.exe",
            "--output",
            r"C:\Foxhole Runs",
            "--sandbox",
            "hyperv",
            "--hv-profile",
            "n",
            "--network-policy",
            "allow-list",
            "--allow-ip",
            "192.0.2.8",
            "--",
            "--token",
            "secret-value",
        ]
        .map(OsString::from);
        let args = Args::try_parse_from(&raw).expect("parse host invocation");
        let invocation = capture_host_invocation(&raw, &args);

        assert!(
            invocation
                .command_line
                .contains("--output 'C:\\Foxhole Runs'")
        );
        assert!(invocation.command_line.contains("--hv-profile n"));
        assert!(invocation.command_line.contains("--allow-ip 192.0.2.8"));
        assert!(invocation.command_line.contains("--path sample.exe"));
        assert!(!invocation.command_line.contains(r"Users\analyst"));
        assert!(!invocation.command_line.contains("secret-value"));
        assert_eq!(invocation.target_argument_count, 2);
        assert_eq!(invocation.allowed_networks, ["192.0.2.8"]);
        assert!(invocation.target_arguments_redacted);
    }

    #[test]
    fn clap_supports_explicit_backend_selection_and_legacy_bare_flags() {
        for (arguments, expected) in [
            (
                vec!["--path", "sample.exe", "--sandbox"],
                CliSandboxBackend::Restricted,
            ),
            (
                vec!["--path", "sample.exe", "--sandbox", "restricted"],
                CliSandboxBackend::Restricted,
            ),
            (
                vec!["--path", "sample.exe", "--sandbox", "hyperv"],
                CliSandboxBackend::HyperV,
            ),
            (
                vec!["--path", "sample.exe", "--sandbox", "auto"],
                CliSandboxBackend::Auto,
            ),
            (
                vec!["--path", "sample.exe", "--vm"],
                CliSandboxBackend::Restricted,
            ),
            (
                vec!["--path", "sample.exe", "--vm", "hyperv"],
                CliSandboxBackend::HyperV,
            ),
            (
                vec!["--path", "sample.exe", "--vm", "auto"],
                CliSandboxBackend::Auto,
            ),
        ] {
            assert_eq!(parse(&arguments).sandbox, Some(expected));
        }

        let args = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "auto",
            "--allow-restricted-fallback",
            "--dry-run",
        ]);
        assert!(args.allow_restricted_fallback);
        assert!(args.dry_run);
        assert!(
            Args::try_parse_from(["foxhole", "--path", "sample.exe", "--sandbox", "unknown"])
                .is_err()
        );
    }

    #[test]
    fn cleanup_recovery_is_an_explicit_standalone_action() {
        let protected_run =
            r"C:\Users\tester\AppData\Local\Foxhole\artifacts\hyperv\runs\0123456789abcdef";
        let args = parse(&["--hyperv-recover-run", protected_run]);
        assert!(args.path.is_none());
        assert!(args.sandbox.is_none());
        assert_eq!(
            args.hyperv_recover_run.as_deref(),
            Some(std::path::Path::new(protected_run))
        );
        assert!(
            Args::try_parse_from([
                "foxhole",
                "--hyperv-recover-run",
                protected_run,
                "--path",
                "sample.exe",
            ])
            .is_err()
        );
    }

    #[test]
    fn selected_backend_is_carried_into_the_common_request() {
        let args = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "hyperv",
            "--network-policy",
            "allow-list",
            "--allow-ip",
            "192.0.2.0/24",
            "--mitigation-profile",
            "strict",
            "--timeout",
            "45",
            "--",
            "--flag",
        ]);
        let request =
            build_sandbox_request("sample.exe", &args, sandbox::backend::BackendKind::HyperV)
                .unwrap();
        assert_eq!(request.backend, sandbox::backend::BackendKind::HyperV);
        assert_eq!(request.timeout_secs, 45);
        assert_eq!(request.arguments, ["--flag"]);
        assert_eq!(
            request.mitigation_profile,
            sandbox::backend::MitigationProfile::Strict
        );
        assert!(matches!(
            request.network_policy,
            sandbox::backend::NetworkPolicy::AllowList(ref entries) if entries.len() == 1
        ));
    }

    #[test]
    fn controlled_network_shortcuts_are_mutually_exclusive_and_hyperv_only() {
        assert!(
            Args::try_parse_from([
                "foxhole",
                "--path",
                "sample.exe",
                "--sandbox",
                "hyperv",
                "--allow-host-server",
                "--allow-external-network",
            ])
            .is_err()
        );

        let default = parse(&["--path", "sample.exe", "--sandbox", "hyperv"]);
        let request = build_sandbox_request(
            "sample.exe",
            &default,
            sandbox::backend::BackendKind::HyperV,
        )
        .unwrap();
        assert_eq!(
            request.network_policy,
            sandbox::backend::NetworkPolicy::DenyAll
        );

        let host = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "hyperv",
            "--allow-host-server",
            "--network-policy",
            "host-server",
        ]);
        let request =
            build_sandbox_request("sample.exe", &host, sandbox::backend::BackendKind::HyperV)
                .unwrap();
        assert_eq!(
            request.network_policy,
            sandbox::backend::NetworkPolicy::HostServer
        );

        let conflicting = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "hyperv",
            "--allow-host-server",
            "--network-policy",
            "allow-internet",
        ]);
        assert!(
            build_sandbox_request(
                "sample.exe",
                &conflicting,
                sandbox::backend::BackendKind::HyperV,
            )
            .is_err()
        );

        let restricted = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "restricted",
            "--allow-external-network",
        ]);
        assert!(requested_backend(&restricted).is_err());
    }

    #[test]
    fn clap_parses_hyperv_resource_and_configuration_options() {
        let args = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "hyperv",
            "--hyperv-base-image",
            r"C:\ProgramData\Foxhole\images\base.vhdx",
            "--hyperv-base-manifest",
            r"C:\ProgramData\Foxhole\images\base.manifest.json",
            "--hyperv-gateway-config",
            r"C:\ProgramData\Foxhole\network\gateway.json",
            "--hyperv-cpu-count",
            "4",
            "--hyperv-memory-mib",
            "4096",
            "--hyperv-boot-timeout",
            "90",
        ]);
        assert_eq!(args.hyperv_cpu_count, 4);
        assert_eq!(args.hyperv_memory_mib, 4096);
        assert_eq!(args.hyperv_boot_timeout, 90);
        assert_eq!(
            args.hyperv_base_image.as_deref(),
            Some(std::path::Path::new(
                r"C:\ProgramData\Foxhole\images\base.vhdx"
            ))
        );
        assert_eq!(
            args.hyperv_base_manifest.as_deref(),
            Some(std::path::Path::new(
                r"C:\ProgramData\Foxhole\images\base.manifest.json"
            ))
        );
        assert_eq!(
            args.hyperv_gateway_config.as_deref(),
            Some(std::path::Path::new(
                r"C:\ProgramData\Foxhole\network\gateway.json"
            ))
        );

        assert!(
            Args::try_parse_from([
                "foxhole",
                "--path",
                "sample.exe",
                "--sandbox",
                "hyperv",
                "--hyperv-memory-mib",
                "511",
            ])
            .is_err()
        );
    }

    #[test]
    fn hyperv_guest_profiles_accept_short_and_long_names() {
        for (value, expected) in [
            ("r", CliHyperVProfile::Restricted),
            ("restricted", CliHyperVProfile::Restricted),
            ("n", CliHyperVProfile::Normal),
            ("normal", CliHyperVProfile::Normal),
            ("a", CliHyperVProfile::Admin),
            ("admin", CliHyperVProfile::Admin),
        ] {
            let args = parse(&[
                "--path",
                "sample.exe",
                "--sandbox",
                "hyperv",
                "--hv-profile",
                value,
            ]);
            assert_eq!(args.hyperv_profile, expected);
        }

        let args = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "hyperv",
            "--hv-profile",
            "n",
        ]);
        let request =
            build_sandbox_request("sample.exe", &args, sandbox::backend::BackendKind::HyperV)
                .unwrap();
        assert_eq!(
            request.hyperv_guest_profile,
            sandbox::backend::HyperVGuestProfile::Normal
        );
    }

    #[test]
    fn gateway_configuration_json_is_bounded_and_strict() {
        let valid = br#"{
            "switch_name":"Foxhole Private",
            "switch_id":"01234567-89ab-cdef-0123-456789abcdef",
            "switch_type":"private",
            "gateway_id":"gateway-01",
            "host_ipv4":"192.168.250.1",
            "prefix_length":24,
            "host_service_port":8080,
            "host_adapter_id":"11111111-1111-1111-1111-111111111111",
            "guest_address_start":"192.168.250.10",
            "guest_address_end":"192.168.250.20",
            "dns_servers":[],
            "gateway_ipv4":null,
            "allocation_directory":"C:\\ProgramData\\Foxhole\\network\\allocations",
            "firewall_enforced":true,
            "packet_capture_enabled":true,
            "host_private_ranges_blocked":true,
            "nat_enabled":false
        }"#;
        let decoded = decode_gateway_config(valid).unwrap();
        assert_eq!(decoded.switch_name, "Foxhole Private");
        assert!(!decoded.owned_by_run);

        let mut unknown = valid[..valid.len() - 1].to_vec();
        unknown.extend_from_slice(br#","unexpected":true}"#);
        assert!(decode_gateway_config(&unknown).is_err());

        let mut trailing_document = valid.to_vec();
        trailing_document.extend_from_slice(b"{}");
        assert!(decode_gateway_config(&trailing_document).is_err());
        assert!(decode_gateway_config(&[]).is_err());
        assert!(decode_gateway_config(&vec![b' '; MAX_GATEWAY_CONFIG_BYTES as usize + 1]).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_selection_fails_closed_without_explicit_fallback() {
        let explicit = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "hyperv",
            "--allow-restricted-fallback",
        ]);
        assert!(resolve_non_windows_backend(&explicit).is_err());

        let auto = parse(&["--path", "sample.exe", "--sandbox", "auto"]);
        assert!(resolve_non_windows_backend(&auto).is_err());

        let permitted = parse(&[
            "--path",
            "sample.exe",
            "--sandbox",
            "auto",
            "--allow-restricted-fallback",
        ]);
        let selected = resolve_non_windows_backend(&permitted).unwrap();
        assert_eq!(
            selected.selected,
            sandbox::backend::BackendKind::RestrictedProcess
        );
        assert!(selected.fallback_used);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandbox_dry_run_covers_every_network_and_mitigation_mode() {
        let target = std::env::current_exe().unwrap();
        let target = target.to_str().unwrap();
        let cases = [
            vec![
                "--network-policy",
                "deny-all",
                "--mitigation-profile",
                "compatible",
            ],
            vec![
                "--network-policy",
                "allow-list",
                "--allow-ip",
                "192.0.2.0/24",
                "--mitigation-profile",
                "strict",
            ],
            vec![
                "--network-policy",
                "allow-internet",
                "--mitigation-profile",
                "maximum",
            ],
            vec!["--network-policy", "capture-only"],
            vec!["--allow-network"],
        ];
        for extra in cases {
            let mut argv = vec!["--path", target, "--sandbox", "--dry-run", "--no-report"];
            argv.extend(extra);
            let args = parse(&argv);
            run_sandbox(target, &args).expect("valid dry-run mode");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandbox_option_security_failures_are_explicit() {
        let target = std::env::current_exe().unwrap();
        let target = target.to_str().unwrap();
        for argv in [
            vec![
                "--path",
                target,
                "--sandbox",
                "--dry-run",
                "--no-report",
                "--network-policy",
                "allow-list",
            ],
            vec![
                "--path",
                target,
                "--sandbox",
                "--dry-run",
                "--no-report",
                "--allow-ip",
                "192.0.2.1",
            ],
            vec![
                "--path",
                target,
                "--sandbox",
                "--dry-run",
                "--no-report",
                "--allow-network",
                "--network-policy",
                "capture-only",
            ],
            vec![
                "--path",
                target,
                "--sandbox",
                "--dry-run",
                "--no-report",
                "--network-policy",
                "allow-list",
                "--allow-ip",
                "invalid",
            ],
        ] {
            let args = parse(&argv);
            assert!(run_sandbox(target, &args).is_err());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn directory_listing_and_dry_run_report_paths_execute() {
        let directory =
            std::env::temp_dir().join(format!("foxhole-main-list-{}", std::process::id()));
        std::fs::create_dir_all(directory.join("nested")).unwrap();
        std::fs::write(directory.join("nested/file.txt"), b"file").unwrap();
        list_directory(directory.to_str().unwrap());
        std::fs::remove_dir_all(directory).unwrap();

        let target = std::env::current_exe().unwrap();
        let report_name = format!("self-test/main-{}.json", std::process::id());
        let destination =
            artifact::report_destination(Some(Path::new(&report_name)), &target).unwrap();
        if destination.exists() {
            std::fs::remove_file(&destination).unwrap();
        }
        let args = parse(&[
            "--path",
            target.to_str().unwrap(),
            "--sandbox",
            "--dry-run",
            "--report",
            &report_name,
        ]);
        run_sandbox(target.to_str().unwrap(), &args).unwrap();
        assert!(destination.exists());
        std::fs::remove_file(destination).unwrap();
    }

    #[tokio::test]
    async fn virus_total_requests_with_empty_api_key_fail_before_network_access() {
        let args = parse(&["--vta", "id"]);
        let settings: crate::structs::Settings =
            serde_json::from_str(include_str!("../settings.json")).unwrap();
        let mut settings = settings;
        settings.run_settings.vt_api.clear();
        assert!(virustotal_api::run_cli(&args, &settings).await.is_err());
    }
}
