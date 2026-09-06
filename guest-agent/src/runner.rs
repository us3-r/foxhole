use crate::artifacts::{RunClaim, StartDecision, StatusPublisher, sha256_file};
use crate::filesystem::GuestWorkspace;
use crate::process::{GuestExecutor, ShutdownController};
use crate::{result, result::protocol_error};
use foxhole::sandbox::hyperv::guest_protocol::{
    GuestError, GuestNetworkAttestation, GuestTerminalOutcome, MAX_REQUEST_BYTES,
    MAX_WARNING_BYTES, ProtocolState,
};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

pub type AgentResult<T> = Result<T, AgentError>;

#[derive(Clone, Debug)]
pub struct AgentError {
    pub stage: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl AgentError {
    pub fn new(stage: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            code,
            message: sanitize_message(message.into()),
        }
    }

    pub fn with_source(
        stage: &'static str,
        code: &'static str,
        message: impl Into<String>,
        source: impl fmt::Display,
    ) -> Self {
        Self::new(stage, code, format!("{}: {source}", message.into()))
    }

    pub fn to_guest_error(&self) -> GuestError {
        GuestError::new(self.stage, self.code, self.message.clone())
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}: {}", self.stage, self.code, self.message)
    }
}

impl Error for AgentError {}

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub run_root: PathBuf,
    pub staging_root: PathBuf,
    pub agent_version: String,
    pub guest_image_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSummary {
    pub run_id: String,
    pub outcome: GuestTerminalOutcome,
    pub result_path: PathBuf,
    pub shutdown_requested: bool,
}

pub fn run<E: GuestExecutor, S: ShutdownController>(
    config: &AgentConfig,
    executor: &mut E,
    shutdown: &mut S,
) -> AgentResult<RunSummary> {
    let layout = crate::request::RunLayout::open(&config.run_root)?;
    let request_digest_before = sha256_file(&layout.request, MAX_REQUEST_BYTES)?;
    let request = layout.load_request()?;
    let request_digest_after = sha256_file(&layout.request, MAX_REQUEST_BYTES)?;
    if request_digest_before != request_digest_after {
        return Err(AgentError::new(
            "request",
            "request_changed",
            "request.json changed while it was being validated",
        ));
    }

    let mut publisher =
        StatusPublisher::open(&layout, &request.run_id, request_digest_before.clone())?;
    let _claim = RunClaim::acquire(&layout, &request.run_id, &config.agent_version)?;

    if publisher.has_seen(ProtocolState::CancelRequested) {
        return finish_cancelled(&layout, &request, config, &mut publisher, shutdown, None);
    }

    // The service-hosted guest agent is trusted. It configures and attests the sole NIC before
    // GuestReady, so the tested process never runs while DHCP, DNS, routes, or IPv6 are broader
    // than the authenticated host request.
    let network_attestation = match crate::network::configure_trusted_nic(&request) {
        Ok(attestation) => attestation,
        Err(error) => {
            finish_failed(
                &layout,
                &request,
                config,
                &mut publisher,
                shutdown,
                &error,
                None,
            )?;
            return Err(error);
        }
    };
    publisher.publish(ProtocolState::GuestReady, None, None)?;
    if publisher.wait_for_start_or_cancel()? == StartDecision::Cancel {
        return finish_cancelled(
            &layout,
            &request,
            config,
            &mut publisher,
            shutdown,
            network_attestation,
        );
    }

    let execution = execute_claimed_run(
        &layout,
        &request,
        config,
        executor,
        &mut publisher,
        network_attestation.as_ref(),
    );
    let (outcome, result_digest) = match execution {
        Ok(value) => value,
        Err(error) => {
            finish_failed(
                &layout,
                &request,
                config,
                &mut publisher,
                shutdown,
                &error,
                network_attestation,
            )?;
            return Err(error);
        }
    };

    publisher.publish(ProtocolState::Completed, None, Some(result_digest.clone()))?;
    publisher.publish(ProtocolState::ShutdownReady, None, Some(result_digest))?;
    let shutdown_requested = request.shutdown_when_complete;
    if shutdown_requested {
        shutdown.request_shutdown()?;
    }
    Ok(RunSummary {
        run_id: request.run_id,
        outcome,
        result_path: layout.output.join("result.json"),
        shutdown_requested,
    })
}

fn execute_claimed_run<E: GuestExecutor>(
    layout: &crate::request::RunLayout,
    request: &foxhole::sandbox::hyperv::guest_protocol::GuestRunRequest,
    config: &AgentConfig,
    executor: &mut E,
    publisher: &mut StatusPublisher,
    network_attestation: Option<&GuestNetworkAttestation>,
) -> AgentResult<(GuestTerminalOutcome, String)> {
    let mut workspace = GuestWorkspace::stage(layout, request, &config.staging_root)?;
    publisher.publish(ProtocolState::Running, None, None)?;
    let execution_result = executor.execute(request, &workspace);
    let cleanup_result = workspace.cleanup();
    let execution = execution_result?;
    let mut warnings = Vec::new();
    if !execution.result.cleanup.success {
        warnings.extend(execution.result.cleanup.warnings.iter().cloned());
    }
    if let Err(error) = cleanup_result {
        warnings.push(error.to_string());
    }
    let envelope = result::completed(
        request,
        execution.result,
        execution.artifacts,
        execution.availability,
        network_attestation.cloned(),
        &config.agent_version,
        &config.guest_image_version,
        warnings,
    );
    let outcome = envelope.outcome;
    let digest = result::write(layout, &envelope)?;
    Ok((outcome, digest))
}

fn finish_failed<S: ShutdownController>(
    layout: &crate::request::RunLayout,
    request: &foxhole::sandbox::hyperv::guest_protocol::GuestRunRequest,
    config: &AgentConfig,
    publisher: &mut StatusPublisher,
    shutdown: &mut S,
    error: &AgentError,
    network_attestation: Option<GuestNetworkAttestation>,
) -> AgentResult<()> {
    result::prepare_failed_publication(layout)?;
    let envelope = result::failed(
        request,
        &config.agent_version,
        &config.guest_image_version,
        error,
        network_attestation,
    );
    let result_digest = result::write(layout, &envelope).ok();
    publisher.publish(
        ProtocolState::Failed,
        Some(protocol_error(error)),
        result_digest.clone(),
    )?;
    publisher.publish(ProtocolState::ShutdownReady, None, result_digest)?;
    if request.shutdown_when_complete {
        shutdown.request_shutdown()?;
    }
    Ok(())
}

fn finish_cancelled<S: ShutdownController>(
    layout: &crate::request::RunLayout,
    request: &foxhole::sandbox::hyperv::guest_protocol::GuestRunRequest,
    config: &AgentConfig,
    publisher: &mut StatusPublisher,
    shutdown: &mut S,
    network_attestation: Option<GuestNetworkAttestation>,
) -> AgentResult<RunSummary> {
    let envelope = result::cancelled(
        request,
        &config.agent_version,
        &config.guest_image_version,
        network_attestation,
    );
    let result_digest = result::write(layout, &envelope)?;
    publisher.publish(ProtocolState::ShutdownReady, None, Some(result_digest))?;
    let shutdown_requested = request.shutdown_when_complete;
    if shutdown_requested {
        shutdown.request_shutdown()?;
    }
    Ok(RunSummary {
        run_id: request.run_id.clone(),
        outcome: GuestTerminalOutcome::Cancelled,
        result_path: layout.output.join("result.json"),
        shutdown_requested,
    })
}

fn sanitize_message(mut message: String) -> String {
    message = message
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\t' | '\n') {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect();
    if message.len() > MAX_WARNING_BYTES {
        let mut end = MAX_WARNING_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    if message.is_empty() {
        "unspecified guest-agent failure".to_string()
    } else {
        message
    }
}

pub fn default_staging_root() -> AgentResult<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let program_data = std::env::var_os("ProgramData").ok_or_else(|| {
            AgentError::new(
                "configuration",
                "missing_program_data",
                "ProgramData is unavailable",
            )
        })?;
        Ok(PathBuf::from(program_data)
            .join("Foxhole")
            .join("GuestRuns"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(AgentError::new(
            "configuration",
            "unsupported_guest_os",
            "default staging root is only defined for Windows guests",
        ))
    }
}

pub fn validate_version_field(name: &str, value: &str) -> AgentResult<()> {
    if value.is_empty() || value.len() > 128 || value.contains('\0') {
        Err(AgentError::new(
            "configuration",
            "invalid_version",
            format!("{name} is empty or exceeds 128 bytes"),
        ))
    } else {
        Ok(())
    }
}

pub fn require_absolute_path(name: &str, path: &Path) -> AgentResult<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(AgentError::new(
            "configuration",
            "relative_path",
            format!("{name} must be absolute"),
        ))
    }
}
