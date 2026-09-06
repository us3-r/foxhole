use crate::filesystem::GuestWorkspace;
use crate::monitor::ObservationAvailability;
use crate::network;
use crate::runner::{AgentError, AgentResult};
use foxhole::sandbox::hyperv::guest_protocol::{
    ArtifactManifestEntry, GuestMitigationProfile, GuestNetworkPolicy, GuestRunRequest,
};
use foxhole::structs::SandboxRunResult;

pub struct GuestExecution {
    pub result: SandboxRunResult,
    pub artifacts: Vec<ArtifactManifestEntry>,
    pub availability: ObservationAvailability,
}

pub trait GuestExecutor {
    fn execute(
        &mut self,
        request: &GuestRunRequest,
        workspace: &GuestWorkspace,
    ) -> AgentResult<GuestExecution>;
}

pub trait ShutdownController {
    fn request_shutdown(&mut self) -> AgentResult<()>;
}

pub struct SystemGuestExecutor;

#[cfg(target_os = "windows")]
impl GuestExecutor for SystemGuestExecutor {
    fn execute(
        &mut self,
        request: &GuestRunRequest,
        workspace: &GuestWorkspace,
    ) -> AgentResult<GuestExecution> {
        use foxhole::sandbox::backend::{MitigationProfile, ResourceLimits, SandboxRequest};
        use foxhole::sandbox::hyperv::guest_protocol::GuestExecutionProfile;
        use foxhole::sandbox::start_with_request;

        let process_memory_bytes = usize::try_from(request.resource_limits.process_memory_bytes)
            .map_err(|_| {
                AgentError::new(
                    "execution",
                    "memory_limit_overflow",
                    "per-process memory limit does not fit this guest architecture",
                )
            })?;
        let job_memory_bytes =
            usize::try_from(request.resource_limits.job_memory_bytes).map_err(|_| {
                AgentError::new(
                    "execution",
                    "memory_limit_overflow",
                    "job memory limit does not fit this guest architecture",
                )
            })?;

        let telemetry = crate::telemetry::TelemetrySession::start(workspace);

        if request.execution_profile != GuestExecutionProfile::Restricted {
            let mut result = crate::native_process::execute(request, workspace)?;
            let observed = telemetry.finish(workspace, result.pid);
            let mut availability = observed.availability;
            availability.processes = true;
            merge_telemetry(&mut result, &observed);
            if request.execution_profile == GuestExecutionProfile::Admin {
                result.monitor_warnings.push(
                    "administrator-profile targets run as LocalSystem and can tamper with in-guest telemetry; the Hyper-V host boundary remains the security boundary"
                        .to_string(),
                );
            }
            return Ok(GuestExecution {
                result,
                artifacts: observed.artifacts,
                availability,
            });
        }

        let mut sandbox_request = SandboxRequest::restricted(&workspace.target);
        sandbox_request.arguments = request.arguments.clone();
        sandbox_request.timeout_secs = request.timeout_seconds;
        sandbox_request.network_policy = network::sandbox_network_policy(request)?;
        sandbox_request.mitigation_profile = match request.mitigation_profile {
            GuestMitigationProfile::Compatible => MitigationProfile::Compatible,
            GuestMitigationProfile::Strict => MitigationProfile::Strict,
            GuestMitigationProfile::Maximum => MitigationProfile::Maximum,
        };
        sandbox_request.resource_limits = ResourceLimits {
            active_process_limit: request.resource_limits.active_process_limit,
            process_memory_bytes,
            job_memory_bytes,
            cpu_rate_percent: request.resource_limits.cpu_rate_percent,
        };
        sandbox_request.mapped_paths.clear();
        sandbox_request.dry_run = false;

        let run = start_with_request(sandbox_request).map_err(|error| {
            AgentError::new(
                "execution",
                "restricted_runner_failed",
                format!("run the target through the restricted guest backend: {error}"),
            )
        })?;
        let mut result = run.result;
        // HostServer is represented as a narrow IP allow-list inside the optional restricted
        // guest profile, while the Hyper-V firewall enforces the TCP port. Preserve the
        // authenticated outer policy name in the guest result.
        if request.network_policy == GuestNetworkPolicy::HostServer {
            result.network_policy = "host_server".to_string();
        }
        let expected_integrity = if request.mitigation_profile == GuestMitigationProfile::Maximum {
            "untrusted"
        } else {
            "low"
        };
        if result.backend != "restricted_process"
            || result.integrity_level != expected_integrity
            || result.pid == 0
        {
            return Err(AgentError::new(
                "execution",
                "restriction_verification_failed",
                "restricted runner did not attest the expected AppContainer integrity level",
            ));
        }
        if !result.cleanup.attempted {
            return Err(AgentError::new(
                "execution",
                "cleanup_not_attempted",
                "restricted runner returned without attempting guest process cleanup",
            ));
        }
        let observed = telemetry.finish(workspace, result.pid);
        merge_telemetry(&mut result, &observed);
        let availability = ObservationAvailability {
            processes: true,
            network: true,
            filesystem: true,
            registry: observed.availability.registry,
        };
        Ok(GuestExecution {
            result,
            artifacts: observed.artifacts,
            availability,
        })
    }
}

#[cfg(target_os = "windows")]
fn merge_telemetry(result: &mut SandboxRunResult, observed: &crate::telemetry::TelemetryResult) {
    result.processes.extend(observed.processes.iter().cloned());
    result.processes.sort_by(|left, right| {
        (left.observed_at_ms, left.pid, left.parent_pid, &left.image).cmp(&(
            right.observed_at_ms,
            right.pid,
            right.parent_pid,
            &right.image,
        ))
    });
    result.processes.dedup();

    result
        .network_connections
        .extend(observed.network_connections.iter().cloned());
    result.network_connections.sort_by(|left, right| {
        (
            left.observed_at_ms,
            left.pid,
            &left.protocol,
            &left.local_address,
            left.local_port,
            &left.remote_address,
            left.remote_port,
            &left.state,
        )
            .cmp(&(
                right.observed_at_ms,
                right.pid,
                &right.protocol,
                &right.local_address,
                right.local_port,
                &right.remote_address,
                right.remote_port,
                &right.state,
            ))
    });
    result.network_connections.dedup();

    result
        .file_observations
        .extend(observed.file_observations.iter().cloned());
    result.file_observations.sort_by(|left, right| {
        (
            left.observed_at_ms,
            &left.relative_path,
            left.size_bytes,
            &left.kind,
            &left.sha256,
            &left.hash_source,
        )
            .cmp(&(
                right.observed_at_ms,
                &right.relative_path,
                right.size_bytes,
                &right.kind,
                &right.sha256,
                &right.hash_source,
            ))
    });
    result.file_observations.dedup();

    result
        .registry_observations
        .extend(observed.registry_observations.iter().cloned());
    result.registry_observations.sort_by(|left, right| {
        (left.observed_at_ms, &left.key, &left.operation).cmp(&(
            right.observed_at_ms,
            &right.key,
            &right.operation,
        ))
    });
    result.registry_observations.dedup();
    result
        .monitor_warnings
        .extend(observed.warnings.iter().cloned());
}

#[cfg(not(target_os = "windows"))]
impl GuestExecutor for SystemGuestExecutor {
    fn execute(
        &mut self,
        _request: &GuestRunRequest,
        _workspace: &GuestWorkspace,
    ) -> AgentResult<GuestExecution> {
        Err(AgentError::new(
            "execution",
            "unsupported_guest_os",
            "the Foxhole guest executor requires Windows",
        ))
    }
}

pub struct SystemShutdownController;

#[cfg(target_os = "windows")]
impl ShutdownController for SystemShutdownController {
    fn request_shutdown(&mut self) -> AgentResult<()> {
        use std::path::PathBuf;
        use std::process::Command;

        let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
            AgentError::new(
                "shutdown",
                "missing_system_root",
                "SystemRoot is unavailable",
            )
        })?;
        let shutdown = PathBuf::from(system_root)
            .join("System32")
            .join("shutdown.exe");
        let status = Command::new(&shutdown)
            .args(["/s", "/t", "0", "/d", "p:0:0"])
            .status()
            .map_err(|error| {
                AgentError::with_source(
                    "shutdown",
                    "start_shutdown",
                    format!("start {}", shutdown.display()),
                    error,
                )
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(AgentError::new(
                "shutdown",
                "shutdown_rejected",
                format!("shutdown.exe exited with {status}"),
            ))
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl ShutdownController for SystemShutdownController {
    fn request_shutdown(&mut self) -> AgentResult<()> {
        Err(AgentError::new(
            "shutdown",
            "unsupported_guest_os",
            "guest shutdown is only supported on Windows",
        ))
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct NoopShutdownController {
    pub requests: usize,
}

#[cfg(test)]
impl ShutdownController for NoopShutdownController {
    fn request_shutdown(&mut self) -> AgentResult<()> {
        self.requests += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_shutdown_records_requests_without_touching_the_machine() {
        let mut shutdown = NoopShutdownController::default();
        shutdown.request_shutdown().unwrap();
        assert_eq!(shutdown.requests, 1);
    }
}
