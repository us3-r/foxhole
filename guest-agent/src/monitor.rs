use crate::registry;
use foxhole::sandbox::hyperv::guest_protocol::{
    CaptureCoverage, GuestRunRequest, ObservationCoverage,
};
use foxhole::structs::{SandboxRunResult, StreamCaptureSummary};

#[derive(Clone, Copy, Debug, Default)]
pub struct ObservationAvailability {
    pub processes: bool,
    pub network: bool,
    pub filesystem: bool,
    pub registry: bool,
}

pub fn apply_capture_policy(
    request: &GuestRunRequest,
    result: &mut SandboxRunResult,
    available: ObservationAvailability,
) -> ObservationCoverage {
    let stdout = stream_coverage(
        request.capture.stdout,
        result.stdout_capture.truncated,
        "stdout was truncated by the bounded guest runner",
    );
    if !request.capture.stdout {
        result.stdout.clear();
        result.stdout_capture = empty_stream();
    }

    let stderr = stream_coverage(
        request.capture.stderr,
        result.stderr_capture.truncated,
        "stderr was truncated by the bounded guest runner",
    );
    if !request.capture.stderr {
        result.stderr.clear();
        result.stderr_capture = empty_stream();
    }

    let processes = observation_coverage(
        request.capture.processes,
        available.processes,
        "process telemetry is bounded and can be evaded or tampered with by an administrator-level target",
        "process telemetry was unavailable",
    );
    if !request.capture.processes {
        result.processes.clear();
    }

    let network = observation_coverage(
        request.capture.network,
        available.network,
        "network telemetry is bounded; encrypted protocols do not expose plaintext headers or payloads",
        "network telemetry was unavailable",
    );
    if !request.capture.network {
        result.network_connections.clear();
    }

    let filesystem = observation_coverage(
        request.capture.filesystem,
        available.filesystem,
        "filesystem telemetry is bounded and does not guarantee observation of every read",
        "filesystem telemetry was unavailable",
    );
    if !request.capture.filesystem {
        result.file_observations.clear();
    }

    let registry = if available.registry {
        observation_coverage(
            request.capture.registry,
            true,
            "registry telemetry is bounded and can be evaded or tampered with by an administrator-level target",
            "registry telemetry was unavailable",
        )
    } else {
        registry::coverage(request.capture.registry)
    };
    if !request.capture.registry {
        result.registry_observations.clear();
    }

    ObservationCoverage {
        stdout,
        stderr,
        processes,
        network,
        filesystem,
        registry,
    }
}

fn observation_coverage(
    requested: bool,
    available: bool,
    warning: &str,
    unavailable_reason: &str,
) -> CaptureCoverage {
    if available {
        captured(requested, false, warning)
    } else {
        CaptureCoverage::unavailable(requested, unavailable_reason)
    }
}

pub fn unavailable_coverage(request: &GuestRunRequest, reason: &str) -> ObservationCoverage {
    ObservationCoverage {
        stdout: CaptureCoverage::unavailable(request.capture.stdout, reason),
        stderr: CaptureCoverage::unavailable(request.capture.stderr, reason),
        processes: CaptureCoverage::unavailable(request.capture.processes, reason),
        network: CaptureCoverage::unavailable(request.capture.network, reason),
        filesystem: CaptureCoverage::unavailable(request.capture.filesystem, reason),
        registry: CaptureCoverage::unavailable(request.capture.registry, reason),
    }
}

fn stream_coverage(requested: bool, truncated: bool, warning: &str) -> CaptureCoverage {
    captured(requested, !truncated, warning)
}

fn captured(requested: bool, complete: bool, warning: &str) -> CaptureCoverage {
    if !requested {
        return CaptureCoverage {
            requested: false,
            collected: false,
            complete: true,
            warnings: Vec::new(),
        };
    }
    CaptureCoverage {
        requested: true,
        collected: true,
        complete,
        warnings: (!complete)
            .then(|| warning.to_string())
            .into_iter()
            .collect(),
    }
}

fn empty_stream() -> StreamCaptureSummary {
    StreamCaptureSummary {
        bytes_seen: 0,
        bytes_stored: 0,
        truncated: false,
    }
}
