mod backend;
mod base_image;
mod capability;
mod cleanup;
mod data_disk;
mod disk;
pub mod guest_protocol;
mod network;
mod powershell;
mod result_collector;
mod vm;

pub use backend::{HyperVBackend, HyperVConfig, HyperVSandboxRun, start_with_request};
pub use capability::{CapabilityIssue, CapabilityReport};
pub use cleanup::{CleanupOutcome, recover_stale_run};
pub use network::{ControlledGatewayConfig, ControlledSwitchType};
pub use result_collector::CollectionLimits;

/// Probe whether this host can safely manage disposable Hyper-V guests.
///
/// Callers must still treat preparation failures as failures of the selected
/// backend; this probe is only backend-selection evidence.
pub fn detect_capability() -> crate::sandbox::backend::SandboxResult<CapabilityReport> {
    capability::detect(&powershell::NativePowerShell)
}

#[cfg(test)]
mod tests;
