//! Windows AppContainer backend: staged workspace, restricted token, private desktop and WFP policy.
//! The process is verified while suspended and assigned to a kill-on-close Job before resuming.
mod desktop;
mod mitigations;
mod monitor;
mod network;
mod restricted_process;
mod token;
mod workspace;

pub use restricted_process::{RestrictedProcessBackend, WindowsSandboxRun, start_with_request};
