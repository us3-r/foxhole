use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static HANDLER: OnceLock<Result<(), String>> = OnceLock::new();

/// Install a process-wide Ctrl+C handler. The handler deliberately only sets
/// a flag; cleanup continues on the normal execution thread where it is safe
/// to stop jobs/VMs and remove their resources.
pub fn install_handler() -> Result<(), String> {
    HANDLER
        .get_or_init(|| {
            ctrlc::set_handler(|| {
                INTERRUPTED.store(true, Ordering::SeqCst);
            })
            .map_err(|error| format!("install Ctrl+C handler: {error}"))
        })
        .clone()
}

pub fn requested() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Cleanup may use the same cancellable command runner as execution. Consume
/// the request before cleanup so the interrupt unwinds the run without also
/// aborting the cleanup operations it triggered.
pub(crate) fn begin_cleanup() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    #[test]
    fn handler_installation_is_idempotent() {
        super::install_handler().expect("first handler installation");
        super::install_handler().expect("repeated handler installation");
        assert!(!super::requested());
    }
}
