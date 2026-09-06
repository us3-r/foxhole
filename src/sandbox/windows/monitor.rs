use crate::structs::{NetworkObservation, ProcessObservation};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

#[derive(Default)]
pub(super) struct MonitorResult {
    pub(super) processes: Vec<ProcessObservation>,
    pub(super) network_connections: Vec<NetworkObservation>,
    pub(super) warnings: Vec<String>,
}

pub(super) struct ActivityMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<MonitorResult>>,
}

impl ActivityMonitor {
    pub(super) fn spawn(
        worker: impl FnOnce(Arc<AtomicBool>) -> MonitorResult + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        Self {
            stop,
            thread: Some(thread::spawn(move || worker(worker_stop))),
        }
    }

    pub(super) fn stop_and_join(mut self) -> MonitorResult {
        self.stop.store(true, Ordering::Release);
        match self
            .thread
            .take()
            .expect("monitor thread is present")
            .join()
        {
            Ok(result) => result,
            Err(_) => MonitorResult {
                warnings: vec!["activity monitor thread panicked".to_string()],
                ..MonitorResult::default()
            },
        }
    }
}

impl Drop for ActivityMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_signals_worker_and_returns_observations() {
        let monitor = ActivityMonitor::spawn(|stop| {
            while !stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            MonitorResult {
                warnings: vec!["stopped".to_string()],
                ..MonitorResult::default()
            }
        });
        let result = monitor.stop_and_join();
        assert_eq!(result.warnings, ["stopped"]);
        assert!(result.processes.is_empty());
        assert!(result.network_connections.is_empty());
    }

    #[test]
    fn panicking_worker_becomes_a_warning() {
        let monitor = ActivityMonitor::spawn(|_| panic!("expected monitor panic"));
        let result = monitor.stop_and_join();
        assert_eq!(result.warnings, ["activity monitor thread panicked"]);
    }

    #[test]
    fn dropping_monitor_stops_and_joins_worker() {
        let monitor = ActivityMonitor::spawn(|stop| {
            while !stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            MonitorResult::default()
        });
        drop(monitor);
    }
}
