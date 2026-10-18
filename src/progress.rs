//! Line-oriented progress on stderr, including a heartbeat during long operations.
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn set_debug(enabled: bool) {
    DEBUG.store(enabled, std::sync::atomic::Ordering::Relaxed);
}
pub fn debug(message: std::fmt::Arguments<'_>) {
    if DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("{message}");
    }
}

pub struct Stage {
    label: &'static str,
    started: Instant,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
    outcome: &'static str,
}
impl Stage {
    pub fn start(label: &'static str) -> Self {
        let started = Instant::now();
        eprintln!("[run ] {label}");
        let (send, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            while matches!(
                receive.recv_timeout(Duration::from_secs(10)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("[run ] {label} ({}s elapsed)", started.elapsed().as_secs());
            }
        });
        Self {
            label,
            started,
            stop: Some(send),
            worker: Some(worker),
            outcome: "fail",
        }
    }
    pub fn finish(mut self, success: bool) {
        self.outcome = if success { "done" } else { "fail" };
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        eprintln!(
            "[{}] {} ({:.1}s)",
            self.outcome,
            self.label,
            self.started.elapsed().as_secs_f32()
        );
    }
}
