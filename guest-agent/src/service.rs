use crate::runner::{AgentError, AgentResult};
use std::ffi::{OsString, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::Duration;
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_SPECIFIC_ERROR,
    NO_ERROR,
};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows::core::{PCWSTR, PWSTR};

const SERVICE_NAME: &str = "FoxholeAgent";
const STATUS_WAIT_HINT_MILLIS: u32 = 15_000;
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(500);

static CONFIGURATION_ARGUMENTS: Mutex<Option<Vec<OsString>>> = Mutex::new(None);
static SERVICE_RESULT: Mutex<Option<AgentResult<()>>> = Mutex::new(None);
static STATUS_UPDATE: Mutex<()> = Mutex::new(());
static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static START_CHECKPOINT: AtomicU32 = AtomicU32::new(1);
static STOP_CHECKPOINT: AtomicU32 = AtomicU32::new(0);

pub fn run_dispatcher(configuration_arguments: Vec<OsString>) -> AgentResult<()> {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
    START_CHECKPOINT.store(1, Ordering::SeqCst);
    STOP_CHECKPOINT.store(0, Ordering::SeqCst);
    STATUS_HANDLE.store(std::ptr::null_mut(), Ordering::SeqCst);
    *lock(&SERVICE_RESULT) = None;
    {
        let mut stored_arguments = lock(&CONFIGURATION_ARGUMENTS);
        if stored_arguments.is_some() {
            return Err(AgentError::new(
                "service",
                "dispatcher_already_started",
                "the service dispatcher may only be started once per process",
            ));
        }
        *stored_arguments = Some(configuration_arguments);
    }

    let mut service_name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    let dispatcher_result = unsafe { StartServiceCtrlDispatcherW(service_table.as_ptr()) };
    if let Err(error) = dispatcher_result {
        *lock(&CONFIGURATION_ARGUMENTS) = None;
        return Err(AgentError::with_source(
            "service",
            "start_dispatcher",
            "connect foxhole-agent to the Windows Service Control Manager",
            error,
        ));
    }

    lock(&SERVICE_RESULT).take().unwrap_or_else(|| {
        Err(AgentError::new(
            "service",
            "missing_service_result",
            "the service entry point returned without recording an outcome",
        ))
    })
}

unsafe extern "system" fn service_main(_argument_count: u32, _argument_vectors: *mut PWSTR) {
    let mut outcome = std::panic::catch_unwind(service_main_inner).unwrap_or_else(|_| {
        Err(AgentError::new(
            "service",
            "service_panic",
            "the service entry point panicked",
        ))
    });

    let stopped_status = if outcome.is_ok() {
        report_status(SERVICE_STOPPED, 0, NO_ERROR.0, 0, 0, 0)
    } else {
        report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR.0, 1, 0, 0)
    };
    if let Err(status_error) = stopped_status {
        if outcome.is_ok() {
            outcome = Err(status_error);
        } else {
            crate::write_stderr(format_args!(
                "[foxhole-agent] additionally failed to publish STOPPED: {status_error}"
            ));
        }
    }
    if let Err(error) = &outcome {
        crate::write_stderr(format_args!("[foxhole-agent] {error}"));
    }
    *lock(&SERVICE_RESULT) = Some(outcome);
}

fn service_main_inner() -> AgentResult<()> {
    let service_name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(service_name.as_ptr()), Some(control_handler), None)
    }
    .map_err(|error| {
        AgentError::with_source(
            "service",
            "register_control_handler",
            "register the foxhole-agent service control handler",
            error,
        )
    })?;
    STATUS_HANDLE.store(handle.0, Ordering::SeqCst);
    report_status(
        SERVICE_START_PENDING,
        0,
        NO_ERROR.0,
        0,
        1,
        STATUS_WAIT_HINT_MILLIS,
    )?;

    let configuration_arguments = lock(&CONFIGURATION_ARGUMENTS).take().ok_or_else(|| {
        AgentError::new(
            "service",
            "missing_configuration",
            "service configuration arguments were unavailable",
        )
    })?;
    let (configuration_sender, configuration_receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("foxhole-agent-startup".to_string())
        .spawn(move || {
            let _ = configuration_sender.send(crate::parse_configuration(configuration_arguments));
        })
        .map_err(|error| {
            AgentError::with_source(
                "service",
                "start_configuration_worker",
                "start the guest-agent configuration worker",
                error,
            )
        })?;

    let config = loop {
        match configuration_receiver.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(result) => break result?,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                report_status(
                    SERVICE_START_PENDING,
                    0,
                    NO_ERROR.0,
                    0,
                    next_start_checkpoint(),
                    STATUS_WAIT_HINT_MILLIS,
                )?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(AgentError::new(
                    "service",
                    "configuration_worker_disconnected",
                    "the guest-agent configuration worker exited without an outcome",
                ));
            }
        }
    };
    report_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        NO_ERROR.0,
        0,
        0,
        0,
    )?;

    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("foxhole-agent-runner".to_string())
        .spawn(move || {
            let _ = sender.send(crate::execute(config));
        })
        .map_err(|error| {
            AgentError::with_source(
                "service",
                "start_worker",
                "start the guest execution worker",
                error,
            )
        })?;

    let execution = loop {
        match receiver.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(result) => break result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if STOP_REQUESTED.load(Ordering::SeqCst)
                    && let Err(error) = report_status(
                        SERVICE_STOP_PENDING,
                        0,
                        NO_ERROR.0,
                        0,
                        next_stop_checkpoint(),
                        STATUS_WAIT_HINT_MILLIS,
                    )
                {
                    crate::write_stderr(format_args!(
                        "[foxhole-agent] failed to refresh STOP_PENDING while the bounded run drains: {error}"
                    ));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(AgentError::new(
                    "service",
                    "worker_disconnected",
                    "the guest execution worker exited without an outcome",
                ));
            }
        }
    };

    if let Ok(summary) = &execution {
        crate::print_summary(summary);
    }
    execution.map(|_| ())
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP_REQUESTED.store(true, Ordering::SeqCst);
            match report_status(
                SERVICE_STOP_PENDING,
                0,
                NO_ERROR.0,
                0,
                next_stop_checkpoint(),
                STATUS_WAIT_HINT_MILLIS,
            ) {
                Ok(()) => NO_ERROR.0,
                Err(_) => ERROR_SERVICE_CANNOT_ACCEPT_CTRL.0,
            }
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR.0,
        _ => ERROR_CALL_NOT_IMPLEMENTED.0,
    }
}

fn next_stop_checkpoint() -> u32 {
    STOP_CHECKPOINT
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |checkpoint| {
            Some(checkpoint.saturating_add(1))
        })
        .unwrap_or_else(|checkpoint| checkpoint)
        .saturating_add(1)
}

fn next_start_checkpoint() -> u32 {
    START_CHECKPOINT
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |checkpoint| {
            Some(checkpoint.saturating_add(1))
        })
        .unwrap_or_else(|checkpoint| checkpoint)
        .saturating_add(1)
}

fn report_status(
    state: SERVICE_STATUS_CURRENT_STATE,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
) -> AgentResult<()> {
    let _update = lock(&STATUS_UPDATE);
    let handle = SERVICE_STATUS_HANDLE(STATUS_HANDLE.load(Ordering::SeqCst));
    if handle.is_invalid() {
        return Err(AgentError::new(
            "service",
            "invalid_status_handle",
            "the service status handle is not registered",
        ));
    }
    let status = service_status(
        state,
        controls_accepted,
        win32_exit_code,
        service_exit_code,
        checkpoint,
        wait_hint,
    );
    unsafe { SetServiceStatus(handle, &status) }.map_err(|error| {
        AgentError::with_source(
            "service",
            "set_status",
            "publish foxhole-agent service status",
            error,
        )
    })
}

fn service_status(
    state: SERVICE_STATUS_CURRENT_STATE,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
) -> SERVICE_STATUS {
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: service_exit_code,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_status_accepts_only_the_controls_we_handle() {
        let status = service_status(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            NO_ERROR.0,
            0,
            0,
            0,
        );
        assert_eq!(status.dwServiceType, SERVICE_WIN32_OWN_PROCESS);
        assert_eq!(status.dwCurrentState, SERVICE_RUNNING);
        assert_eq!(
            status.dwControlsAccepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
        assert_eq!(status.dwCheckPoint, 0);
        assert_eq!(status.dwWaitHint, 0);
    }

    #[test]
    fn pending_and_terminal_statuses_do_not_accept_controls() {
        let pending = service_status(
            SERVICE_STOP_PENDING,
            0,
            NO_ERROR.0,
            0,
            2,
            STATUS_WAIT_HINT_MILLIS,
        );
        assert_eq!(pending.dwControlsAccepted, 0);
        assert!(pending.dwCheckPoint > 0);
        assert!(pending.dwWaitHint > 0);

        let stopped = service_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR.0, 1, 0, 0);
        assert_eq!(stopped.dwControlsAccepted, 0);
        assert_eq!(stopped.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR.0);
        assert_eq!(stopped.dwServiceSpecificExitCode, 1);
        assert_eq!(stopped.dwCheckPoint, 0);
        assert_eq!(stopped.dwWaitHint, 0);
    }

    #[test]
    fn startup_and_stop_checkpoint_sequences_increase_independently() {
        START_CHECKPOINT.store(1, Ordering::SeqCst);
        STOP_CHECKPOINT.store(0, Ordering::SeqCst);

        assert_eq!(next_start_checkpoint(), 2);
        assert_eq!(next_start_checkpoint(), 3);
        assert_eq!(next_stop_checkpoint(), 1);
        assert_eq!(next_stop_checkpoint(), 2);
    }

    #[test]
    fn startup_pending_status_uses_a_checkpoint_and_wait_hint() {
        let pending = service_status(
            SERVICE_START_PENDING,
            0,
            NO_ERROR.0,
            0,
            1,
            STATUS_WAIT_HINT_MILLIS,
        );
        assert_eq!(pending.dwCurrentState, SERVICE_START_PENDING);
        assert_eq!(pending.dwControlsAccepted, 0);
        assert_eq!(pending.dwCheckPoint, 1);
        assert_eq!(pending.dwWaitHint, STATUS_WAIT_HINT_MILLIS);
    }
}
