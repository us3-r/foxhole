use crate::sandbox::backend::{SandboxError, SandboxResult};
use once_cell::sync::Lazy;
use std::ffi::c_void;
use std::mem;
use std::sync::{Mutex, MutexGuard};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW, DESKTOP_CONTROL_FLAGS,
    GetProcessWindowStation, GetUserObjectInformationW, HDESK, HWINSTA, SetProcessWindowStation,
    UOI_NAME,
};
use windows::core::{PCWSTR, PWSTR};

const SDDL_REVISION_1: u32 = 1;
const WINSTA_ALL_ACCESS: u32 = 0x000f_037f;
const DESKTOP_ALL_ACCESS: u32 = 0x000f_01ff;

static WINDOW_STATION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        security_descriptor: *const u16,
        revision: u32,
        converted: *mut *mut c_void,
        converted_size: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

pub(super) struct PrivateDesktop {
    station: HWINSTA,
    desktop: HDESK,
    startup_name: Vec<u16>,
}

impl PrivateDesktop {
    pub(super) fn create(run_id: &str, sandbox_sid: &str) -> SandboxResult<Self> {
        let desktop_name = "Sandbox";
        let requested_station_name = private_station_name(run_id)?;
        let requested_station_name_wide = wide(&requested_station_name);
        let current_user = crate::artifact::current_user_sid_string().map_err(|error| {
            SandboxError::with_source("private_desktop", "resolve the broker SID", error)
        })?;

        let station_descriptor = SecurityDescriptor::new(&format!(
            "O:{current_user}D:P(A;;GA;;;{current_user})(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x000F037F;;;{sandbox_sid})S:(ML;;NW;;;LW)"
        ))?;
        let station_attributes = station_descriptor.attributes();
        let station = unsafe {
            CreateWindowStationW(
                PCWSTR(requested_station_name_wide.as_ptr()),
                0,
                WINSTA_ALL_ACCESS,
                Some(&station_attributes),
            )
            .map_err(|error| {
                SandboxError::with_source(
                    "private_desktop",
                    "create the private window station",
                    error,
                )
            })?
        };
        let station_name = match user_object_name(station) {
            Ok(name) => name,
            Err(error) => {
                unsafe {
                    let _ = CloseWindowStation(station);
                }
                return Err(error);
            }
        };

        let desktop_result = (|| {
            let _guard = lock_window_station(&WINDOW_STATION_LOCK)?;
            let original = unsafe { GetProcessWindowStation() }.map_err(|error| {
                SandboxError::with_source(
                    "private_desktop",
                    "query the broker window station",
                    error,
                )
            })?;
            unsafe { SetProcessWindowStation(station) }.map_err(|error| {
                SandboxError::with_source(
                    "private_desktop",
                    "temporarily enter the private window station",
                    error,
                )
            })?;
            let restore = RestoreWindowStation(original);

            let desktop_descriptor = SecurityDescriptor::new(&format!(
                "O:{current_user}D:P(A;;GA;;;{current_user})(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x000F01FF;;;{sandbox_sid})S:(ML;;NW;;;LW)"
            ))?;
            let desktop_attributes = desktop_descriptor.attributes();
            let desktop_name_wide = wide(desktop_name);
            let desktop = unsafe {
                CreateDesktopW(
                    PCWSTR(desktop_name_wide.as_ptr()),
                    PCWSTR::null(),
                    None,
                    DESKTOP_CONTROL_FLAGS(0),
                    DESKTOP_ALL_ACCESS,
                    Some(&desktop_attributes),
                )
                .map_err(|error| {
                    SandboxError::with_source(
                        "private_desktop",
                        "create the private desktop",
                        error,
                    )
                })?
            };
            restore.restore()?;
            Ok(desktop)
        })();

        let desktop = match desktop_result {
            Ok(desktop) => desktop,
            Err(error) => {
                unsafe {
                    let _ = CloseWindowStation(station);
                }
                return Err(error);
            }
        };

        Ok(Self {
            station,
            desktop,
            startup_name: wide(&format!("{station_name}\\{desktop_name}")),
        })
    }

    pub(super) fn startup_name(&mut self) -> PWSTR {
        PWSTR(self.startup_name.as_mut_ptr())
    }
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        unsafe {
            if !self.desktop.is_invalid() {
                let _ = CloseDesktop(self.desktop);
                self.desktop = HDESK::default();
            }
            if !self.station.is_invalid() {
                let _ = CloseWindowStation(self.station);
                self.station = HWINSTA::default();
            }
        }
    }
}

struct RestoreWindowStation(HWINSTA);

impl RestoreWindowStation {
    fn restore(self) -> SandboxResult<()> {
        unsafe { SetProcessWindowStation(self.0) }.map_err(|error| {
            SandboxError::with_source(
                "private_desktop",
                "restore the broker window station",
                error,
            )
        })?;
        mem::forget(self);
        Ok(())
    }
}

impl Drop for RestoreWindowStation {
    fn drop(&mut self) {
        unsafe {
            let _ = SetProcessWindowStation(self.0);
        }
    }
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn new(sddl: &str) -> SandboxResult<Self> {
        let sddl = wide(sddl);
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(SandboxError::with_source(
                "private_desktop",
                "build the private-desktop security descriptor",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn private_station_name(run_id: &str) -> SandboxResult<String> {
    if run_id.is_empty()
        || run_id.len() > 64
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SandboxError::new(
            "private_desktop",
            "the private window-station run ID is invalid",
        ));
    }
    Ok(format!("Foxhole-{run_id}"))
}

fn lock_window_station(lock: &Mutex<()>) -> SandboxResult<MutexGuard<'_, ()>> {
    lock.lock()
        .map_err(|_| SandboxError::new("private_desktop", "window-station lock is poisoned"))
}

fn user_object_name(station: HWINSTA) -> SandboxResult<String> {
    user_object_name_with(|buffer, length, required| unsafe {
        GetUserObjectInformationW(HANDLE(station.0), UOI_NAME, buffer, length, Some(required))
    })
}

fn user_object_name_with(
    mut query: impl FnMut(Option<*mut c_void>, u32, &mut u32) -> windows::core::Result<()>,
) -> SandboxResult<String> {
    let mut required = 0u32;
    let first = query(None, 0, &mut required);
    if required == 0 {
        return Err(SandboxError::with_source(
            "private_desktop",
            "query the generated private window-station name length",
            first
                .err()
                .unwrap_or_else(windows::core::Error::from_thread),
        ));
    }
    let mut name = vec![0u16; (required as usize).div_ceil(mem::size_of::<u16>())];
    query(Some(name.as_mut_ptr().cast()), required, &mut required).map_err(|error| {
        SandboxError::with_source(
            "private_desktop",
            "query the generated private window-station name",
            error,
        )
    })?;
    let length = name
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(name.len());
    String::from_utf16(&name[..length]).map_err(|error| {
        SandboxError::with_source(
            "private_desktop",
            "decode the generated private window-station name",
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_strings_and_security_attributes_are_valid() {
        assert_eq!(wide("Sandbox"), [83, 97, 110, 100, 98, 111, 120, 0]);
        assert_eq!(
            private_station_name("0123456789abcdef").unwrap(),
            "Foxhole-0123456789abcdef"
        );
        let current_user = crate::artifact::current_user_sid_string().unwrap();
        let descriptor =
            SecurityDescriptor::new(&format!("D:P(A;;GA;;;{current_user})")).expect("valid SDDL");
        let attributes = descriptor.attributes();
        assert_eq!(
            attributes.nLength as usize,
            mem::size_of::<SECURITY_ATTRIBUTES>()
        );
        assert!(!attributes.lpSecurityDescriptor.is_null());
        assert!(!attributes.bInheritHandle.as_bool());
    }

    #[test]
    fn malformed_security_descriptor_fails_closed() {
        let error = match SecurityDescriptor::new("definitely-not-sddl") {
            Ok(_) => panic!("malformed SDDL must fail"),
            Err(error) => error,
        };
        assert_eq!(error.stage, "private_desktop");
    }

    #[test]
    fn invalid_window_station_name_query_is_rejected() {
        let error = user_object_name(HWINSTA::default()).expect_err("invalid handle must fail");
        assert_eq!(error.stage, "private_desktop");
    }

    #[test]
    fn private_desktop_can_be_created_and_restored() {
        let sid = crate::artifact::current_user_sid_string().unwrap();
        let run_id = format!("coverage-{}", std::process::id());
        let mut desktop = match PrivateDesktop::create(&run_id, &sid) {
            Ok(desktop) => desktop,
            Err(error) => {
                let access_denied = std::error::Error::source(&error)
                    .and_then(|source| source.downcast_ref::<windows::core::Error>())
                    .is_some_and(|source| {
                        source.code() == windows::Win32::Foundation::E_ACCESSDENIED
                    });
                assert!(
                    access_denied,
                    "an elevated broker should create the private station: {error}"
                );
                return;
            }
        };
        let startup = desktop.startup_name();
        assert!(!startup.is_null());
        let decoded = String::from_utf16_lossy(
            &desktop.startup_name[..desktop.startup_name.len().saturating_sub(1)],
        );
        assert!(decoded.ends_with("\\Sandbox"));
    }

    #[test]
    fn private_desktop_rejects_an_invalid_sandbox_sid() {
        let error = match PrivateDesktop::create("coverage", "not-a-sid") {
            Ok(_) => panic!("invalid sandbox SID must fail"),
            Err(error) => error,
        };
        assert_eq!(error.stage, "private_desktop");
    }

    #[test]
    fn private_desktop_rejects_an_invalid_station_run_id() {
        let sid = crate::artifact::current_user_sid_string().unwrap();
        for run_id in ["", "contains\\separator", "contains space", &"a".repeat(65)] {
            let error = match PrivateDesktop::create(run_id, &sid) {
                Ok(_) => panic!("invalid window-station run ID must fail"),
                Err(error) => error,
            };
            assert_eq!(error.stage, "private_desktop");
        }
    }

    #[test]
    fn restore_guard_attempts_restoration_on_error_and_drop() {
        assert!(RestoreWindowStation(HWINSTA::default()).restore().is_err());
        drop(RestoreWindowStation(HWINSTA::default()));

        let empty = SecurityDescriptor(std::ptr::null_mut());
        drop(empty);
        let desktop = PrivateDesktop {
            station: HWINSTA::default(),
            desktop: HDESK::default(),
            startup_name: vec![0],
        };
        drop(desktop);
    }

    #[test]
    fn lock_and_window_station_name_failure_paths_are_injectable() {
        let lock = std::sync::Arc::new(Mutex::new(()));
        let poisoned = lock.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison test mutex");
        })
        .join();
        assert_eq!(
            lock_window_station(&lock).unwrap_err().stage,
            "private_desktop"
        );

        let mut calls = 0;
        let name = user_object_name_with(|buffer, _, required| {
            calls += 1;
            *required = 4;
            if let Some(buffer) = buffer {
                unsafe {
                    std::ptr::copy_nonoverlapping([b'A' as u16, 0].as_ptr(), buffer.cast(), 2)
                };
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(name, "A");
        assert_eq!(calls, 2);

        let error = user_object_name_with(|buffer, _, required| {
            *required = 4;
            if buffer.is_some() {
                Err(windows::core::Error::new(
                    windows::Win32::Foundation::E_FAIL,
                    "injected query failure",
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("query the generated"));

        let error = user_object_name_with(|buffer, _, required| {
            *required = 4;
            if let Some(buffer) = buffer {
                unsafe { std::ptr::copy_nonoverlapping([0xd800u16, 0].as_ptr(), buffer.cast(), 2) };
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("decode"));
    }
}
