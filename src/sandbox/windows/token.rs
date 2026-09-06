use crate::sandbox::backend::{MitigationProfile, SandboxError, SandboxResult};
use std::mem;
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, GetLengthSid,
    GetTokenInformation, PSID, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION_TYPE,
    TOKEN_LINKED_TOKEN, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_TYPE, TokenElevationType,
    TokenElevationTypeFull, TokenIntegrityLevel, TokenLinkedToken, TokenPrimary, TokenType,
    TokenUIAccess, WinBuiltinAdministratorsSid, WinBuiltinPowerUsersSid,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

const SE_GROUP_INTEGRITY: u32 = 0x20;
const LOW_INTEGRITY_SID: &str = "S-1-16-4096";
const UNTRUSTED_INTEGRITY_SID: &str = "S-1-16-0";

pub(super) struct RestrictedToken {
    handle: HANDLE,
    integrity_level: &'static str,
}

impl RestrictedToken {
    pub(super) fn create(profile: MitigationProfile) -> SandboxResult<Self> {
        let mut current = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                &mut current,
            )
            .map_err(|error| {
                SandboxError::with_source(
                    "restricted_token",
                    "open the broker process token",
                    error,
                )
            })?;
        }
        let current = OwnedToken(current);
        let linked_standard = linked_standard_user_token(&current)?;
        let source = linked_standard
            .as_ref()
            .map_or(current.0, |linked| linked.0);
        let source = duplicate_token_handle_with_required_access(source)?;
        require_primary_token(source.0)?;

        let mut sid_buffers = [SidBuffer::new(), SidBuffer::new()];
        sid_buffers[0].initialize(WinBuiltinAdministratorsSid)?;
        sid_buffers[1].initialize(WinBuiltinPowerUsersSid)?;
        let deny_only = sid_buffers
            .iter_mut()
            .map(|buffer| SID_AND_ATTRIBUTES {
                Sid: buffer.as_psid(),
                Attributes: 0,
            })
            .collect::<Vec<_>>();

        let mut restricted = HANDLE::default();
        unsafe {
            CreateRestrictedToken(
                source.0,
                DISABLE_MAX_PRIVILEGE,
                Some(&deny_only),
                None,
                None,
                &mut restricted,
            )
            .map_err(|error| {
                SandboxError::with_source(
                    "restricted_token",
                    "create the deny-only, privilege-stripped token",
                    error,
                )
            })?;
        }

        let token = Self {
            handle: restricted,
            integrity_level: if profile == MitigationProfile::Maximum {
                "untrusted"
            } else {
                "low"
            },
        };
        token.set_integrity(if profile == MitigationProfile::Maximum {
            UNTRUSTED_INTEGRITY_SID
        } else {
            LOW_INTEGRITY_SID
        })?;
        token.disable_ui_access()?;
        Ok(token)
    }

    pub(super) fn get(&self) -> HANDLE {
        self.handle
    }

    pub(super) fn integrity_level(&self) -> &'static str {
        self.integrity_level
    }

    fn set_integrity(&self, integrity_sid: &str) -> SandboxResult<()> {
        let integrity_sid = integrity_sid
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(PCWSTR(integrity_sid.as_ptr()), &mut sid).map_err(|error| {
                SandboxError::with_source(
                    "restricted_token",
                    "create the mandatory-integrity SID",
                    error,
                )
            })?;
        }
        let sid_guard = LocalSid(sid);
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid_guard.0,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let information_length = mem::size_of::<TOKEN_MANDATORY_LABEL>()
            .checked_add(unsafe { GetLengthSid(sid_guard.0) } as usize)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| {
                SandboxError::new("restricted_token", "integrity label length overflowed")
            })?;
        unsafe {
            SetTokenInformation(
                self.handle,
                TokenIntegrityLevel,
                (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                information_length,
            )
            .map_err(|error| {
                SandboxError::with_source(
                    "restricted_token",
                    "set the launch token integrity level",
                    error,
                )
            })?;
        }
        Ok(())
    }

    fn disable_ui_access(&self) -> SandboxResult<()> {
        let ui_access = 0u32;
        unsafe {
            SetTokenInformation(
                self.handle,
                TokenUIAccess,
                (&ui_access as *const u32).cast(),
                mem::size_of_val(&ui_access) as u32,
            )
            .map_err(|error| {
                SandboxError::with_source(
                    "restricted_token",
                    "disable UIAccess on the launch token",
                    error,
                )
            })?;
        }
        Ok(())
    }
}

fn duplicate_token_handle_with_required_access(source: HANDLE) -> SandboxResult<OwnedToken> {
    let mut duplicate = HANDLE::default();
    let required = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut duplicate,
            required.0,
            false,
            DUPLICATE_HANDLE_OPTIONS::default(),
        )
        .map_err(|error| {
            SandboxError::with_source(
                "restricted_token",
                "open the source token with the required launch rights",
                error,
            )
        })?;
    }
    Ok(OwnedToken(duplicate))
}

fn require_primary_token(source: HANDLE) -> SandboxResult<()> {
    let mut token_type = TOKEN_TYPE::default();
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            source,
            TokenType,
            Some((&mut token_type as *mut TOKEN_TYPE).cast()),
            mem::size_of::<TOKEN_TYPE>() as u32,
            &mut returned,
        )
        .map_err(|error| {
            SandboxError::with_source("restricted_token", "verify the launch-token type", error)
        })?;
    }
    if token_type != TokenPrimary {
        return Err(SandboxError::new(
            "restricted_token",
            "Windows returned an impersonation token where a primary launch token was required",
        ));
    }
    Ok(())
}

fn linked_standard_user_token(current: &OwnedToken) -> SandboxResult<Option<OwnedToken>> {
    let mut elevation_type = TOKEN_ELEVATION_TYPE::default();
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            current.0,
            TokenElevationType,
            Some((&mut elevation_type as *mut TOKEN_ELEVATION_TYPE).cast()),
            mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut returned,
        )
        .map_err(|error| {
            SandboxError::with_source(
                "restricted_token",
                "query the broker token elevation type",
                error,
            )
        })?;
    }
    if elevation_type != TokenElevationTypeFull {
        return Ok(None);
    }

    let mut linked = TOKEN_LINKED_TOKEN::default();
    unsafe {
        GetTokenInformation(
            current.0,
            TokenLinkedToken,
            Some((&mut linked as *mut TOKEN_LINKED_TOKEN).cast()),
            mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut returned,
        )
        .map_err(|error| {
            SandboxError::with_source(
                "restricted_token",
                "obtain the elevated broker's linked standard-user token",
                error,
            )
        })?;
    }
    owned_linked_token(linked)
}

fn owned_linked_token(linked: TOKEN_LINKED_TOKEN) -> SandboxResult<Option<OwnedToken>> {
    if linked.LinkedToken.is_invalid() {
        return Err(SandboxError::new(
            "restricted_token",
            "Windows returned an invalid linked standard-user token",
        ));
    }
    crate::sandbox::sandbox_utils::log_outside(
        "elevated broker detected; deriving the sandbox token from its linked standard-user token",
    );
    Ok(Some(OwnedToken(linked.LinkedToken)))
}

impl Drop for RestrictedToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
            self.handle = HANDLE::default();
        }
    }
}

struct OwnedToken(HANDLE);

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

struct SidBuffer {
    storage: Box<[usize]>,
    length: u32,
}

impl SidBuffer {
    fn new() -> Self {
        let words = (SECURITY_MAX_SID_SIZE as usize).div_ceil(mem::size_of::<usize>());
        Self {
            storage: vec![0usize; words].into_boxed_slice(),
            length: SECURITY_MAX_SID_SIZE,
        }
    }

    fn initialize(
        &mut self,
        kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
    ) -> SandboxResult<()> {
        unsafe {
            CreateWellKnownSid(kind, None, Some(self.as_psid()), &mut self.length).map_err(
                |error| {
                    SandboxError::with_source(
                        "restricted_token",
                        "create a deny-only well-known SID",
                        error,
                    )
                },
            )?;
        }
        Ok(())
    }

    fn as_psid(&mut self) -> PSID {
        PSID(self.storage.as_mut_ptr().cast())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_restricted_token_from_current_broker_context() {
        let token = RestrictedToken::create(MitigationProfile::Compatible)
            .expect("restricted token creation should support the current elevation context");
        assert!(!token.get().is_invalid());
        assert_eq!(token.integrity_level(), "low");
    }

    #[test]
    fn maximum_profile_uses_untrusted_integrity() {
        let token = RestrictedToken::create(MitigationProfile::Maximum)
            .expect("maximum token creation should succeed");
        assert!(!token.get().is_invalid());
        assert_eq!(token.integrity_level(), "untrusted");
    }

    #[test]
    fn well_known_sid_buffers_are_initialized() {
        let mut admin = SidBuffer::new();
        admin.initialize(WinBuiltinAdministratorsSid).unwrap();
        assert!(!admin.as_psid().is_invalid());
        assert!(admin.length > 0);

        let mut power_user = SidBuffer::new();
        power_user.initialize(WinBuiltinPowerUsersSid).unwrap();
        assert!(!power_user.as_psid().is_invalid());
    }

    #[test]
    fn invalid_token_operations_fail_closed() {
        let invalid = OwnedToken(HANDLE::default());
        assert!(linked_standard_user_token(&invalid).is_err());

        let token = RestrictedToken {
            handle: HANDLE::default(),
            integrity_level: "low",
        };
        assert!(token.set_integrity("not-a-sid").is_err());
        assert!(token.set_integrity(LOW_INTEGRITY_SID).is_err());
        assert!(token.disable_ui_access().is_err());
    }

    #[test]
    fn invalid_well_known_sid_kind_and_empty_guards_are_safe() {
        let mut buffer = SidBuffer::new();
        assert!(
            buffer
                .initialize(windows::Win32::Security::WELL_KNOWN_SID_TYPE(i32::MAX))
                .is_err()
        );
        drop(OwnedToken(HANDLE::default()));
        drop(LocalSid(PSID::default()));
    }

    #[test]
    fn an_invalid_linked_token_result_is_rejected_explicitly() {
        let error = owned_linked_token(TOKEN_LINKED_TOKEN::default())
            .err()
            .expect("invalid linked token must fail");
        assert!(
            error
                .to_string()
                .contains("invalid linked standard-user token")
        );
    }

    #[test]
    fn current_process_source_is_a_primary_token() {
        let mut current = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current).unwrap();
        }
        let current = OwnedToken(current);
        let duplicate = duplicate_token_handle_with_required_access(current.0)
            .expect("the source token must provide every right used after restriction");
        require_primary_token(duplicate.0).expect("a process token must be primary");
    }
}
