use crate::sandbox::backend::MitigationProfile;

const DEP_ENABLE: u64 = 0x0000_0001;
const SEHOP_ENABLE: u64 = 0x0000_0004;
const FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 1 << 8;
const HEAP_TERMINATE_ALWAYS_ON: u64 = 1 << 12;
const BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 1 << 16;
const HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 1 << 20;
const STRICT_HANDLE_CHECKS_ALWAYS_ON: u64 = 1 << 24;
const WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64 = 1 << 28;
const EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 1 << 32;
const PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64 = 1 << 36;
const CONTROL_FLOW_GUARD_ALWAYS_ON: u64 = 1 << 40;
const BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 1 << 44;
const IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 = 1 << 52;
const IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 = 1 << 56;
const IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 1 << 60;

const COMPATIBLE_POLICY: u64 = DEP_ENABLE
    | SEHOP_ENABLE
    | FORCE_RELOCATE_IMAGES_ALWAYS_ON
    | HEAP_TERMINATE_ALWAYS_ON
    | BOTTOM_UP_ASLR_ALWAYS_ON
    | HIGH_ENTROPY_ASLR_ALWAYS_ON
    | STRICT_HANDLE_CHECKS_ALWAYS_ON
    | EXTENSION_POINT_DISABLE_ALWAYS_ON
    | CONTROL_FLOW_GUARD_ALWAYS_ON;

pub(super) fn policy(profile: MitigationProfile, _gui_target: bool) -> u64 {
    match profile {
        MitigationProfile::Compatible => COMPATIBLE_POLICY,
        MitigationProfile::Strict => {
            COMPATIBLE_POLICY
                | PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
                | IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
                | IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
                | IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON
        }
        MitigationProfile::Maximum => {
            policy(MitigationProfile::Strict, false)
                | WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
                | BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mitigation_profiles_are_monotonic() {
        let compatible = policy(MitigationProfile::Compatible, false);
        let strict = policy(MitigationProfile::Strict, false);
        let maximum = policy(MitigationProfile::Maximum, false);
        assert_eq!(compatible & strict, compatible);
        assert_eq!(strict & maximum, strict);
        assert_ne!(strict, maximum);
    }

    #[test]
    fn win32k_lockdown_is_reserved_for_maximum() {
        let console = policy(MitigationProfile::Strict, false);
        let gui = policy(MitigationProfile::Strict, true);
        let maximum = policy(MitigationProfile::Maximum, false);
        assert_eq!(console, gui);
        assert_eq!(gui & WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON, 0);
        assert_ne!(maximum & WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON, 0);
    }
}
