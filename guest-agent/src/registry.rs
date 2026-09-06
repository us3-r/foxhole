use foxhole::sandbox::hyperv::guest_protocol::CaptureCoverage;

pub fn coverage(requested: bool) -> CaptureCoverage {
    CaptureCoverage::unavailable(
        requested,
        "registry event collection is not implemented by the restricted guest runner",
    )
}
