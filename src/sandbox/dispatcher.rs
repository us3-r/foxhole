use crate::sandbox::backend::{BackendKind, SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::fmt;

const FALLBACK_WARNING_PREFIX: &str = "Hyper-V is unavailable; using the weaker restricted-process backend because fallback was explicitly permitted";

/// The backend mode requested by the caller.
///
/// `Auto` is a selection policy, not an executable backend. A successful
/// selection always resolves it to a concrete [`BackendKind`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestedBackend {
    Restricted,
    #[serde(rename = "hyperv")]
    HyperV,
    Auto,
}

impl fmt::Display for RequestedBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Restricted => "restricted",
            Self::HyperV => "hyperv",
            Self::Auto => "auto",
        })
    }
}

/// Whether capability detection established that Hyper-V can be selected.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAvailability {
    Available,
    Unavailable,
}

/// Platform-neutral evidence supplied by Hyper-V capability detection.
///
/// The resolver deliberately consumes only capability evidence. Base-image,
/// preparation, and execution failures happen after selection and therefore
/// cannot trigger a fallback through this API.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HyperVCapabilityEvidence {
    pub availability: CapabilityAvailability,
    pub reason: Option<String>,
}

impl HyperVCapabilityEvidence {
    pub fn available() -> Self {
        Self {
            availability: CapabilityAvailability::Available,
            reason: None,
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: CapabilityAvailability::Unavailable,
            reason: Some(reason.into()),
        }
    }

    fn unavailable_reason(&self) -> &str {
        self.reason
            .as_deref()
            .filter(|reason| !reason.trim().is_empty())
            .unwrap_or("capability detection reported no additional reason")
    }
}

/// A resolved, concrete backend choice suitable for execution and reporting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendSelection {
    pub requested: RequestedBackend,
    pub selected: BackendKind,
    pub fallback_used: bool,
    pub warnings: Vec<String>,
}

/// Resolve a requested backend using pre-execution Hyper-V capability evidence.
///
/// The only permitted fallback is `Auto` plus an unavailable Hyper-V capability
/// plus explicit authorization for weaker restricted-process isolation.
/// Explicit `HyperV` requests fail when unavailable, irrespective of fallback
/// authorization. Failures after this function returns must be reported as
/// failures of the selected backend and must not be fed back into selection.
pub fn resolve_backend(
    requested: RequestedBackend,
    hyperv: &HyperVCapabilityEvidence,
    allow_restricted_fallback: bool,
) -> SandboxResult<BackendSelection> {
    match requested {
        RequestedBackend::Restricted => Ok(selection(
            requested,
            BackendKind::RestrictedProcess,
            false,
            Vec::new(),
        )),
        RequestedBackend::HyperV => match hyperv.availability {
            CapabilityAvailability::Available => {
                Ok(selection(requested, BackendKind::HyperV, false, Vec::new()))
            }
            CapabilityAvailability::Unavailable => Err(SandboxError::new(
                "backend_selection",
                format!(
                    "Hyper-V was explicitly requested but is unavailable: {}",
                    hyperv.unavailable_reason()
                ),
            )),
        },
        RequestedBackend::Auto => match hyperv.availability {
            CapabilityAvailability::Available => {
                Ok(selection(requested, BackendKind::HyperV, false, Vec::new()))
            }
            CapabilityAvailability::Unavailable if allow_restricted_fallback => {
                let warning = format!("{FALLBACK_WARNING_PREFIX}: {}", hyperv.unavailable_reason());
                Ok(selection(
                    requested,
                    BackendKind::RestrictedProcess,
                    true,
                    vec![warning],
                ))
            }
            CapabilityAvailability::Unavailable => Err(SandboxError::new(
                "backend_selection",
                format!(
                    "Hyper-V is unavailable and fallback to the weaker restricted-process backend was not explicitly permitted: {}",
                    hyperv.unavailable_reason()
                ),
            )),
        },
    }
}

fn selection(
    requested: RequestedBackend,
    selected: BackendKind,
    fallback_used: bool,
    warnings: Vec<String>,
) -> BackendSelection {
    BackendSelection {
        requested,
        selected,
        fallback_used,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Expected {
        Selected {
            backend: BackendKind,
            fallback_used: bool,
            warning_count: usize,
        },
        Rejected,
    }

    #[test]
    fn selection_policy_table_is_exhaustive() {
        let cases = [
            (
                RequestedBackend::Restricted,
                CapabilityAvailability::Available,
                false,
                Expected::Selected {
                    backend: BackendKind::RestrictedProcess,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::Restricted,
                CapabilityAvailability::Available,
                true,
                Expected::Selected {
                    backend: BackendKind::RestrictedProcess,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::Restricted,
                CapabilityAvailability::Unavailable,
                false,
                Expected::Selected {
                    backend: BackendKind::RestrictedProcess,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::Restricted,
                CapabilityAvailability::Unavailable,
                true,
                Expected::Selected {
                    backend: BackendKind::RestrictedProcess,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::HyperV,
                CapabilityAvailability::Available,
                false,
                Expected::Selected {
                    backend: BackendKind::HyperV,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::HyperV,
                CapabilityAvailability::Available,
                true,
                Expected::Selected {
                    backend: BackendKind::HyperV,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::HyperV,
                CapabilityAvailability::Unavailable,
                false,
                Expected::Rejected,
            ),
            (
                RequestedBackend::HyperV,
                CapabilityAvailability::Unavailable,
                true,
                Expected::Rejected,
            ),
            (
                RequestedBackend::Auto,
                CapabilityAvailability::Available,
                false,
                Expected::Selected {
                    backend: BackendKind::HyperV,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::Auto,
                CapabilityAvailability::Available,
                true,
                Expected::Selected {
                    backend: BackendKind::HyperV,
                    fallback_used: false,
                    warning_count: 0,
                },
            ),
            (
                RequestedBackend::Auto,
                CapabilityAvailability::Unavailable,
                false,
                Expected::Rejected,
            ),
            (
                RequestedBackend::Auto,
                CapabilityAvailability::Unavailable,
                true,
                Expected::Selected {
                    backend: BackendKind::RestrictedProcess,
                    fallback_used: true,
                    warning_count: 1,
                },
            ),
        ];

        for (requested, availability, fallback_permitted, expected) in cases {
            let evidence = HyperVCapabilityEvidence {
                availability,
                reason: Some("test evidence".to_string()),
            };
            let actual = resolve_backend(requested, &evidence, fallback_permitted);

            match expected {
                Expected::Selected {
                    backend,
                    fallback_used,
                    warning_count,
                } => {
                    let actual = actual.unwrap_or_else(|error| {
                        panic!(
                            "{requested}/{availability:?}/{fallback_permitted} was rejected: {error}"
                        )
                    });
                    assert_eq!(actual.requested, requested);
                    assert_eq!(actual.selected, backend);
                    assert_eq!(actual.fallback_used, fallback_used);
                    assert_eq!(actual.warnings.len(), warning_count);
                }
                Expected::Rejected => {
                    let error = match actual {
                        Ok(selection) => panic!(
                            "{requested}/{availability:?}/{fallback_permitted} unexpectedly selected {:?}",
                            selection.selected
                        ),
                        Err(error) => error,
                    };
                    assert_eq!(error.stage, "backend_selection");
                    assert!(error.to_string().contains("test evidence"));
                }
            }
        }
    }

    #[test]
    fn fallback_warning_is_explicit_and_preserves_capability_evidence() {
        let selection = resolve_backend(
            RequestedBackend::Auto,
            &HyperVCapabilityEvidence::unavailable("Hyper-V feature is disabled"),
            true,
        )
        .expect("explicit auto fallback should resolve");

        assert_eq!(selection.selected, BackendKind::RestrictedProcess);
        assert!(selection.fallback_used);
        assert_eq!(selection.warnings.len(), 1);
        assert!(selection.warnings[0].contains("weaker restricted-process"));
        assert!(selection.warnings[0].contains("explicitly permitted"));
        assert!(selection.warnings[0].contains("Hyper-V feature is disabled"));
    }

    #[test]
    fn missing_unavailability_reason_has_a_bounded_diagnostic() {
        let evidence = HyperVCapabilityEvidence {
            availability: CapabilityAvailability::Unavailable,
            reason: None,
        };
        let error = resolve_backend(RequestedBackend::Auto, &evidence, false)
            .expect_err("auto without fallback must fail closed");

        assert!(
            error
                .to_string()
                .contains("capability detection reported no additional reason")
        );
    }

    #[test]
    fn selector_types_round_trip_with_stable_wire_names() {
        let selected = resolve_backend(
            RequestedBackend::HyperV,
            &HyperVCapabilityEvidence::available(),
            false,
        )
        .expect("available Hyper-V should be selected");

        let value = serde_json::to_value(&selected).expect("selection should serialize");
        assert_eq!(value["requested"], "hyperv");
        assert_eq!(value["selected"], "hyperv");
        assert_eq!(value["fallback_used"], false);
        assert_eq!(
            serde_json::from_value::<BackendSelection>(value)
                .expect("selection should deserialize"),
            selected
        );

        let evidence = HyperVCapabilityEvidence::unavailable("disabled");
        let value = serde_json::to_value(&evidence).expect("evidence should serialize");
        assert_eq!(value["availability"], "unavailable");
        assert_eq!(value["reason"], "disabled");
        assert_eq!(
            serde_json::from_value::<HyperVCapabilityEvidence>(value)
                .expect("evidence should deserialize"),
            evidence
        );
    }

    #[test]
    fn requested_backend_display_names_match_cli_values() {
        assert_eq!(RequestedBackend::Restricted.to_string(), "restricted");
        assert_eq!(RequestedBackend::HyperV.to_string(), "hyperv");
        assert_eq!(RequestedBackend::Auto.to_string(), "auto");
    }
}
