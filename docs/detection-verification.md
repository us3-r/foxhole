# Detection verification record — 2026-09-07

Implemented and checked locally on branch `ioc-expand`, Windows x64, Rust 1.93.1 and
Python 3.13. No real malware was executed or parsed on the development host.

| Check | Result |
|---|---|
| Rust formatting | Passed |
| Clippy, all targets, warnings denied | Passed |
| Locked build, all targets | Passed |
| Rust coverage scope | 319 passed; seven existing desktop tests delegated to the privileged job |
| Real YARA / PE / capa / packet fixtures and negative/property cases | 16 Python tests passed |
| Windows Job launcher | Success, timeout, nonzero exit, output exhaustion, missing executable and integrity mismatch passed |
| Golden scanner, findings, IOC, verdict and web data | Passed without update mode |
| Offline DOM | Hostile text, prototype-like keys, display bounds, filters and evidence links passed |
| CI configuration | YAML parsed; equivalent local commands and coverage gate passed; remote Actions run not performed |

Measured line / branch coverage:

| Scope | Lines | Branches | Recorded minimum lines / branches |
|---|---:|---:|---:|
| Rust project | 58.91% | 46.70% | 58% / 46% |
| Critical validation, correlation, publication and telemetry | 85.46% | 56.86% | 85% / 56% |
| Guest Python worker | 77.49% | 64.57% | 77% / 64% |

The checker passes these measurements and rejects a deliberately unmet threshold. The first
baseline is stored in `coverage/detection-baseline.json`; subsequent PR baselines cannot
decrease. Coverage does not claim every branch is exercised.

## Outstanding environment validation

The unfiltered `cargo test --locked --all-targets --no-fail-fast` run fails at the same seven
existing Windows tests that failed before this expansion: five restricted-process unit tests
and two `sandbox_win_test` integration tests. Their failure is private window-station creation:
`Access is denied. (0x80070005)`. Their bodies and expectations were not weakened. The exact
list appears in `scripts/test_detection_coverage.ps1`; the privileged Windows workflow runs
the full suite without these exclusions.

The initial non-elevated session could not use `Get-VMHost`. The four existing opt-in real
Hyper-V tests remain unrun. A subsequent authorized administrator-shell demo is recorded
below; its successful target execution does not establish the full Windows/Hyper-V completion
criteria. The protected disposable-host job in [the setup guide](deterministic-detection.md)
is still required.

The optional historical archive `test_ai_vm/16/reports` is absent. Its existing test returns
early in this environment. Version-controlled synthetic goldens and legacy deserialization
unit tests pass, but this does not establish that missing archive's full integration result.

capa/Vivisect occasionally emits a Python ResourceWarning when its fixture input mapping is
garbage-collected. The real guest adapter terminates and joins the worker job before cleanup;
the mapped file does not outlive that process. No test sample is executed by the Python suite.

The supplied packs are diagnostic starter rules, and packet parsing does not reassemble TCP
or decrypt traffic. These supported-scope limitations are reported explicitly and documented
in the setup guide. Offline signature tests exercise the real unsigned-file path and a mock
that enforces cache-only retrieval, no dialog, and provider-state closure; successful trust
of a signed executable in the deployed guest still needs that image's integration validation.

## Administrator-shell download demo, 2026-09-07

The repository's `test_download.exe` ran in a disposable Hyper-V normal-user guest against
the dedicated local server at `192.168.250.1:8080`, with `--output test_ioc_new` and offline
analysis enabled. The original base image was preserved. A separate sealed demo image held
the updated static guest agent, Python runtime, pinned scanner packages, and local rules.
Run `728fa56e77b6184ca4b647891022b5e1` completed with exit code 0 in 1,711 ms; VM cleanup
succeeded and the host generated the analysis JSON and web report without VirusTotal.

The first live attempt exposed a publication/collection mismatch: the new `detection/`
directory was absent from both existing artifact-root lists. Host and guest now share that
list, retain the existing hash/manifest and bounded traversal checks, and restrict failed-run
cleanup to known scanner filenames. All 30 then-existing guest-agent tests and seven host
collection tests passed. A further failed-publication regression test also passed, together
with the other two publication tests.

Observed coverage in the successful demo:

- YARA completed; the diagnostic starter pack had no matches.
- PE analysis completed and extracted 1,068 strings.
- Packet analysis retained 92 packet observations, with its documented partial-coverage warning.
- capa returned `invalid_output` / `scanner_rejected_input_or_schema` in this initial run.
- Sysmon did not provide the target process creation event within the bounded collection
  window. No descendant file or registry events were available, so dropped-file analysis and
  the expected runtime behavior chains were not demonstrated in this run.

The verdict is explicitly **inconclusive**. This demo verifies the real guest-to-host scanner
artifact handoff and working YARA/PE stages; it does not establish complete capa or behavioral
coverage. The subsequent fixes and live rerun are documented in
[the Sysmon/capa comparison](sysmon-download-comparison.md).
