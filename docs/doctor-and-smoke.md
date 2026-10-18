# Deployment diagnostics and telemetry smoke test

`foxhole doctor` runs read-only host checks. It creates no VM and changes no
firewall rules, audit policy, image, or service configuration. Run it from elevated
PowerShell for complete Hyper-V checks. A successful preflight is not proof that
guest telemetry works; the live smoke test verifies that separately.

```powershell
.\target\release\foxhole.exe doctor
.\target\release\foxhole.exe doctor --json
.\target\release\foxhole.exe doctor `
  --base-image C:\ProgramData\Foxhole\images\foxhole-smoke.vhdx `
  --base-manifest C:\ProgramData\Foxhole\images\foxhole-smoke.manifest.json `
  --network-policy host-server `
  --gateway-config C:\ProgramData\Foxhole\network\host-only.json `
  --analysis-config C:\Foxhole\detection-config.json
```

Image defaults match execution: `FOXHOLE_HYPERV_BASE_IMAGE`, then
`%ProgramData%\Foxhole\images\foxhole-base.vhdx`. The manifest defaults to the
matching `.manifest.json`, with `FOXHOLE_HYPERV_BASE_MANIFEST` as an override.
Gateway configuration can come from `FOXHOLE_HYPERV_GATEWAY_CONFIG`.

Checks include Hyper-V feature/service/access and cmdlets; the image's protected,
read-only, standalone VHDX properties, protocol and SHA-256; gateway schema and
internal switch identity; scanner paths/hashes/budgets in configuration; and the
host PCAPNG converter. Image hashing can take several minutes. Doctor does not
inspect installed guest tools, verify a live VM's ACLs, or claim network attestation
from configuration alone. Missing optional tools are warnings; failed required
checks return a nonzero exit status. `--json` emits one document on stdout even
when checks fail. Diagnostic/progress output goes to stderr.

## Prepare a smoke-test deployment

Use a separate copy of a previously qualified execution image. Keep the source
sealed image and manifest intact. Build a static-CRT agent with
`scripts/Build-FoxholeGuestAgent.ps1`, update the copy using
`scripts/Update-FoxholeBaseAgent.ps1`, and seal it with
`scripts/Finalize-FoxholeBaseImage.ps1`. The image version in the manifest must
match the guest configuration. Include installed Sysmon/WFP telemetry and, for
scanner checks, the pinned offline Python/scanner/rule deployment described in
[deterministic-detection.md](deterministic-detection.md).

The host needs Rust/Cargo (unless using `-SkipBuild`), MinGW g++, Python 3 for the
verifier, and the configured host-server internal switch. g++ may be supplied as
an absolute path; the script adds its directory to PATH only for the invocation.
For healthy host capture conversion, provision Microsoft's signed `etl2pcapng.exe`
at `%SystemRoot%\System32\etl2pcapng.exe`. The smoke runner does not download tools,
edit base images, broaden networking, or modify existing HTTP services.

```powershell
.\scripts\Invoke-FoxholeSmokeTest.ps1 `
  -BaseImage C:\ProgramData\Foxhole\images\foxhole-smoke.vhdx `
  -BaseManifest C:\ProgramData\Foxhole\images\foxhole-smoke.manifest.json `
  -GatewayConfig C:\ProgramData\Foxhole\network\host-only.json `
  -AnalysisConfig C:\Foxhole\detection-config.json `
  -Compiler C:\Tools\mingw64\bin\g++.exe `
  -RequireHostPcapng
```

The default output is a fresh `output/smoke-<random-token>` directory. An explicit
`-OutputRoot` must not already exist. Each invocation compiles the repository's
fixture, runs doctor, reuses a healthy `/health` endpoint or starts its own bounded
Python HTTP responder on the configured private host address/port, executes the fixture
inside a normal-user disposable Hyper-V guest, and generates offline HTML with
VirusTotal disabled. The temporary responder is stopped in `finally`; preexisting
services are preserved. An application-specific firewall block can still prevent
guest access despite a successful local health probe; the HTTP assertion catches
this and server logs are retained. `-SkipBuild` skips Rust compilation only.

## What the C++ fixture and verifier cover

`cpp_files/code/test_telemetry_smoke.cpp` uses Windows APIs and a unique run token.
It requires explicit `--foxhole-smoke` arguments and a private IPv4 endpoint.
It creates/renames/deletes small files in its working directory, creates and removes
its own HKCU registry value/key, spawns a bounded copy of itself as a child, queries
that owned child's process handle, loads a system DLL, creates a named pipe, binds
a loopback socket, queries a unique `.invalid` domain, downloads a small HTTP
response, and attempts the unapproved adjacent TCP port. Redirects are disabled.

There is no injection, credential access, destructive behavior, real persistence,
or external executable download. Never use the fixture as a blanket assertion
that every malicious behavior or telemetry channel is covered.

Required evidence includes the exact sample hash, successful fixture operations,
stdout/stderr markers, process creation and normalized child ancestry, file and
registry events, created-file and downloaded-file hashes, attributed WFP attempts at the approved and
unapproved endpoints, verified host-switch policy before and after execution,
started/stopped capture health, retained host ETL, normalized
events, matching HTML data, and successful cleanup without recorded leftovers.
The unapproved connection must fail. A connection failure by itself is not proof
of a particular enforcement layer: the normal guest may log WFP permission before
the host switch blocks traffic. Guest WFP denial is an optional separate probe.
Providing `-AnalysisConfig`
requires YARA/PE/capa/network results and the harmless YARA marker. Providing
`-RequireHostPcapng` requires nonempty host PCAPNG, a positive parsed packet count, and this run's unique
plaintext HTTP request in the host capture.

DNS, pipe, file-delete, process-access and image-load observations are additional
coverage probes. If unavailable under the configured Sysmon policy, they appear as
`not_observed`, never as passes. Capture bounds, encryption, provider loss and
guest-admin tampering remain limitations. A successful smoke result establishes
the listed assertions only, not exhaustive detection or containment.

`smoke-result.json` records each assertion and fails the command on any missing
required evidence. Earlier provisioning/run failures raise an error and retain
whatever diagnostics were produced; do not confuse an older result with a new run.
Keep failed run directories for investigation and use the existing explicit
`--hyperv-recover-run` operation if cleanup requires recovery.

## Progress and stage summaries

Runs print line-oriented progress and periodic elapsed-time messages on stderr.
The guest execution phase includes boot, target execution and scanner/collection
work; it does not infer target launch time from VM boot. Detailed Hyper-V debug
messages require `--debug`. Final target exit and cleanup status remain separate.

Offline analysis adds `analysis/stages.json` and an Overview status table. These
adapt existing scanner statuses instead of changing scanner/report contracts.
Execution, cleanup, each available capture channel, scanners and behavioral
analysis are reported independently. Old archives without a stage remain readable
and report unavailable coverage. A completed stage does not imply a benign sample.

## Verification

The ordinary CI workflow runs synthetic WFP and host-capture lifecycle checks,
smoke-verifier negative cases and offline HTML tests. These need no live VM.
The live smoke runner is an explicit elevated operation on a qualified machine;
never run untrusted PR code on an administrator-owned Hyper-V test host.

The protected `privileged-windows` workflow also offers an explicit `smoke_test`
dispatch input. Configure `FOXHOLE_HYPERV_BASE_IMAGE`,
`FOXHOLE_HYPERV_BASE_MANIFEST`, `FOXHOLE_HYPERV_GATEWAY_CONFIG`,
`FOXHOLE_SMOKE_ANALYSIS_CONFIG`, `FOXHOLE_SMOKE_COMPILER` and
`FOXHOLE_TEST_PYTHON` on that disposable runner. This path requires scanners and
host PCAPNG; it does not execute automatically for pull requests.
The separate `privileged_windows` input runs the full desktop and Hyper-V suite;
selecting only `smoke_test` runs the smoke workflow independently.

```powershell
python -m unittest discover -s tests -p test_smoke_verifier.py
powershell -NoProfile -File tests/test_wfp_collector.ps1
powershell -NoProfile -File tests/test_host_capture.ps1
cargo test --locked --test doctor_cli_test
```

The local outcomes and remaining environment limits are recorded in
[stabilization-verification.md](stabilization-verification.md).
