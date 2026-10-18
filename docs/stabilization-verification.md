# Stabilization verification — 2026-09-18

Work stayed on `ioc-expand` and preserved the earlier detection and telemetry work.
No Ghidra integration was started. Only harmless repository fixtures were executed.

## End-to-end telemetry smoke

The strict live smoke passed on this Windows Hyper-V host, using a separate sealed
copy of the execution image, normal guest profile, host-server networking, the
existing pinned scanner configuration and host PCAPNG conversion.

Local evidence: `output/smoke-stabilization-04/smoke-result.json` and
`output/smoke-stabilization-04/web/index.html`. Run ID:
`90bdaedb0f2a517477e811cb5571f0d1`. Fixture SHA-256:
`fed3a1372d786f7a74a6a44069d9078c25ea8d269f9eb0bfca94202207458624`.
These generated archives are deliberately not committed.

To repeat that deployment from an elevated shell in this checkout:

```powershell
.\scripts\Invoke-FoxholeSmokeTest.ps1 `
  -BaseImage C:\ProgramData\Foxhole\images\foxhole-stabilization-smoke.vhdx `
  -BaseManifest C:\ProgramData\Foxhole\images\foxhole-stabilization-smoke.manifest.json `
  -GatewayConfig C:\ProgramData\Foxhole\network\host-only.json `
  -AnalysisConfig .\tmp\detection-demo-config.json `
  -Compiler 'C:\Program Files\JetBrains\CLion 2024.2.2\bin\mingw\bin\g++.exe' `
  -Python "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" `
  -RequireHostPcapng
```

Those installed paths and the ignored deployment configuration are local to this
machine; other hosts should use the generic [setup guide](doctor-and-smoke.md).

The final verifier records 48 passing checks, no required failures, and two
optional observations missing: the system-DLL image-load event and a guest WFP
denial. The host switch enforces the unapproved endpoint; guest WFP permission
does not imply that the connection succeeded. The target exited zero after about
7.4 seconds, both host network attestations passed, and cleanup recorded no
leftover resources. Host capture retained 9 packets and the unique HTTP request;
guest capture retained 52 packets, and WFP retained 21 events. These counts describe
this fixture run, not exhaustive telemetry coverage.

YARA, PE and capa completed. The packet scanner returned its explicit partial
status because its bounded parser does not provide general TCP reassembly.
Sysmon process, file, registry, DNS, named-pipe, deletion and owned-child access
evidence was observed. Bind/listen WFP events and created/downloaded file hashes
were also verified. Rename is exercised by the fixture but is not asserted as a
separate Sysmon rename event.

Live testing exposed and corrected the capture provider's `128 MB` size rendering,
setup audit events being included in the observation window, executable-name
assumptions after staging as `target.bin`, and excessive C++ runtime code causing
capa timeouts. The final fixture uses bounded buffers and remains within the
existing 60-second scanner budget. No scanner budget or coverage threshold was
relaxed. Audit policy changes during observation still signal incomplete coverage.

The HTTP fixture uses Python. An existing host firewall rule blocks PowerShell
listeners; that rule was preserved. Microsoft's signed etl2pcapng converter was
installed for this verification. The original execution VHDX was preserved; only
the separate smoke image received the rebuilt agent.

## Automated checks and limits

Formatting, all-target Clippy with warnings denied, the locked release build,
doctor CLI tests, scanner fixtures, WFP/host-capture regression checks, smoke
verifier negative cases and offline DOM checks were run locally. The new tests
keep execution, cleanup, scanner availability and capture health independent.

The full ordinary Rust suite recorded 334 passes, seven failures and four ignored
live tests. The same seven restricted-process tests failed before this work. They
also fail in the elevated hidden session, with private-desktop/token launch
errors. Their assertions and isolation controls were not weakened. The separate
coverage job excludes exactly those pre-existing seven tests; the protected
Windows CI job still runs them unfiltered. No remote CI run or push was performed.

The final coverage gate passed: Rust lines 60.52% and branches 48.38%; critical
lines 85.63% and branches 56.80%; Python worker lines 77.49% and branches 64.57%.
The recorded minimums remain unchanged.

Live Hyper-V tests build the std-only helper source with static CRT linkage into
an independent single-link file. This avoids Cargo hard links and a dependency on
guest-installed `VCRUNTIME140.dll`. They use a short dedicated output directory
under `target/hv-*`, and a bounded coordinator
deadline separate from the target timeout. Run them serially with the execution
image idle; an attached parent image is rejected by preflight. Failed exploratory
runs in the default AppData archive reported a staging-directory collision; that
default-path deployment behavior remains unqualified by the successful smoke,
which uses an explicit output root. Failed preparation diagnostics were retained.

The ordinary-execution and host-canary tests retain the restricted guest profile.
The no-NIC and process-tree timeout tests explicitly use normal/compatible guest
execution: the restricted profile rejects Winsock startup and child creation
before those tests can exercise their intended Hyper-V controls. This is test
configuration, not a change to production defaults or acceptance of a panic as a
successful network probe. The earlier failures remain in local diagnostic logs.

All four live cases were verified: restricted-profile ordinary execution and
host-canary isolation passed, followed by a targeted rerun in which the corrected
normal-profile no-NIC and process-tree timeout cases both passed. The latter
connection probe returned the expected failure code 2; the tree run recorded
`timed_out=true`. Guest cleanup succeeded in all four cases. This is not a claim
that restricted guests can initialize sockets or create child processes.

The final read-only host audit checked 21 retained run directories. It found no
remaining run-owned VMs, virtual disks, firewall rules or capture sessions. The
temporary HTTP server was stopped, the smoke base was detached, and the original
source VHDX still matched its sealed manifest hash.
