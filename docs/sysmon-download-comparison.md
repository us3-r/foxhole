# Download-test comparison and capa fix — 2026-09-07

The corrected Hyper-V run completed with target exit code **0**, successful VM cleanup,
and **completed capa analysis with two capability findings**. YARA and PE analysis also
completed. Results are in `test_ioc_new/capa_fixed`.

## Comparable inputs

All three runs used `test_download.exe`, SHA-256
`d8ad8eebe80ea1a5e8201c8cdd27416ad9652987ed798399dc172f7056bfc38c`, with a normal-user
Hyper-V profile, 60-second target timeout, two vCPUs, 2 GiB guest memory, and the host-only
server `192.168.250.1:8080`. The downloaded child also matched the earlier run:
`f8f913548052c3bd53754c6763222ee06852e5f2834ff04f714b48c54ac022b1`.

| Run | Location | Run ID |
|---|---|---|
| Earlier working run | `test_download_hashing_c` | `acf6aa7a12adb59eec52c3a293ff4cb6` |
| Expansion before these fixes | `test_ioc_new` | `728fa56e77b6184ca4b647891022b5e1` |
| Corrected run | `test_ioc_new/capa_fixed` | `d667e49583ba0641b5b69e55434cd31c` |

The original base image and previous run archives were preserved. The corrected agent was
installed in the dedicated demo image, whose new sealed SHA-256 is
`4ce223f948c43a0abae70b139e3542cb006c5f125c0394144047ea77c811fbcd`.

## Raw Sysmon comparison

Counts below come from each run's archived
`collected-artifacts/guest-output/extracted-files/telemetry-events.json` under
`hyperv/runs/<run-id>`. These are raw target-related Sysmon records; report process lists
also contain a launcher observation, and normalized lists can merge duplicate records.

| Sysmon evidence | Earlier run | Before fix | Corrected run |
|---|---:|---:|---:|
| Process creation, ID 1 | 4 | 0 | 4 |
| Process termination, ID 5 | 4 | 0 | 4 |
| File creation, IDs 11/29 | 6 | 0 | 6 |
| Registry, IDs 12/13 | 8 | 0 | 8 |
| Network connection, ID 3 | 0 | 0 | 2 |
| Process access, ID 10 | 0 | 0 | 4 |
| Total Sysmon records | 22 | 0 | 28 |

Both working runs show the target, console helper, downloaded child and calculator process,
file writes, and the child's `CurrentVersion\Run\FoxholeTestToDownloadExe` startup value.
The four WFP network records were present even in the broken run, explaining why network
activity appeared while the process/file/registry evidence was missing. The corrected run
has no missing-target-process warning. Its report contains 9 process, 6 filesystem,
6 registry and 6 network observations; the earlier report contained 9, 6, 4 and 4 respectively.

## Fixes and verification

The scanner launcher cleared `LOCALAPPDATA`, causing capa's Windows cache setup to raise
`KeyError`. Supplying that value exposed a second missing environment dependency:
Vivisect's `getpass.getuser()` could not determine a username. The launcher now supplies a
cache location inside the protected guest workspace and the fixed `FoxholeScanner` label.
It continues to clear inherited variables and enforce the same scanner job limits.

The Sysmon query previously applied `MaxEvents` before discarding records older than its
baseline. With the added high-volume ProcessAccess event type, recent pre-baseline records
could fill the cap and exclude the target's creation event. GUID-based attribution then
could not identify the process tree. The corrected XPath applies the baseline and time
filters inside Event Log before the cap. Bounds and exact process-GUID attribution remain.
The archived failed run does not retain discarded background records, so its exact omitted
record count cannot be reconstructed; the failure mechanism was reproduced with a crowded
synthetic log, and the corrected live run restored the expected evidence.

Verification completed:

- All 32 guest-agent tests passed, including a real capa worker under the production Job
  launcher against a hand-built inert PE fixture. The fixture is parsed and never executed.
- The actual PowerShell collector passed a fixture with 10,001 older ProcessAccess records
  preceding the target. The pre-fix query failed the same fixture. New-record overflow
  remains bounded and produces an explicit truncation warning.
- The new XPath was accepted by the Windows Event Log API.
- Formatting and `cargo clippy --locked --all-targets -- -D warnings` passed.
- The fresh disposable-VM test and offline report generation succeeded.

The two capa findings describe debugger-detection and process-creation imports, with no
independent verdict weight. The report's suspicious score of 30 includes observed behavior;
this deliberately persistent test helper must be interpreted in its known test context.
The successful capa result covers the primary executable. The report still explicitly lists
packet-local analysis limitations and files outside the private collection directory that
were not scanned; these results do not establish exhaustive behavioral or dropped-file coverage.
