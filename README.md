# Foxhole

> Experimental software. Do not treat Foxhole as a production malware-analysis appliance.

Foxhole is a Windows CLI for executing a target under either a restricted local process or a disposable Hyper-V guest, collecting bounded evidence, and generating JSON analysis and an offline HTML report.

Current capabilities on `master` include:

- Disposable Hyper-V execution with restricted, standard-user, and guest LocalSystem profiles.
- Deny-all networking or verified host-server and controlled internet access, with capture-health reporting.
- Sysmon, WFP, packet capture, process-tree, file/hash, registry, and stdout/stderr evidence, subject to collection limits.
- Optional guest-only YARA, capa, PE/string, and offline packet analysis with pinned tooling and rule packs; behavioral correlation and provenance-backed IOCs.
- Offline HTML findings, timeline, process, network, IOC, and VirusTotal views; optional hash-only VirusTotal enrichment.
- Read-only deployment diagnostics through `doctor`, a harmless end-to-end smoke workflow, and stale-run cleanup recovery.

Safe USB inspection is developed on the separate `safe-usb` branch and is not included in this `master` checkout.

See [deterministic detection](docs/deterministic-detection.md) for guest-only YARA, PE/string,
capa, behavioral and offline PCAPNG analysis, installation, rule packs and coverage checks.

## Backends

| Mode | Boundary | Intended use |
| --- | --- | --- |
| `restricted` | AppContainer/LPAC, Job Object, mitigations, WFP; shares the host kernel | Trusted tools and compatibility testing |
| `hyperv` | Disposable Generation 2 VM with a separate kernel | Unknown or hostile inputs |
| `auto` | Hyper-V when available | Fails unless `--allow-restricted-fallback` permits the weaker fallback |

Use Hyper-V for untrusted code. The local restricted backend is defense in depth, not a VM-equivalent security boundary.

## Build

For read-only deployment checks, run `foxhole doctor`. For an end-to-end harmless
VM fixture with evidence assertions, use `scripts/Invoke-FoxholeSmokeTest.ps1`.
See [doctor and smoke-test setup](docs/doctor-and-smoke.md) for requirements,
commands, stage summaries, and coverage limits.

Requirements: Windows, Rust, an elevated PowerShell session for Hyper-V, and an enabled Hyper-V feature with VMMS running.

```powershell
cargo build --release --locked
```

Check a prepared host and image before execution:

```powershell
.\target\release\foxhole.exe doctor `
  --base-image "C:\ProgramData\Foxhole\images\foxhole-base.vhdx" `
  --base-manifest "C:\ProgramData\Foxhole\images\foxhole-base.manifest.json" `
  --json
```

## Run

### Required path format

**For now, supply literal absolute local Windows paths beginning with a drive letter, such as `C:\Foxhole\runs\test_1810_2`, for every file/directory argument.** This includes `--path`, `--output`, `--settings`, `--analysis-config`, `--hyperv-base-image`, `--hyperv-base-manifest`, `--hyperv-gateway-config`, `--hyperv-recover-run`, the analyzer's run-root argument, and the corresponding `doctor` paths. Do not pass relative values such as `.\test_1810_2` or `tmp\analysis-config.json`; relative paths can fail with `path is not absolute`. Expand environment variables before passing a path, and quote paths containing spaces. UNC/network-share paths are unsuitable for protected local inputs.

The examples use `C:\Foxhole` as a short, non-personal repository location; replace it with your actual checkout. Relative executable/script names such as `.\target\release\foxhole.exe` only locate the command from the repository root. They do not relax the requirement for its path arguments. Paths in artifact tables below describe the output layout, not command arguments.

`--report` is a specific exception: its filename is relative to Foxhole's protected artifact directory. Arguments after `--` belong to the target program and follow that program's own rules.

Restricted process:

```powershell
.\target\release\foxhole.exe `
  --path C:\samples\program.exe `
  --sandbox restricted `
  --timeout 30
```

Hyper-V:

```powershell
.\target\release\foxhole.exe `
  --path C:\samples\unknown.exe `
  --sandbox hyperv `
  --hv-profile r `
  --hyperv-base-image C:\ProgramData\Foxhole\images\foxhole-base.vhdx `
  --hyperv-base-manifest C:\ProgramData\Foxhole\images\foxhole-base.manifest.json `
  --output C:\Foxhole\runs
```

Guest profiles:

- `--hv-profile r`: restricted AppContainer; default.
- `--hv-profile n`: disposable standard guest user. The guest agent provisions and removes a
  random local account for each run unless a fixed account is explicitly configured in the image.
- `--hv-profile a`: guest LocalSystem. This does not run the target on the host, but the target can tamper with in-guest telemetry.

Normal and admin profiles require `--mitigation-profile compatible`.

### Download-test example

Run this from an elevated PowerShell session after building the release binaries and preparing the demo image. Start the host HTTP server at `http://192.168.250.1:8080` first using the host-only network setup below. Use a fresh output directory for each test.

```powershell
.\target\release\foxhole.exe `
  --path "C:\Foxhole\cpp_files\toTest\test_download.exe" `
  --sandbox hyperv `
  --hv-profile n `
  --allow-host-server `
  --hyperv-gateway-config "C:\ProgramData\Foxhole\network\host-only.json" `
  --hyperv-base-image "C:\ProgramData\Foxhole\images\foxhole-ioc-demo.vhdx" `
  --hyperv-base-manifest "C:\ProgramData\Foxhole\images\foxhole-ioc-demo.manifest.json" `
  --analysis-config "C:\Foxhole\tmp\detection-demo-config.json" `
  --output "C:\Foxhole\test_1810_2" `
  --timeout 60 `
  -- "http://192.168.250.1:8080"

.\target\release\foxhole-analyze.exe "C:\Foxhole\test_1810_2" --no-virustotal
```

The sample path ends with `cpp_files\toTest\test_download.exe` once; do not append a second copy of that path. The analyzer prints the generated HTML report's location. Omit `--no-virustotal` and supply `--settings "C:\Foxhole\settings.json"` to enable configured hash-only VirusTotal lookups.

`detection-demo-config.json` is generated setup data, not a file supplied by a fresh checkout. It enables scanner stages and records the guest interpreter/rule paths and SHA-256 hashes. The JSON lives on the host; its scanner paths refer to files installed inside the prepared guest image. It is separate from the host's Python environment used for tests. Generate it with `scripts/build_detection_config.py` using an exact copy of the guest interpreter and the deployed rules, as described in [deterministic detection setup](docs/deterministic-detection.md). The configuration must match the selected image. Omitting `--analysis-config` runs without those configured scanner stages and reduces detection coverage.

Useful options:

```text
-o, --output <PATH>       Root for reports, logs, and Hyper-V run data
--clean-up                Remove only Foxhole's default artifacts and logs
--dry-run                 Validate without launching the target
--no-report               Disable the final JSON report
--network-policy <MODE>   deny-all, host-server, allow-list, allow-internet, capture-only
--allow-host-server       Hyper-V: only the configured host HTTP endpoint
--allow-external-network  Hyper-V: controlled public IPv4/DNS through verified NAT
--allow-ip <IP/CIDR>      Repeatable allow-list entry
--timeout <SECONDS>       Guest target execution limit
--hyperv-boot-timeout     Guest boot allowance
--hyperv-recover-run      Reconcile a stale protected Hyper-V run
--analysis-config <JSON>  Offline guest scanner configuration; absolute host path
```

Run `foxhole.exe --help` for the complete option list.

## Hyper-V behavior

Each run uses a read-only base image, differencing OS disk, bounded run-data disk, random VM identity, Secure Boot, fixed CPU/memory, and host-authoritative timeout and cleanup. Nested virtualization is disabled, host resource protection is enabled, the virtual DVD drive is removed, and Heartbeat is the only enabled Hyper-V integration service.

`deny-all` remains the default: it removes every virtual NIC and verifies the VM has none. The two
controlled networking shortcuts are Hyper-V-only and mutually exclusive. They also conflict with an
explicit `--network-policy` unless it names the identical policy. `--network-policy` and `--allow-ip`
remain available for existing restricted-process workflows; Hyper-V never silently maps an
unsupported policy to broader access.

### Controlled Hyper-V networking

Controlled modes require a persistent, administrator-configured Internal switch and a gateway JSON
file. Foxhole treats that JSON as expected state, not proof: immediately before target launch and
again after execution it queries the actual switch, host adapter/address, NAT and static mappings,
routes, exact VM-adapter extended ACLs, the host-ingress firewall tuple, IPv6 state, and (for
controlled modes) packet-capture provider.
Missing commands or any mismatch abort the run. The Default Switch, External switches, and Private
switches are rejected. Per-run firewall rules, capture sessions, and atomic guest-address leases are
journaled before use and removed only after the VM is stopped and removed. Persistent switches,
host adapters, and NAT objects are never run-owned or deleted by cleanup.

Create or verify the dedicated host-only infrastructure from an elevated PowerShell session:

```powershell
.\scripts\Configure-FoxholeControlledNetwork.ps1 -Mode HostOnly
```

This creates the persistent `Foxhole Internal` Internal switch, configures only
`192.168.250.1/24` on its host adapter, disables IPv6 there, verifies NAT is absent, protects the
guest-address allocation directory, and writes
`C:\ProgramData\Foxhole\network\host-only.json`. It does not use Hyper-V's Default Switch. Start the
included server on the fixed address (wildcard binds are refused):

```powershell
python .\cpp_files\server\server.py `
  --host 192.168.250.1 `
  --port 8080 `
  --files-dir C:\Foxhole\server-files
```

Then run:

```powershell
.\target\release\foxhole.exe `
  --path C:\samples\unknown.exe `
  --sandbox hyperv `
  --allow-host-server `
  --hyperv-gateway-config C:\ProgramData\Foxhole\network\host-only.json
```

The trusted guest agent configures its one synthetic NIC before it launches the target. Host-server
mode has no default route and no usable DNS configuration. Per-run VM-adapter ACLs and an exact
Windows Firewall host-ingress rule permit only the allocated guest address to reach
`192.168.250.1:8080/TCP`; catch-all outbound/inbound denies block other host ports, private
destinations, DNS, and the internet. An administrator must remove any pre-existing explicit Windows
Firewall block rule that covers the chosen server binary because Windows gives explicit block rules
precedence over a narrow allow rule; Foxhole never weakens unrelated host firewall policy.

For controlled external IPv4 access, create a separate Internal switch and NAT:

```powershell
.\scripts\Configure-FoxholeControlledNetwork.ps1 `
  -Mode External `
  -DnsServers 1.1.1.1,8.8.8.8

.\target\release\foxhole.exe `
  --path C:\samples\unknown.exe `
  --sandbox hyperv `
  --allow-external-network `
  --hyperv-gateway-config C:\ProgramData\Foxhole\network\external.json
```

External mode configures only the approved DNS resolvers, a default route through the verified NAT
gateway, absence of NAT static mappings, and a per-run capture session before target start. Ordered
VM-adapter ACLs allow DNS only to the approved resolvers and stateful outbound TCP to public IPv4
destinations while blocking other DNS resolvers, RFC1918,
carrier-grade NAT, loopback, link-local, local/peer VM space, multicast, reserved/documentation
ranges, and metadata endpoints. Unsolicited inbound traffic is blocked. IPv6 is disabled in both the
host adapter setup and the guest and is attested; Foxhole does not fall back to unfiltered IPv6.
Each ACL uses a unique attested weight, including configurations with multiple approved resolvers;
duplicate resolvers and lists larger than eight are rejected.

The same JSON path can be supplied through `FOXHOLE_HYPERV_GATEWAY_CONFIG`. A networked invocation
without a valid configuration fails closed. For host-server mode, start the server before Foxhole so
the pre-run check can prove that the configured port is bound specifically to `192.168.250.1`, not
`0.0.0.0` or `::`.

The host validates request/result hashes, protocol state transitions, artifact manifests, paths, sizes, and SHA-256 values before publishing output. Guest output is never trusted directly.

## Telemetry

The Hyper-V guest combines Sysmon process, DNS, file, registry, pipe, WMI,
image-load, process-access and tampering events; Windows Filtering Platform (WFP)
Security audit events; bounded Packet Monitor capture; and bounded stdout/stderr.
Before launching the target, the guest enables success and failure auditing for
both Filtering Platform Connection and Filtering Platform Packet Drop, using
locale-independent subcategory GUIDs. Events 5152–5159 cover blocked packets,
permitted/blocked connections, binds, and listens. Audit interruption, log clearing,
log rollover, and policy-change indicators are reported when observed.

Artifacts (paths are relative to the Hyper-V run directory):

| Artifact | Contents |
| --- | --- |
| `collected-artifacts/guest-output/extracted-files/telemetry-events.json` | Raw normalized, bounded Sysmon/WFP/Defender events. WFP events include unattributed attempts; an empty successful collection is preserved as `[]`. |
| `collected-artifacts/guest-output/extracted-files/network-capture.etl` and `.pcapng` | Guest Packet Monitor capture, bounded to 64 MiB per artifact. |
| `network-capture.etl` and `network-capture.pcapng` | Host switch capture, bounded to 128 MiB per artifact, scoped to the run's guest IPv4. |
| `network-capture-health.json` | Host capture health, also retained during failed-run cleanup/recovery when finalization runs. |

Host capture starts and is attested before VM boot, and stops only after the VM
has been removed, including timeout and interrupted-run cleanup. It therefore
covers target launch through termination. Capture is required for both external
and host-server modes; a failed start prevents launch. Deny-all retains **no
virtual NIC** and reports host packet capture as unavailable. Guest WFP can still
record local bind/listen and denied network attempts in that mode.

Host NDIS ETL conversion requires an administrator to provision Microsoft's
[`etl2pcapng.exe`](https://github.com/microsoft/etl2pcapng) in the host Windows
`System32` directory. Foxhole never downloads a converter or searches PATH at run
time. Conversion has a 45-second deadline and a 128 MiB output limit. If the tool
is missing or conversion fails, ETL remains available and the report explicitly
warns that PCAPNG is unavailable/incomplete. Guest conversion uses Windows Pktmon.
Neither converter decodes encrypted application content.

The report's `result.network_connections[].event` carries WFP `time_utc`,
`event_id`, `action`, `image`, and `correlation` (`target`, `confidence`, `reason`,
`process_guid`), alongside PID, protocol, local/remote IP and port, and elapsed
`observed_at_ms`. Inbound endpoints are normalized to local/remote orientation.
Raw events retain the bounded original event-data fields as well. Correlation uses
Sysmon process-tree GUIDs and PID lifetimes where available; because WFP has no
ProcessGuid, this is explicitly **inferred**. Root-PID-only fallback has low
confidence. Unknown/reused PIDs remain in the raw archive without target
attribution, rather than being silently discarded. Bind/listen events need not
have a remote endpoint; unavailable raw PIDs are null.

Schema 2.3 adds `result.capture_health` entries for `guest_wfp`, `guest_pktmon`,
and `host_ndis`:

- `requested`, `started`, `stopped` describe the observed collection lifecycle.
  For WFP, stopped means the bounded query through the execution end time finished;
  auditing itself remains enabled until the disposable guest is destroyed.
- `byte_limit`, `event_limit`, `raw_event_limit` describe configured bounds. WFP
  queries retain at most 10,000 window records before normalization; the shared
  raw archive retains at most 5,000 records and 8 MiB, prioritizing WFP. The complete
  structured views share a separate 6 MiB budget; the collector response has a
  16 MiB acceptance limit.
- `captured_bytes`, `captured_packets`, `captured_events`, `retained_events`
  describe available counters. ETL byte counts are file sizes, not wire payload
  bytes. Packet counts describe records in a valid retained PCAPNG and can include
  provider duplicates. WFP counts describe retrieved and archived records, not all
  events generated in the guest.
- `truncated`, `dropped_events`, `dropped_packets`, `loss_detected`,
  `provider_errors`, `artifacts`, and `warnings` describe known gaps and artifacts.
  Null counters/limits mean unknown or not applicable, **never zero loss**.
  Unavailable channels, unconfirmed stops, truncation, and provider errors also
  produce explicit report warnings. Older guest output lacking health metadata
  produces a coverage warning.

Telemetry is **never complete**. Encrypted traffic content, events lost before
instrumentation, capture byte/event bounds, and guest-admin tampering can prevent
complete observation. Circular ETL files can overwrite earlier packets, and
providers may lose events or packets without exposing usable counters. Packets
blocked before the host switch provider are not observable there; WFP can only
observe attempts that reach its instrumented Windows layers. The guest execution
window ends when the runner returns after process cleanup; a bounded collection
grace period allows delayed event-log writes but does not extend that window.
Empty arrays are not evidence that no network attempt occurred.

The offline HTML report shows capture-health cards on **Overview** and **Network**,
including lifecycle states, bounds, counts, loss indicators, provider errors, and
artifact paths. The Network page also has a searchable, paginated WFP table with
UTC timestamps, event IDs/actions, endpoints, process images, attribution confidence
and reasons, and expandable raw evidence. Unattributed guest-wide events remain
visible without being promoted into target-only behavioral findings. These fields
are published as `normalized.capture_health` and `normalized.network_attempts` in
`web/data/report-data.js`. Regenerate existing HTML reports with `foxhole-analyze`
to use the new views; older runs cannot recover telemetry that was never captured.

Telemetry does not change network permissions: external mode still permits only
approved DNS and outbound public IPv4 TCP, blocks other UDP/QUIC, and disables
IPv6. DNS remains the existing explicit UDP/TCP port-53 exception; capture never
adds an allow rule or relaxes containment.

## Analyst reports

Report analysis is provided by the separate `foxhole-analyze` executable. It reads a completed run's collected evidence and generates normalized JSON, a verdict, IOCs, and an offline HTML report. It does not execute the sample again or start a VM.

### Build the report analyzer

From the repository root, build just the analyzer:

```powershell
cargo build --release --locked --bin foxhole-analyze
```

The executable is written to `C:\Foxhole\target\release\foxhole-analyze.exe` for the example checkout. The general `cargo build --release --locked` command also builds it alongside the other binaries.

### Analyze a run

Pass the absolute output directory used for the Foxhole run. For the download-test example, generate a report without VirusTotal network requests:

```powershell
.\target\release\foxhole-analyze.exe "C:\Foxhole\test_1810_2" --no-virustotal
```

To enrich file hashes with VirusTotal results, supply an absolute settings path containing your API key and trusted-engine configuration:

```powershell
.\target\release\foxhole-analyze.exe "C:\Foxhole\test_1810_2" `
  --settings "C:\Foxhole\settings.json"
```

Keep your API key in a private local settings file, and leave the tracked settings template's key empty.

You can also build and run the analyzer through Cargo:

```powershell
cargo run --release --locked --bin foxhole-analyze -- "C:\Foxhole\test_1810_2" --no-virustotal
```

The input can instead be one specific run, for example `C:\Foxhole\test_1810_2\hyperv\runs\<run-id>`; replace `<run-id>` with the actual directory name. When multiple runs are discovered, use the arrow keys and Enter to select a report in the terminal.

### Open the HTML report

On completion, the analyzer prints the JSON output paths and `web=` / `open_web_path=` lines containing the HTML report's absolute path. Copy that path into your browser or open the file in Explorer. For a report generated directly below the example output root:

```powershell
Start-Process -FilePath "C:\Foxhole\test_1810_2\web\index.html"
```

Use the printed path when a specific run was selected, since its report may be written beneath that run's directory. Keep the entire generated `web` folder together when sharing or moving a report. You can rerun the analyzer on archived evidence to regenerate the HTML with updated report views; it cannot recover telemetry or scanner evidence that was not collected during execution.

The command also accepts a specific `hyperv/runs/<run-id>` directory. By default it reads the VirusTotal API key and trusted-engine list from `settings.json`, performs hash-only file-report lookups, and writes the sanitized results to `analysis/virustotal.json`. It never uploads report files during this enrichment step. Use `--settings <PATH>` to select another settings file or `--no-virustotal` to generate the report without network lookups.

The analyzer writes `normalized.json`, `stages.json`, `detection.json`, `verdict.json`, `iocs.json`, and `virustotal.json` below `analysis/` without modifying raw artifacts. If an artifact root contains multiple runs, it offers an interactive terminal selector. A separate offline report is generated at `web/index.html`, with linked findings, timeline, process, network, IOC, and VirusTotal pages. The VirusTotal page places the main executed file first, followed by other hashed files observed in the guest; each row expands to detection statistics and complete per-engine results. The web report uses local assets only, so the complete `web/` directory can be opened directly or copied as one unit without a web service.

Every malformed event becomes a warning with its raw value, inferred PID associations are marked as inferred, artifact hashes are reverified, and every finding and IOC retains source provenance. The web report renders untrusted evidence through text-only DOM operations rather than HTML insertion.

Verdict scoring is intentionally small: informational rules add 0 points, suspicious rules add 30, and malicious rules add 70. Scores from 20 through 59 are suspicious and scores of 60 or more are malicious; an explicit malicious finding is always malicious. Common test domains, loopback/unspecified addresses, Windows system binaries, and routine system registry keys remain visible as contextual or likely benign IOCs. When an archived run does not expose the original target hash, IOC extraction records `target_hash_unavailable` rather than treating a request hash or launcher hash as the target hash.

## Base image

The image must be a standalone Generation 2 Windows VHDX with current security updates, no personal data or host credentials, and `foxhole-agent.exe` registered as an automatic service. Build the statically linked agent:

```powershell
.\scripts\Build-FoxholeGuestAgent.ps1
```

Update an existing image:

```powershell
.\scripts\Update-FoxholeBaseAgent.ps1 `
  -ImagePath C:\ProgramData\Foxhole\images\foxhole-base.vhdx `
  -AgentPath C:\Foxhole\target\guest-agent-static\release\foxhole-agent.exe
```

Stage a Microsoft-signed Sysmon binary and Foxhole configuration:

```powershell
.\scripts\Install-FoxholeGuestTelemetry.ps1 `
  -ImagePath C:\ProgramData\Foxhole\images\foxhole-base.vhdx `
  -SysmonPath C:\tools\Sysmon64.exe
```

The normal-user profile automatically provisions a disposable standard account, so a fixed guest
credential is not required. To opt into a preconfigured account without placing its password in the
repository or host request:

```powershell
$password = Read-Host 'Configured guest password' -AsSecureString
.\scripts\Configure-FoxholeGuestNormalProfile.ps1 `
  -ImagePath C:\ProgramData\Foxhole\images\foxhole-base.vhdx `
  -Username Erick `
  -Password $password
```

Finalize a new image and manifest:

```powershell
.\scripts\Finalize-FoxholeBaseImage.ps1 `
  -ImagePath C:\ProgramData\Foxhole\images\foxhole-base.vhdx `
  -ImageVersion 2026.08.1
```

After modifying an already finalized image, use `Refinalize-FoxholeBaseImage.ps1` with a unique manifest backup path. Foxhole requires the guest's `FOXHOLE_GUEST_IMAGE_VERSION` to match the manifest version.

Environment alternatives are `FOXHOLE_HYPERV_BASE_IMAGE`, `FOXHOLE_HYPERV_BASE_MANIFEST`, and `FOXHOLE_HYPERV_GATEWAY_CONFIG`.

## Output

The final report uses schema `2.3`. The `target` object records the pinned primary file's SHA-256,
and target-created file observations include SHA-256 evidence when Sysmon supplied a creation hash
or the guest could safely hash the remaining regular file within bounded collection limits. The
offline `web/index.html` report shows the primary file name, size, and hash plus a deduplicated table
of files created or downloaded inside the VM. Hyper-V metadata records the requested mode, switch identity and
type, allocated guest address, gateway/DNS, host endpoint, firewall scope and rule identifiers,
capture state, pre/post verification snapshots, and cleanup results/warnings. A custom `--output`
root contains reports, Hyper-V run records, logs, and validated guest artifacts. Without `--output`,
Foxhole uses its protected directories below `%LOCALAPPDATA%\Foxhole`.

`--clean-up` removes only the default Foxhole artifact/log locations. It never deletes a custom `--output` location.

## Security maintenance

Keep the host, guest image, firmware, and drivers patched. Foxhole reduces exposed virtual hardware and host integration channels, but code cannot compensate for a vulnerable Hyper-V host. Do not use the Hyper-V host as a general workstation while analyzing hostile samples, mount untrusted VHDs on it, or expose personal files to the guest.

Run dependency and code checks before rebuilding an image:

```powershell
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
py -3.13 -m venv C:\Foxhole\tmp\detection-venv
C:\Foxhole\tmp\detection-venv\Scripts\python.exe -m pip install --no-deps -r C:\Foxhole\guest-agent\assets\detection-requirements.lock
$env:FOXHOLE_TEST_PYTHON = 'C:\Foxhole\tmp\detection-venv\Scripts\python.exe'
cargo test --all-targets --locked
cargo audit
```

Create the Python environment once, then reuse it for subsequent test runs. Use Python 3.13 and the locked requirements: the real capa worker regression fails with `this regression needs the pinned scanner test runtime` when its interpreter is missing. You do not need to activate the environment. `cargo audit` requires a separate `cargo install cargo-audit --locked` installation.

The detection CI workflow also runs Python scanner fixtures, offline JavaScript DOM tests, PowerShell telemetry/capture regressions, and coverage-baseline checks. A plain `cargo test` does not run all of those checks. See [detection verification](docs/detection-verification.md).

Real Hyper-V smoke tests require an elevated Windows test host and a configured base image. Ordinary tests include live restricted-process checks; they skip privilege-dependent checks when the process is not elevated. Run live Hyper-V tests only through the documented opt-in workflow on a disposable host. The `doctor` command checks host prerequisites without launching a target, but guest scanner and telemetry readiness still require a live smoke test.
