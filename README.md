# Foxhole

> Experimental software. Do not treat Foxhole as a production malware-analysis appliance.

Foxhole is a Windows CLI for executing a target under either a restricted local process or a disposable Hyper-V guest and producing a bounded JSON report plus supporting artifacts.

## Backends

| Mode | Boundary | Intended use |
| --- | --- | --- |
| `restricted` | AppContainer/LPAC, Job Object, mitigations, WFP; shares the host kernel | Trusted tools and compatibility testing |
| `hyperv` | Disposable Generation 2 VM with a separate kernel | Unknown or hostile inputs |
| `auto` | Hyper-V when available | Fails unless `--allow-restricted-fallback` permits the weaker fallback |

Use Hyper-V for untrusted code. The local restricted backend is defense in depth, not a VM-equivalent security boundary.

## Build

Requirements: Windows, Rust, an elevated PowerShell session for Hyper-V, and an enabled Hyper-V feature with VMMS running.

```powershell
cargo build --release --locked
```

## Run

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

Pass target arguments after `--`:

```powershell
.\target\release\foxhole.exe --path C:\samples\program.exe --sandbox hyperv -- --input sample.dat
```

Guest profiles:

- `--hv-profile r`: restricted AppContainer; default.
- `--hv-profile n`: disposable standard guest user. The guest agent provisions and removes a
  random local account for each run unless a fixed account is explicitly configured in the image.
- `--hv-profile a`: guest LocalSystem. This does not run the target on the host, but the target can tamper with in-guest telemetry.

Normal and admin profiles require `--mitigation-profile compatible`.

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
external mode) packet-capture provider.
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

The Hyper-V guest combines:

- Sysmon process, DNS, file, registry, pipe, WMI, image-load, process-access, and tampering events;
- Windows Filtering Platform allow/block/bind/listen events;
- bounded Pktmon ETL and PCAPNG packet captures;
- bounded stdout and stderr.

The report contains correlated process, network, file, and registry arrays. Raw bounded events are archived as `extracted-files/telemetry-events.json`; packet data is archived as `network-capture.etl` and `network-capture.pcapng`.

Telemetry is evidence, not a completeness proof. Very high event volume can hit bounds, in-guest administrator code can tamper with collectors, an operation rejected before reaching an instrumented Windows subsystem may appear only in process arguments or stderr, and TLS prevents passive capture of plaintext HTTP headers or bodies. Foxhole reports unavailable or incomplete channels instead of claiming empty arrays are complete.

## Analyst reports

Build normalized evidence, a deterministic verdict, and deduplicated IOCs from an existing Hyper-V artifact root:

```powershell
cargo run --bin foxhole-analyze -- C:\Foxhole\runs
```

The command also accepts a specific `hyperv/runs/<run-id>` directory. It writes byte-stable `normalized.json`, `verdict.json`, and `iocs.json` files below `analysis/` without modifying raw artifacts. A separate offline report is generated at `web/index.html`, with linked findings, timeline, process, and IOC pages. It uses local assets only, so the complete `web/` directory can be opened directly or copied as one unit without a web service.

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
  -AgentPath .\target\guest-agent-static\release\foxhole-agent.exe
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

The final report uses schema `2.1`. The `target` object records the pinned primary file's SHA-256,
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
cargo test --all-targets --locked
cargo audit
```

Real Hyper-V smoke tests require an elevated Windows test host and a configured base image. Unit tests do not create VMs or alter host networking.
