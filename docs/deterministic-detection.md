# Deterministic detection stages 1–5

Foxhole can collect bounded YARA matches, PE properties and strings, capa capabilities,
behavioral chains, and packet observations without an online service. Host analysis imports
hashed JSON; only the disposable Windows guest runs parsers against target bytes. The host
analyzer never launches a scanner or the target. Existing containment and network policy
remain authoritative. There is no new decompiler, AI, upload, or sample-submission feature.

## Install in a disposable base image

1. Build the Rust binaries with `cargo build --release --locked`. Install the updated guest
   agent and telemetry collector using the existing Hyper-V image provisioning procedure.
2. In an administrator-owned **image-building** environment, prepare Python 3.13 and wheels
   for `guest-agent/assets/detection-requirements.lock`. Use `pip wheel --no-deps -r ...`
   with a local wheelhouse. `py-tlsh==4.5.0` needs MSVC C++ build tools on Windows if no
   matching wheel is available. Review and record SHA-256 of every wheel before transfer.
   This is a version lock, not a pip `--require-hashes` file. Do not install undeclared
   transitive dependencies: capa's optional IDA packages are deliberately omitted.
3. Install the reviewed wheels **offline** into an administrator-owned guest interpreter:
   `python -m pip install --no-index --find-links C:\Foxhole\wheelhouse --no-deps -r C:\Foxhole\detection-requirements.lock`.
   Protect the interpreter, its DLLs, site-packages and rule directory from the target token.
   Pin the entire resulting base-image manifest using the existing image integrity workflow.
   Pinning python.exe alone does not authenticate its libraries; the immutable base-image
   hash and guest ACLs are also necessary.
4. Install `rules/foxhole-yara-1.yar`, `rules/foxhole-capa-1.zip`, and
   `rules/foxhole-packet-1.json` into an administrator-owned guest directory. The capa ZIP
   is reproducibly built from `rules/capa/*.yml` by the configuration helper below.
5. Make a local, reviewable configuration using an exact copy of the guest interpreter:

   ```powershell
   python scripts/build_detection_config.py --python-binary C:\ImageBuild\python.exe --guest-python C:\Foxhole\Python\python.exe --guest-rules C:\Foxhole\Rules --output analysis-config.json
   ```

   This helper hashes administrator-owned tooling and packs; it never reads samples.
   Preserve LF rule files during deployment: the configured hash covers exact bytes.
6. Add `--analysis-config analysis-config.json` to the existing Hyper-V run command.
   Configuration is validated before target execution. The option is rejected with the
   restricted-process backend. Scanner executable paths refer to the guest, not the host.

The supported engines are YARA 4.5.2, pefile 2024.8.26 (with LIEF 0.16.6,
cryptography 46.0.5 and py-tlsh 4.5.0), capa 9.2.1 using Vivisect, and
`foxhole-packet-1`, a small equivalent deterministic PCAPNG engine. Dependency versions
are also recorded in the image-build lock. Do not substitute another capa JSON schema or
engine without updating the adapter, version gate and reviewed goldens together.

The bundled rule packs are **small diagnostic starter packs**, not a comprehensive malware
signature database. They recognize harmless fixture markers, selected imports and section
markers. Broader detection requires an analyst-reviewed, versioned, compatible rule corpus.
Build and test that corpus in an isolated image-building worker, record its exact hash and
version in configuration, and rebuild the pinned guest image. No rule update is downloaded
during an analysis run.

## Configuration and resource ceilings

All four scanner blocks accept `enabled`, an absolute `executable` paired with
`executable_sha256`, `rules`, `user_rules`, and `limits`. `rules` contains `id`, `version`,
`path`, and `sha256`. `user_rules` is supported only for YARA, in a separate namespace;
its metadata cannot change Foxhole scores, configuration, or built-in rules. YARA includes
are disabled. capa ZIPs allow bounded YAML rule files only. Packet rules accept schema 1
and exact `{id, field, equals}` entries; scripts, arbitrary regular expressions and Suricata
syntax are not accepted. Rule-pack count, depth, length and hash checks precede use.

Each scanner is independently enabled by default but **unavailable until configured**.
Set `enabled: false` to record `disabled`. Set top-level `behavioral: false` to disable
behavioral scoring, including legacy behavior rules. No scanner executable is searched on
PATH. Unknown fields, traversal, UNC executable paths and invalid pins are rejected.

| Limit | Default | Hard maximum |
|---|---:|---:|
| Per-scanner execution | 60 s | 300 s |
| Worker/job memory | 512 MiB | 2 GiB |
| Scanner input | 32 MiB | 128 MiB |
| Scanner JSON output | 4 MiB | 16 MiB |
| Findings / strings | 512 / 2,048 | 4,096 / 8,192 |
| Bytes per string / match excerpt | 2,048 / 64 | 4,096 / 256 |
| Locations / features | 256 / 256 | 1,024 / 1,024 |
| Recursion depth / rules | 16 / 10,000 | 24 / 50,000 |
| Files / packets / flows | 32 / 100,000 / 4,096 | 64 / 1,000,000 / 16,384 |
| Total scanning time | 180 s | 900 s |
| Capture bytes / aggregate collected-file bytes | 64 MiB each | 128 MiB each |
| Total scanner output | 16 MiB | 32 MiB |

The effective input budget is the smaller applicable limit. Output limits reserve at least
4 KiB per scanner and 16 KiB globally for status records. A suspended child is placed in a
Windows Job with memory, active-process and kill-on-close restrictions before it is resumed.
The launcher uses an explicit argument array, isolated Python mode and a cleared environment;
bounded stdout is collected and stderr is discarded. Timeout, excess output or launcher
failure terminates the job. Target execution time does not consume the separate scan budget.
The cleared worker environment supplies `LOCALAPPDATA` inside the broker-owned guest
workspace for capa's rule cache, and the fixed `USERNAME=FoxholeScanner` label required by
Vivisect. Neither value is inherited from the host or target's user profile.

Primary YARA/PE/capa scans run before execution. After execution, the broker collects regular
target-written executables and scripts from the private guest work directory, hashes and
scans them. It also scans suitable collected executable/script artifacts and PCAPNG captures.
Reparse points, hard links, traversal, missing files, changed files and size/count exhaustion
are rejected or warned. Files outside the private collection directory remain telemetry
observations with an explicit collection warning; Foxhole does not walk the entire guest.
Captured files are named by their hash. Existing exact-cleanup safeguards remain in use.

## Evidence and interpretation

`analysis/detection.json` and the **Analysis** page show effective non-secret configuration,
engine/pack pins, coverage, warnings, file properties, matches, strings, packet flows and
process associations. New fields are additive to report schema `1.0`; scanner/config and
structured telemetry schemas use integer version `1`. Older archives deserialize with
empty detection defaults and visible unavailable coverage. They are not retroactively
scanned on the host. Missing host target hashes are not invented.

Every accepted result must match the host's target hash and collected artifact identity.
The host reopens and rehashes bounded scanner artifacts, checks duplicate keys, count and
depth limits, typed schemas, offsets, hash formats and evidence references, then remaps
guest aliases to normalized evidence IDs. A final publication gate rejects unresolved
references. Failure in one scanner preserves accepted results from other stages.

`completed` means the scanner completed its supported scope. `partial`, `timed_out`,
`unavailable`, `failed`, `invalid_output`, `skipped`, and `disabled` remain distinct. Stage
coverage reflects the worst status across analyzed files. A report-wide banner stays visible
even when the verdict is suspicious or malicious. No failed stage implies a clean scan.

YARA and packet signatures and capa capabilities produce informational findings with **zero
independent verdict weight**. Capabilities describe possible code behavior, not observed
execution. PE timestamps are untrusted metadata. Entropy, RWX sections, section-name packer
markers and an unsigned file are contextual properties, not independent malicious verdicts.
Authenticode uses offline WinVerifyTrust and embedded certificate metadata; a locally valid
signature says nothing about signer reputation or current revocation. Trust stores and image
contents must be fixed for reproducible scanner runs. No online chain retrieval is allowed.

Behavior rules FH-B001–FH-B016 require explicit object/process conditions and 30–120 second
windows. They cover execution, persistence, services/tasks, injection, credential access,
anti-analysis, tampering, DNS/connection chains, script children, packed anti-analysis code,
named pipes and suspicious children. FH-B017 confirms a mapped primary-file capability
against runtime evidence in the primary process lifetime; FH-B018 records nonconfirmation
without treating absence as safety. The finding records version, ATT&CK, required events,
time window, association, confidence, false-positive guidance and every score contribution.
Installers, administration, debugging and test harnesses can produce these chains; review the
actual payload, purpose and objects. Filenames or Microsoft signatures never blanket-allow
behavior. Duplicate evidence shares one score, and each behavior family contributes at most
its strongest score. Inferred associations and incomplete telemetry reduce confidence.

Process termination and available Sysmon GUID changes prevent cross-lifetime PID correlation.
Missing timestamps cannot establish temporal chains. The collector now retains relevant
Sysmon process, injection/access, file, registry, pipe, DNS and network records with relative
timestamps. Sysmon does **not** observe all file reads, API anti-debug checks or task/service
semantics; those rules need explicit supported telemetry and otherwise remain unconfirmed.
Correlation has a fixed million-pair budget and 256 evidence references per rule, with a
visible partial-analysis finding on exhaustion. Duplicate/order properties are tested.

Only syntactically validated concrete values become new IOC candidates. Original and
normalized values, source categories, file hash, offsets, confidence and evidence are retained.
Private/reserved/test IPs, documentation domains, localhost and common Windows paths are
contextual and searchable, not silently discarded. Bitcoin Base58Check is the supported
wallet validator; ambiguous wallet formats are not promoted. Rule names, APIs, ATT&CK IDs
and capability labels are findings or metadata, never standalone IOCs. Legacy command-line
and endpoint observables retain their compatibility fields and provenance.

Network parsing is offline and **packet-local**: Ethernet/VLAN and raw IPv4/IPv6 with bounded
DNS, plaintext HTTP and visible TLS handshakes. It does not reassemble TCP/IP fragments,
decrypt HTTPS, infer hidden TLS 1.3 certificates, or claim unsupported JA4. It emits JA3/JA3S
when the required hello fields are visible and SHA-256/metadata for a complete visible TLS
certificate. Missing/truncated/unsupported data is partial coverage, not proof of absence.
Flow byte counts are captured frame bytes, not reconstructed application byte counts.
Packet timestamps are UTC microseconds; process associations require an explicit capture
clock anchor, matching five-tuple, a one-second window and a unique PID/GUID identity.
Associations remain inferred. Packet IOC times are capture epoch milliseconds; dynamic IOC
times retain the legacy run-relative milliseconds, distinguished by their source category.
DNS answers preserve direct domain/address relationships without assigning unrelated shared-IP
connections to that domain. Association output is bounded to 4,096 entries and a million checks.

Exports use text-only DOM APIs, a restrictive CSP and local assets. Preview values are limited
to 2,048 characters, with full bounded data in downloadable JSON. Hash/evidence links lead
to normalized evidence, not arbitrary scanner-selected host files. Raw command streams,
host invocation/configuration paths and common credential fields/assignments are redacted
from published analysis; the original protected run archive is separate. Share the generated
`web` directory or analysis JSON, not the raw evidence archive. No heuristic can identify an
arbitrary unknown secret embedded in sample bytes; review retained bounded strings before
sharing outside the investigation.

Re-analysis of identical archives is byte-stable. Arrays/maps are normalized and sorted,
artifact hashes are retained, and operational wall-clock scanner durations are represented
as nullable fields rather than embedded in hashed deterministic outputs. Golden fixtures
exclude volatile capa timestamps, command arguments and absolute paths. Existing optional
VirusTotal functionality is unchanged; use `foxhole-analyze --no-virustotal` for fully offline
CLI analysis. The new library analysis path performs no network requests.

## Verification and coverage

Only purpose-built harmless PE bytes, scripts and simulated telemetry are used. The PE
fixture is parsed, never executed on the development host. The launcher integration uses a
trusted interpreter and simple printing/sleeping/exit-code scripts. Real Hyper-V tests use
the repository's bounded harmless helper. No malware download is needed.

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --all-targets
cargo test --locked --all-targets --no-fail-fast
tmp/detection-venv/Scripts/python.exe -m unittest discover -s tests -p test_detection_worker.py
# With NODE_PATH pointing to a trusted jsdom 26.1.0 installation:
node tests/detection_web_test.cjs
```

The detection CI workflow uploads Rust and Python line/branch coverage and enforces
`coverage/detection-baseline.json`. This is the first recorded baseline for this expansion;
the repository had no prior coverage threshold. PRs cannot reduce any recorded threshold.
Run `scripts/test_detection_coverage.ps1`, Python `coverage run --branch` / `coverage json`,
and `scripts/check_detection_coverage.py` to reproduce the CI scope. The seven existing
desktop-dependent tests are excluded **only from this coverage measurement** and listed
explicitly in that script. They remain required in the full Windows job. Do not accept
coverage from a failed test binary, which may not flush its instrumentation counters.

The manually dispatched `privileged-windows` job requires a disposable, trusted Windows
runner with desktop/WFP permissions, Hyper-V access, `FOXHOLE_TEST_PYTHON`,
`FOXHOLE_HYPERV_BASE_IMAGE` and `FOXHOLE_HYPERV_BASE_MANIFEST`. It runs all normal tests plus
the four existing opt-in Hyper-V tests. Configure the protected environment before use.
The job must not run automatically on untrusted PR code. The ordinary hosted runner cannot
prove VM containment or replace these live checks.

Update goldens only by explicitly setting `FOXHOLE_UPDATE_DETECTION_GOLDENS=1`, running the
Python fixture suite and Rust `report_analysis::detection::tests`, unsetting the variable,
reviewing every diff, and rerunning normally. Do not update them to mask a failure. Parser
tests include malformed/schema/hash/count/depth/path/evidence failures and fixed-seed byte
mutation properties. Behavioral tests cover positive, near-miss, duplicate, incomplete,
reordered and PID-reuse cases. Offline DOM tests exercise hostile HTML, bounded rendering,
source filters and evidence anchors.
