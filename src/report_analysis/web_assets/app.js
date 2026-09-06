"use strict";

(() => {
  const report = window.FOXHOLE_REPORT;
  const page = document.body.dataset.page;
  const error = document.getElementById("report-error");

  if (!report || !report.normalized || !report.verdict || !report.iocs) {
    error.hidden = false;
    error.textContent = "Report data could not be loaded. Keep the data and assets folders beside this page.";
    return;
  }

  const normalized = report.normalized;
  const verdict = report.verdict;
  const iocs = report.iocs;
  const downloadsByEndpoint = correlateDownloads();
  const targetPath = normalized.target && typeof normalized.target.path === "string"
    ? normalized.target.path
    : "<unknown target>";
  const targetFileName = basename(targetPath);

  document.querySelectorAll("[data-nav]").forEach((link) => {
    if (link.dataset.nav === page) link.setAttribute("aria-current", "page");
  });
  setText("run-id", normalized.run_id);
  setText("target-file-name", targetFileName);
  setText("schema-version", normalized.schema_version);
  const targetChip = document.getElementById("target-file-name");
  if (targetChip) targetChip.title = targetPath;
  document.title = `${targetFileName} · ${document.title}`;

  const renderers = {
    overview: renderOverview,
    parameters: renderParameters,
    findings: renderFindings,
    timeline: renderTimeline,
    processes: renderProcesses,
    network: renderNetwork,
    iocs: renderIocs,
  };
  if (renderers[page]) renderers[page]();

  function renderOverview() {
    const findingCounts = countBy(verdict.findings, (finding) => finding.severity);
    const contextual = iocs.indicators.filter((indicator) => indicator.contextual).length;
    const strip = document.querySelector(".verdict-strip");
    setText("overview-target-file", targetFileName);
    setText("target-size", formatBytes(normalized.target && normalized.target.size_bytes));
    const targetSha256 = normalized.target && typeof normalized.target.sha256 === "string"
      ? normalized.target.sha256
      : ((normalized.target_hashes || []).find((hash) => hash.algorithm === "sha256") || {}).value;
    setText("target-sha256", targetSha256 || "Not available");
    const targetVirusTotal = document.getElementById("target-virustotal");
    if (isSha256(targetSha256)) {
      targetVirusTotal.href = virusTotalUrl(targetSha256);
      targetVirusTotal.hidden = false;
    } else {
      targetVirusTotal.removeAttribute("href");
      targetVirusTotal.hidden = true;
    }
    strip.dataset.verdict = verdict.verdict;
    setText("verdict-label", verdict.verdict);
    setText("score-value", verdict.score);
    setText(
      "verdict-summary",
      verdict.findings.length
        ? `${verdict.findings.length} deterministic rule${plural(verdict.findings.length)} triggered. ${findingCounts.suspicious || 0} suspicious and ${findingCounts.malicious || 0} malicious finding${plural((findingCounts.suspicious || 0) + (findingCounts.malicious || 0))}.`
        : "No deterministic behavioral rules triggered for this run."
    );
    const gauge = document.getElementById("score-gauge");
    gauge.dataset.verdict = verdict.verdict;
    gauge.style.setProperty("--score", `${Math.min(100, verdict.score) * 3.6}deg`);
    gauge.setAttribute("aria-label", `${verdict.verdict} verdict, score ${verdict.score}`);

    setText("finding-count", verdict.findings.length);
    setText(
      "finding-mix",
      `${findingCounts.informational || 0} info · ${findingCounts.suspicious || 0} suspicious · ${findingCounts.malicious || 0} malicious`
    );
    setText("timeline-count", verdict.timeline.length);
    setText("ioc-count", iocs.indicators.length);
    setText("ioc-context", `${contextual} contextual or likely benign`);
    setText("warning-count", normalized.validation_warnings.length);

    renderActivityChart("activity-chart", verdict.timeline);
    renderBars("event-bars", [
      ["Process", normalized.raw_event_counts.process, "process"],
      ["Network", normalized.raw_event_counts.network, "network"],
      ["Filesystem", normalized.raw_event_counts.filesystem, "file"],
      ["Registry", normalized.raw_event_counts.registry, "registry"],
    ]);
    renderBars(
      "ioc-bars",
      Object.entries(iocs.counts_by_type)
        .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .slice(0, 7)
        .map(([label, value]) => [humanize(label), value, ""])
    );
    renderCoverage();
    renderFindingSummary();
    renderCreatedFileHashes();
  }

  function renderParameters() {
    const execution = normalized.execution || {};
    const target = normalized.target || {};
    const sandbox = normalized.sandbox || {};
    const hostReport = normalized.raw && normalized.raw.host_report ? normalized.raw.host_report : {};
    const recordedInvocation = hostReport.host_invocation || null;
    const backendSelection = hostReport.backend_selection || {};
    const rootProcess = (normalized.processes || []).find((process) => process.pid === Number(execution.pid));
    const observedCommand = rootProcess && rootProcess.command_line;
    const reportedArguments = Array.isArray(target.arguments) ? target.arguments : [];
    const commandLine = recordedInvocation && recordedInvocation.command_line
      ? recordedInvocation.command_line
      : reconstructHostCommand(hostReport, target, sandbox);
    const allowedNetworks = recordedInvocation && Array.isArray(recordedInvocation.allowed_networks)
      ? recordedInvocation.allowed_networks
      : [];
    const targetArgumentCount = recordedInvocation && Number.isInteger(recordedInvocation.target_argument_count)
      ? recordedInvocation.target_argument_count
      : reportedArguments.length;

    setText("host-command-line", commandLine);
    setText("host-command-source", recordedInvocation ? "Recorded by host" : "Reconstructed · legacy report");
    setText(
      "host-command-note",
      recordedInvocation
        ? "The host command is PowerShell-ready. The target path is reduced to its filename and target argument values remain redacted in exported reports."
        : "This older report did not retain the original host command or output root. Known effective settings are reconstructed; placeholders mark values that cannot be recovered."
    );
    setText("parameter-output", recordedInvocation && recordedInvocation.output_root ? recordedInvocation.output_root : "Not retained in legacy report");
    setText("parameter-requested-backend", humanize(backendSelection.requested || sandbox.backend || "unknown"));
    setText("parameter-selected-backend", humanize(backendSelection.selected || sandbox.backend || execution.backend || "unknown"));
    setText("parameter-hv-profile", hyperVProfileLabel(sandbox.guest_execution_profile));
    setText("parameter-network-policy", humanize(sandbox.network_policy || execution.network_policy || "unknown"));
    setText("parameter-allowed-ips", allowedNetworks.length ? allowedNetworks.join(" · ") : "None recorded");
    setText("parameter-mitigation", humanize(sandbox.mitigation_profile || execution.mitigation_profile || "unknown"));
    setText("parameter-timeout", sandbox.timeout_seconds == null ? "Not recorded" : `${sandbox.timeout_seconds} s`);
    setText("parameter-target-arguments", targetArgumentCount ? `${targetArgumentCount} value${plural(targetArgumentCount)} · redacted` : "None");
    setText("guest-command-line", observedCommand || "No process command line was observed");
    setText("guest-command-source", observedCommand ? `PID ${rootProcess.pid} · process telemetry` : "Unavailable");
    wireCopyButton(document.getElementById("copy-host-command"), commandLine, "host command");
  }

  function reconstructHostCommand(hostReport, target, sandbox) {
    const backendSelection = hostReport.backend_selection || {};
    const backendMetadata = hostReport.backend_metadata || {};
    const tokens = ["foxhole.exe", "--path", target.path || "<target>"];
    tokens.push("--output", "<not retained>");
    tokens.push("--sandbox", sandboxBackendFlag(backendSelection.requested || sandbox.backend));
    if (String(sandbox.backend || "").toLowerCase().includes("hyperv")) {
      tokens.push("--hv-profile", hyperVProfileFlag(sandbox.guest_execution_profile));
      if (Number.isFinite(Number(backendMetadata.cpu_count))) {
        tokens.push("--hyperv-cpu-count", String(backendMetadata.cpu_count));
      }
      if (Number.isFinite(Number(backendMetadata.startup_memory_bytes))) {
        tokens.push("--hyperv-memory-mib", String(Math.round(Number(backendMetadata.startup_memory_bytes) / (1024 * 1024))));
      }
    }
    if (sandbox.timeout_seconds != null) tokens.push("--timeout", String(sandbox.timeout_seconds));
    if (sandbox.network_policy) tokens.push("--network-policy", String(sandbox.network_policy).replace(/_/g, "-"));
    if (sandbox.mitigation_profile) tokens.push("--mitigation-profile", String(sandbox.mitigation_profile).replace(/_/g, "-"));
    const targetArguments = Array.isArray(target.arguments) ? target.arguments : [];
    if (targetArguments.length) tokens.push("--", ...targetArguments.map(() => "<redacted>"));
    return tokens.map(powerShellArgument).join(" ");
  }

  function powerShellArgument(value) {
    const text = String(value);
    return /^[A-Za-z0-9_.:/\\?=-]+$/.test(text) ? text : `'${text.replace(/'/g, "''")}'`;
  }

  function hyperVProfileFlag(profile) {
    const value = String(profile || "restricted").toLowerCase();
    if (value === "normal") return "n";
    if (value === "admin") return "a";
    return "r";
  }

  function sandboxBackendFlag(backend) {
    const value = String(backend || "restricted").toLowerCase();
    if (value === "restricted_process" || value === "restricted-process") return "restricted";
    return value.replace(/_/g, "-");
  }

  function hyperVProfileLabel(profile) {
    const flag = hyperVProfileFlag(profile);
    return `${flag} · ${humanize(profile || "restricted")}`;
  }

  function renderCreatedFileHashes() {
    const unique = new Map();
    (normalized.file_events || []).forEach((event) => {
      if (typeof event.sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(event.sha256)) return;
      const key = `${String(event.path || "").toLowerCase()}\u0000${event.sha256.toLowerCase()}`;
      const previous = unique.get(key);
      if (!previous || (Number(event.size_bytes) || 0) > (Number(previous.size_bytes) || 0)) {
        unique.set(key, event);
      }
    });
    const files = Array.from(unique.values()).sort((left, right) =>
      String(left.path || "").localeCompare(String(right.path || "")) ||
      left.sha256.localeCompare(right.sha256)
    );
    setText("created-file-count", `${files.length} hashed file${plural(files.length)}`);
    const empty = document.getElementById("created-file-empty");
    const wrap = document.getElementById("created-file-table-wrap");
    const body = clear("created-file-table");
    empty.hidden = files.length !== 0;
    wrap.hidden = files.length === 0;
    files.forEach((event) => {
      const row = node("tr");
      appendCell(row, basename(event.path || "<unknown>"));
      appendCell(row, event.path || "—", "cell-evidence");
      appendCell(row, humanize(event.action || "file observation"), "type-label");
      appendCell(row, formatBytes(event.size_bytes));
      const hashCell = node("td", "cell-evidence");
      hashCell.append(node("code", "hash-value", event.sha256));
      row.append(hashCell);
      appendCell(row, humanize(event.hash_source || "guest telemetry"), "cell-source");
      const lookupCell = node("td", "cell-action");
      lookupCell.append(virusTotalLink(event.sha256, "VirusTotal"));
      row.append(lookupCell);
      body.append(row);
    });
  }

  function renderCoverage() {
    const container = clear("coverage-grid");
    Object.entries(normalized.coverage || {}).forEach(([channel, state]) => {
      const item = node("div", "coverage-item");
      let classification = "missing";
      let label = "not collected";
      if (state && state.complete) {
        classification = "complete";
        label = "complete";
      } else if (state && state.collected) {
        classification = "partial";
        label = "partial coverage";
      } else if (state && !state.requested) {
        classification = "missing";
        label = "not requested";
      }
      item.classList.add(classification);
      item.append(node("strong", "", humanize(channel)));
      item.append(node("span", "coverage-state", label));
      container.append(item);
    });
  }

  function renderFindingSummary() {
    const container = clear("finding-list");
    if (!verdict.findings.length) {
      container.append(node("p", "empty-state", "No findings were produced."));
      return;
    }
    verdict.findings.forEach((finding) => {
      const link = node("a", "finding-summary");
      link.href = `findings.html#rule-${safeId(finding.rule_id)}`;
      link.append(node("span", `severity-dot ${finding.severity}`));
      const text = node("span");
      text.append(node("strong", "", finding.title));
      text.append(node("small", "", `${finding.evidence.length} evidence reference${plural(finding.evidence.length)}`));
      link.append(text, node("strong", "", `+${finding.score_contribution}`));
      container.append(link);
    });
  }

  function renderFindings() {
    setText("findings-score", verdict.score);
    setText("findings-confidence", percent(verdict.confidence));
    setText(
      "evidence-count",
      verdict.findings.reduce((total, finding) => total + finding.evidence.length, 0)
    );
    const severityCounts = countBy(verdict.findings, (finding) => finding.severity);
    renderBars("severity-bars", [
      ["Informational", severityCounts.informational || 0, "informational"],
      ["Suspicious", severityCounts.suspicious || 0, "suspicious"],
      ["Malicious", severityCounts.malicious || 0, "malicious"],
    ]);

    const severity = document.getElementById("finding-severity");
    const search = document.getElementById("finding-search");
    const update = () => {
      const query = search.value.trim().toLowerCase();
      const filtered = verdict.findings.filter((finding) => {
        const matchesSeverity = severity.value === "all" || finding.severity === severity.value;
        const haystack = [
          finding.rule_id,
          finding.title,
          finding.explanation,
          ...finding.evidence.flatMap((evidence) => [evidence.process_image, evidence.exact_value, evidence.source_artifact]),
        ]
          .join(" ")
          .toLowerCase();
        return matchesSeverity && (!query || haystack.includes(query));
      });
      setText("finding-result-count", `${filtered.length} finding${plural(filtered.length)}`);
      renderFindingCards(filtered);
    };
    severity.addEventListener("change", update);
    search.addEventListener("input", update);
    update();
  }

  function renderFindingCards(findings) {
    const container = clear("findings-container");
    if (!findings.length) {
      container.append(node("p", "empty-state", "No findings match the current filters."));
      return;
    }
    findings.forEach((finding) => {
      const card = node("article", `finding-card ${finding.severity}`);
      card.id = `rule-${safeId(finding.rule_id)}`;
      const headingRow = node("div", "finding-title-row");
      const heading = node("div");
      heading.append(node("h2", "", finding.title), node("code", "", finding.rule_id));
      headingRow.append(heading, node("span", `severity-badge ${finding.severity}`, finding.severity));
      card.append(headingRow, node("p", "", finding.explanation));

      const meta = node("div", "finding-meta");
      meta.append(node("span", "", `Score contribution +${finding.score_contribution}`));
      const confidence = node("span", "", `Confidence ${percent(finding.confidence)}`);
      const track = node("span", "confidence-track");
      const fill = node("span");
      fill.style.width = `${finding.confidence * 100}%`;
      track.append(fill);
      confidence.append(track);
      meta.append(confidence, node("span", "", `${finding.evidence.length} evidence reference${plural(finding.evidence.length)}`));
      card.append(meta);

      const wrap = node("div", "table-wrap");
      const table = node("table");
      const head = node("thead");
      const headRow = node("tr");
      ["Time", "Process", "Exact evidence", "Association", "Source"].forEach((label) => headRow.append(node("th", "", label)));
      head.append(headRow);
      const body = node("tbody");
      finding.evidence.forEach((evidence) => {
        const row = node("tr");
        appendCell(row, formatTime(evidence.observed_at_ms));
        appendCell(row, `PID ${evidence.pid} · ${basename(evidence.process_image)}`);
        appendEvidenceCell(row, evidence);
        appendCell(row, evidence.inferred ? "Inferred" : "Explicit", `association ${evidence.inferred ? "inferred" : ""}`);
        appendCell(row, evidence.source_artifact, "cell-source");
        body.append(row);
      });
      table.append(head, body);
      wrap.append(table);
      card.append(wrap);
      container.append(card);
    });
  }

  function renderTimeline() {
    const kind = document.getElementById("timeline-kind");
    const pid = document.getElementById("timeline-pid");
    const inferred = document.getElementById("timeline-inferred");
    let filtered = verdict.timeline.slice();

    const update = () => {
      const pidValue = pid.value.trim();
      filtered = verdict.timeline.filter((event) => {
        return (kind.value === "all" || event.kind === kind.value) &&
          (!pidValue || String(event.pid) === pidValue) &&
          (!inferred.checked || event.inferred);
      });
      setText("timeline-result-count", `${filtered.length} event${plural(filtered.length)}`);
      renderTimelineChart("timeline-chart", filtered);
      renderTimelineTable(filtered);
    };
    kind.addEventListener("change", update);
    pid.addEventListener("input", update);
    inferred.addEventListener("change", update);
    update();
  }

  function renderTimelineTable(events) {
    const body = clear("timeline-table");
    if (!events.length) {
      const row = node("tr");
      const cell = node("td", "empty-state", "No timeline events match the current filters.");
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
      return;
    }
    events.forEach((event) => {
      const row = node("tr");
      appendCell(row, formatTime(event.observed_at_ms));
      appendCell(row, humanize(event.kind), "type-label");
      appendCell(row, `PID ${event.pid} · ${basename(event.process_image)}`);
      appendEvidenceCell(row, event);
      appendCell(row, event.inferred ? "Inferred" : "Explicit", `association ${event.inferred ? "inferred" : ""}`);
      appendCell(row, event.source_artifact, "cell-source");
      body.append(row);
    });
  }

  function appendEvidenceCell(row, evidence) {
    const registry = ["registry", "registry_event"].includes(evidence.kind)
      ? (normalized.registry_events || []).find((event) => event.evidence_id === evidence.evidence_id)
      : null;
    if (!registry) return appendCell(row, evidence.exact_value, "cell-evidence");

    const details = registryOperationDetails(registry.operation);
    const cell = node("td", "cell-evidence structured-evidence");
    cell.append(node("span", `operation-badge ${details.tone}`, details.label));
    cell.append(node("code", "evidence-key", registry.key));
    if (registry.value_name) {
      cell.append(node("span", "evidence-detail", `Value name: ${registry.value_name}`));
    }
    if (registry.value_data) {
      cell.append(node("span", "evidence-detail", `Captured data: ${registry.value_data}`));
    }
    if (details.note) cell.append(node("span", "evidence-note", details.note));
    row.append(cell);
    return cell;
  }

  function registryOperationDetails(operation) {
    const name = String(operation || "unknown").split(" data=")[0].toLowerCase();
    if (name === "create_key") return { label: "Key created", tone: "created", note: "" };
    if (name === "delete_key") return { label: "Key deleted", tone: "deleted", note: "" };
    if (name === "set_value") return { label: "Value set", tone: "updated", note: "" };
    if (name === "rename") return { label: "Key renamed", tone: "updated", note: "" };
    if (name === "create_or_delete") {
      return {
        label: "Create or delete",
        tone: "ambiguous",
        note: "Legacy Sysmon Event 12 data did not retain whether this key was created or deleted. Future runs preserve that distinction when EventType is available.",
      };
    }
    return { label: humanize(name), tone: "ambiguous", note: "" };
  }

  function renderProcesses() {
    const processes = normalized.processes;
    const observationCount = processes.reduce((total, process) => total + process.observations.length, 0);
    setText("process-count", processes.length);
    setText("observation-count", observationCount);
    setText("root-pid", normalized.execution.pid || "—");
    renderProcessTree("process-tree", processes, normalized.execution.pid);
    renderBars(
      "process-bars",
      processes
        .slice()
        .sort((left, right) => right.observations.length - left.observations.length || left.pid - right.pid)
        .map((process) => [
          `${process.pid} · ${basename(process.image)}`,
          process.observations.length,
          "process",
          {
            copyValue: basename(process.image),
            title: `PID ${process.pid} · ${basename(process.image)}\nFull path: ${process.image}`,
          },
        ])
    );
    const body = clear("process-table");
    processes
      .slice()
      .sort((left, right) => left.observed_at_ms - right.observed_at_ms || left.pid - right.pid)
      .forEach((process) => {
        const row = node("tr");
        appendCell(row, process.pid);
        appendCell(row, process.parent_pid == null ? "—" : process.parent_pid);
        appendCell(row, process.image, "cell-evidence");
        appendCell(row, process.command_line || "—", "cell-evidence");
        appendCell(row, humanize(process.status));
        appendCell(row, formatTime(process.observed_at_ms));
        appendCell(row, process.observations.length);
        body.append(row);
      });
  }

  function renderNetwork() {
    const events = Array.isArray(normalized.network_events) ? normalized.network_events : [];
    const remoteEndpoints = new Set(
      events
        .map((event) => networkRemoteEndpoint(event))
        .filter((endpoint) => endpoint !== "—")
    );
    const domains = new Set(events.map((event) => event.domain).filter(Boolean));
    const inferredCount = events.filter((event) => event.association && event.association.inferred).length;
    setText("network-count", events.length);
    setText("remote-endpoint-count", remoteEndpoints.size);
    setText("network-domain-count", domains.size);
    setText("network-inferred-count", inferredCount);

    const protocolCounts = countBy(events, (event) => event.protocol || "unknown");
    const stateCounts = countBy(events, (event) => event.state || "unknown");
    renderBars(
      "network-protocol-bars",
      sortedCounts(protocolCounts).map(([label, value]) => [humanize(label), value, "network"])
    );
    renderBars(
      "network-state-bars",
      sortedCounts(stateCounts).map(([label, value]) => [humanize(label), value, "network"])
    );

    const protocol = document.getElementById("network-protocol");
    const direction = document.getElementById("network-direction");
    uniqueValues(events, (event) => event.protocol || "unknown").forEach((value) => {
      const option = node("option", "", humanize(value));
      option.value = value;
      protocol.append(option);
    });
    uniqueValues(events, (event) => event.direction || "unknown").forEach((value) => {
      const option = node("option", "", humanize(value));
      option.value = value;
      direction.append(option);
    });

    const search = document.getElementById("network-search");
    const inferred = document.getElementById("network-inferred");
    const update = () => {
      const query = search.value.trim().toLowerCase();
      const filtered = events
        .filter((event) => {
          const association = event.association || {};
          const haystack = [
            event.protocol,
            event.direction,
            event.local_address,
            event.local_port,
            event.remote_address,
            event.remote_port,
            event.domain,
            event.state,
            association.image,
            event.source,
          ].join(" ").toLowerCase();
          return (protocol.value === "all" || (event.protocol || "unknown") === protocol.value) &&
            (direction.value === "all" || (event.direction || "unknown") === direction.value) &&
            (!inferred.checked || association.inferred) &&
            (!query || haystack.includes(query));
        })
        .sort((left, right) => left.observed_at_ms - right.observed_at_ms || left.evidence_id.localeCompare(right.evidence_id));
      setText("network-result-count", `${filtered.length} event${plural(filtered.length)}`);
      renderNetworkTable(filtered);
    };
    protocol.addEventListener("change", update);
    direction.addEventListener("change", update);
    search.addEventListener("input", update);
    inferred.addEventListener("change", update);
    update();
  }

  function renderNetworkTable(events) {
    const body = clear("network-table");
    const annotatedEndpoints = new Set();
    if (!events.length) {
      const row = node("tr");
      const cell = node("td", "empty-state", "No network events match the current filters.");
      cell.colSpan = 9;
      row.append(cell);
      body.append(row);
      return;
    }
    events.forEach((event) => {
      const association = event.association || {};
      const row = node("tr");
      appendCell(row, formatTime(event.observed_at_ms));
      appendCell(row, humanize(event.protocol || "unknown"), "type-label");
      appendCell(row, humanize(event.direction || "unknown"), "type-label");
      appendCell(row, `PID ${event.pid} · ${basename(association.image || "unknown")}`);
      appendCell(row, networkEndpoint(event.local_address, event.local_port), "cell-endpoint");
      const remoteCell = node("td", "cell-endpoint");
      remoteCell.append(node("span", "", networkRemoteEndpoint(event)));
      const endpointKey = endpointForNetworkEvent(event);
      const downloads = annotatedEndpoints.has(endpointKey) ? [] : downloadsForEndpoint(endpointKey);
      downloads.forEach((download) => remoteCell.append(downloadNote(download, "endpoint-download table-download")));
      if (downloads.length) annotatedEndpoints.add(endpointKey);
      row.append(remoteCell);
      appendCell(row, humanize(event.state || "unknown"));
      appendCell(row, association.inferred ? "Inferred" : "Explicit", `association ${association.inferred ? "inferred" : ""}`);
      appendCell(row, event.source || "—", "cell-source");
      body.append(row);
    });
  }

  function networkRemoteEndpoint(event) {
    const endpoint = networkEndpoint(event.remote_address, event.remote_port);
    if (!event.domain) return endpoint;
    return endpoint === "—" ? event.domain : `${event.domain} · ${endpoint}`;
  }

  function networkEndpoint(address, port) {
    const host = String(address || "").trim();
    const parsedPort = Number(port);
    const hasPort = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535;
    if (!host) return hasPort ? `:${parsedPort}` : "—";
    if (!hasPort) return host;
    return host.includes(":") && !host.startsWith("[") ? `[${host}]:${parsedPort}` : `${host}:${parsedPort}`;
  }

  function correlateDownloads() {
    const grouped = new Map();
    const networkEvents = (normalized.network_events || [])
      .filter((event) => /connect/i.test(event.state || "") && endpointForNetworkEvent(event) !== "—")
      .sort((left, right) => left.observed_at_ms - right.observed_at_ms);
    const observedEndpoints = new Set(networkEvents.map(endpointForNetworkEvent));

    const add = (endpoint, download) => {
      const key = normalizeEndpointValue(endpoint);
      if (!key || key === "—") return;
      if (!grouped.has(key)) grouped.set(key, []);
      const existing = grouped.get(key);
      if (existing.some((value) =>
        (download.sha256 && value.sha256 === download.sha256) ||
        value.fileName.toLowerCase() === download.fileName.toLowerCase()
      )) return;
      existing.push(download);
    };

    const execution = normalized.execution || {};
    const rootProcess = (normalized.processes || []).find((process) => process.pid === Number(execution.pid));
    const commandLine = String((rootProcess && rootProcess.command_line) || "");
    const commandEndpoints = [...new Set(
      (commandLine.match(/https?:\/\/[^\s"'<>]+/gi) || [])
        .map(endpointForUrl)
        .filter((endpoint) => observedEndpoints.has(endpoint))
    )];
    const reportedDownloads = String(execution.stdout || "")
      .split(/\r?\n/)
      .map((line) => line.match(/\bDownloaded\s+(\d+)\s+bytes\s+to\s+(.+?)\s*$/i))
      .filter(Boolean);

    if (commandEndpoints.length === 1) {
      reportedDownloads.forEach((match) => {
        const path = match[2].replace(/^"|"$/g, "");
        const fileName = basename(path).replace(/\.part$/i, "");
        const matchingFile = (normalized.file_events || []).find((event) =>
          basename(event.path || "").replace(/\.part$/i, "").toLowerCase() === fileName.toLowerCase() && isSha256(event.sha256)
        );
        add(commandEndpoints[0], {
          fileName,
          path,
          sizeBytes: Number(match[1]),
          sha256: matchingFile && matchingFile.sha256,
          basis: "Program-reported download corroborated by the observed command line and network endpoint.",
        });
      });
    }

    networkEvents.forEach((networkEvent) => {
      const endpoint = endpointForNetworkEvent(networkEvent);
      (normalized.file_events || [])
        .filter((fileEvent) => {
          const delta = fileEvent.observed_at_ms - networkEvent.observed_at_ms;
          return isSha256(fileEvent.sha256) && delta >= 0 && delta <= 2000;
        })
        .sort((left, right) => left.observed_at_ms - right.observed_at_ms)
        .forEach((fileEvent) => {
          const delta = fileEvent.observed_at_ms - networkEvent.observed_at_ms;
          add(endpoint, {
            fileName: basename(fileEvent.path || "").replace(/\.part$/i, ""),
            path: fileEvent.path,
            sizeBytes: fileEvent.size_bytes,
            sha256: fileEvent.sha256,
            basis: `Timing correlation: the hashed file appeared ${formatTime(delta)} after this network event. The file-to-process association is ${fileEvent.association && fileEvent.association.inferred ? "inferred" : "explicit"}.`,
          });
        });
    });
    return grouped;
  }

  function endpointForNetworkEvent(event) {
    const address = String(event.remote_address || "").replace(/\s+\([^)]*\)\s*$/, "").trim();
    return normalizeEndpointValue(networkEndpoint(address, event.remote_port));
  }

  function endpointForUrl(value) {
    try {
      const parsed = new URL(value);
      const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
      return normalizeEndpointValue(networkEndpoint(parsed.hostname, Number(port)));
    } catch (_) {
      return "";
    }
  }

  function normalizeEndpointValue(value) {
    return String(value || "").trim().toLowerCase();
  }

  function downloadsForEndpoint(endpoint) {
    return downloadsByEndpoint.get(normalizeEndpointValue(endpoint)) || [];
  }

  function downloadNote(download, className) {
    const note = node("span", className);
    note.title = `${download.basis}\n${download.path}`;
    note.append(
      node("span", "download-label", "> DOWNLOADED"),
      node("code", "", download.fileName)
    );
    if (Number.isFinite(Number(download.sizeBytes)) && Number(download.sizeBytes) > 0) {
      note.append(node("span", "download-size", formatBytes(download.sizeBytes)));
    }
    return note;
  }

  function renderIocs() {
    const contextualCount = iocs.indicators.filter((indicator) => indicator.contextual).length;
    const sourceCount = iocs.indicators.reduce((total, indicator) => total + indicator.sources.length, 0);
    setText("iocs-total", iocs.indicators.length);
    setText("iocs-contextual", contextualCount);
    setText("ioc-source-count", sourceCount);
    renderBars(
      "ioc-type-bars",
      Object.entries(iocs.counts_by_type)
        .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .map(([label, value]) => [humanize(label), value, ""])
    );

    const type = document.getElementById("ioc-type");
    Object.keys(iocs.counts_by_type).sort().forEach((value) => {
      const option = node("option", "", humanize(value));
      option.value = value;
      type.append(option);
    });
    const search = document.getElementById("ioc-search");
    const fileType = document.getElementById("ioc-file-type");
    const eventType = document.getElementById("ioc-event-type");
    const scope = document.getElementById("ioc-scope");
    uniqueValues(iocs.indicators.flatMap(indicatorFileTypes), (value) => value).forEach((value) => {
      const option = node("option", "", value);
      option.value = value;
      fileType.append(option);
    });
    uniqueValues(
      iocs.indicators.flatMap((indicator) => indicator.sources.map((source) => source.kind)),
      (value) => value
    ).forEach((value) => {
      const option = node("option", "", humanize(value));
      option.value = value;
      eventType.append(option);
    });
    const update = () => {
      const query = search.value.trim().toLowerCase();
      const filtered = iocs.indicators.filter((indicator) => {
        const sources = indicator.sources.map((source) => `${source.kind} ${source.artifact}`).join(" ");
        const fileTypes = indicatorFileTypes(indicator);
        const matchesScope = scope.value === "all" ||
          (scope.value === "contextual" && indicator.contextual) ||
          (scope.value === "observable" && !indicator.contextual);
        return (type.value === "all" || indicator.type === type.value) &&
          (fileType.value === "all" || fileTypes.includes(fileType.value)) &&
          (eventType.value === "all" || indicator.sources.some((source) => source.kind === eventType.value)) &&
          matchesScope &&
          (!query || `${indicator.value} ${indicator.type} ${fileTypes.join(" ")} ${sources}`.toLowerCase().includes(query));
      });
      setText("ioc-result-count", `${filtered.length} indicator${plural(filtered.length)}`);
      renderIocGroups(filtered);
    };
    type.addEventListener("change", update);
    search.addEventListener("input", update);
    fileType.addEventListener("change", update);
    eventType.addEventListener("change", update);
    scope.addEventListener("change", update);
    update();

    const warningPanel = document.getElementById("ioc-warning-panel");
    const warningList = clear("ioc-warnings");
    if (!iocs.extraction_warnings.length) {
      warningPanel.hidden = true;
    } else {
      iocs.extraction_warnings.forEach((warning) => {
        warningList.append(node("li", "", `${warning.code}: ${warning.message}`));
      });
    }
  }

  function renderIocGroups(indicators) {
    const container = clear("ioc-groups");
    if (!indicators.length) {
      container.append(node("p", "empty-state", "No indicators match the current filters."));
      return;
    }

    const grouped = new Map();
    indicators.forEach((indicator) => {
      if (!grouped.has(indicator.type)) grouped.set(indicator.type, []);
      grouped.get(indicator.type).push(indicator);
    });

    [...grouped.entries()]
      .sort((left, right) => left[0].localeCompare(right[0]))
      .forEach(([type, values], index) => {
        const section = node("section", "panel ioc-group");
        const heading = node("div", "panel-heading ioc-group-heading");
        const headingCopy = node("div");
        headingCopy.append(
          node("p", "section-kicker", `Group ${String(index + 1).padStart(2, "0")}`),
          node("h3", "", humanize(type))
        );
        heading.append(headingCopy, node("strong", "group-count", `${values.length} value${plural(values.length)}`));

        const layout = node("div", "ioc-group-layout");
        const chartBlock = node("div", "ioc-value-chart");
        chartBlock.append(node("p", "chart-caption", "Source references per value"));
        const chart = node("div", "bar-chart ioc-value-bars");
        renderBars(
          chart,
          values
            .slice()
            .sort((left, right) => right.sources.length - left.sources.length || left.value.localeCompare(right.value))
            .map((indicator) => [
              indicator.value,
              indicator.sources.length,
              iocTone(type),
              {
                copyValue: indicator.value,
                title: indicator.value,
                notes: type === "network_endpoint" ? downloadsForEndpoint(indicator.value) : [],
              },
            ])
        );
        chartBlock.append(chart);

        const tableWrap = node("div", "table-wrap");
        const table = node("table", "ioc-detail-table");
        const tableHead = node("thead");
        const headRow = node("tr");
        ["Value", "First", "Last", "Classification", "Events / sources"].forEach((label) => {
          headRow.append(node("th", "", label));
        });
        tableHead.append(headRow);
        const tableBody = node("tbody");
        renderIocRows(tableBody, values);
        table.append(tableHead, tableBody);
        tableWrap.append(table);
        layout.append(chartBlock, tableWrap);
        section.append(heading, layout);
        container.append(section);
      });
  }

  function renderIocRows(body, indicators) {
    indicators.forEach((indicator) => {
      const row = node("tr");
      const value = node("td", "cell-evidence");
      value.append(node("code", "", indicator.value));
      if (indicator.type === "sha256" && isSha256(indicator.value)) {
        value.append(virusTotalLink(indicator.value, "VirusTotal"));
      }
      if (indicator.type === "network_endpoint") {
        downloadsForEndpoint(indicator.value).forEach((download) => {
          value.append(downloadNote(download, "endpoint-download table-download"));
        });
      }
      row.append(value);
      appendCell(row, formatTime(indicator.first_seen_ms));
      appendCell(row, formatTime(indicator.last_seen_ms));
      appendCell(
        row,
        indicator.contextual ? "Contextual / likely benign" : "Observable",
        `context-label ${indicator.contextual ? "" : "observable"}`
      );
      appendCell(
        row,
        indicator.sources.map((source) => `${humanize(source.kind)} · ${source.artifact}`).join("\n"),
        "cell-source"
      );
      body.append(row);
    });
  }

  function indicatorFileTypes(indicator) {
    if (!["file_path", "command_line", "process_image"].includes(indicator.type)) return [];
    const withoutUrls = String(indicator.value).replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, " ");
    const matches = withoutUrls.match(/\.[a-z0-9]{1,12}(?=$|[\s"'?,;:)\\])/gi) || [];
    return [...new Set(matches.map((value) => value.toLowerCase()))].sort();
  }

  function iocTone(type) {
    if (type === "command_line" || type === "process_image") return "process";
    if (type === "file_path" || type === "sha256") return "file";
    if (type === "registry_key") return "registry";
    if (["domain", "ipv4", "ipv6", "network_endpoint", "url"].includes(type)) return "network";
    return "";
  }

  function renderBars(containerId, entries) {
    const container = clear(containerId);
    const maximum = Math.max(1, ...entries.map((entry) => Number(entry[1]) || 0));
    entries.forEach(([label, rawValue, tone, interaction]) => {
      const value = Number(rawValue) || 0;
      const row = node("div", "bar-row");
      const labelNode = node("span", "bar-label", label);
      if (interaction && interaction.copyValue != null) {
        makeCopyableLabel(labelNode, interaction.copyValue, interaction.title || label);
        row.classList.add("copyable-row");
      }
      row.append(labelNode);
      if (interaction && interaction.copyValue != null) {
        row.append(node("span", "copy-hint", "COPY"));
      }
      if (interaction && Array.isArray(interaction.notes)) {
        interaction.notes.forEach((download) => row.append(downloadNote(download, "endpoint-download bar-note")));
      }
      const track = node("div", "bar-track");
      const fill = node("div", `bar-fill ${tone || ""}`);
      fill.style.width = `${(value / maximum) * 100}%`;
      track.append(fill);
      row.append(track, node("strong", "bar-value", value));
      container.append(row);
    });
  }

  function renderActivityChart(containerId, events) {
    responsiveSvg(containerId, (container, width) => {
      if (!events.length) {
        container.append(node("p", "empty-state", "No event activity was recorded."));
        return;
      }
      const height = 190;
      const margin = { left: 92, right: 18, top: 18, bottom: 32 };
      const times = events.map((event) => event.observed_at_ms);
      const min = Math.min(...times);
      const max = Math.max(...times);
      const bins = Math.max(10, Math.min(28, Math.floor(width / 38)));
      const counts = Array.from({ length: bins }, () => 0);
      events.forEach((event) => {
        const ratio = max === min ? 0 : (event.observed_at_ms - min) / (max - min);
        counts[Math.min(bins - 1, Math.floor(ratio * bins))] += 1;
      });
      const maximum = Math.max(...counts, 1);
      const x = (index) => margin.left + (index / (bins - 1)) * (width - margin.left - margin.right);
      const y = (value) => height - margin.bottom - (value / maximum) * (height - margin.top - margin.bottom);
      const svg = svgRoot(width, height, "Event density over elapsed milliseconds");
      svg.append(svgElement("rect", { x: margin.left, y: margin.top, width: width - margin.left - margin.right, height: height - margin.top - margin.bottom, class: "chart-frame" }));
      const points = counts.map((value, index) => [x(index), y(value)]);
      const area = [`M ${points[0][0]} ${height - margin.bottom}`, ...points.map(([px, py]) => `L ${px} ${py}`), `L ${points[points.length - 1][0]} ${height - margin.bottom}`, "Z"].join(" ");
      svg.append(svgElement("path", { d: area, class: "activity-area" }));
      svg.append(svgElement("path", { d: points.map(([px, py], index) => `${index ? "L" : "M"} ${px} ${py}`).join(" "), class: "activity-line" }));
      addAxisLabel(svg, margin.left, height - 10, `${formatTime(min)} start`, "start");
      addAxisLabel(svg, width - margin.right, height - 10, `${formatTime(max)} end`, "end");
      addAxisLabel(svg, margin.left - 8, margin.top + 5, `${maximum} events/bin`, "end");
      container.append(svg);
    });
  }

  function renderTimelineChart(containerId, events) {
    responsiveSvg(containerId, (container, width) => {
      if (!events.length) {
        container.append(node("p", "empty-state", "No events match the current filters."));
        return;
      }
      const lanes = ["process", "file", "registry", "network"];
      const height = 330;
      const margin = { left: 90, right: 24, top: 24, bottom: 46 };
      const times = events.map((event) => event.observed_at_ms);
      const min = Math.min(...times);
      const max = Math.max(...times);
      const x = (value) => margin.left + ((value - min) / Math.max(1, max - min)) * (width - margin.left - margin.right);
      const laneHeight = (height - margin.top - margin.bottom) / lanes.length;
      const y = (kind) => margin.top + (lanes.indexOf(kind) + 0.5) * laneHeight;
      const svg = svgRoot(width, height, "Filtered process, file, registry, and network events on a shared elapsed-time axis");
      svg.append(svgElement("rect", { x: margin.left, y: margin.top, width: width - margin.left - margin.right, height: height - margin.top - margin.bottom, class: "chart-frame" }));

      lanes.forEach((lane) => {
        const laneY = y(lane);
        svg.append(svgElement("line", { x1: margin.left, y1: laneY, x2: width - margin.right, y2: laneY, class: "grid-line" }));
        const label = svgElement("text", { x: margin.left - 12, y: laneY + 4, "text-anchor": "end", class: "lane-label" });
        label.textContent = humanize(lane);
        svg.append(label);
      });
      for (let tick = 0; tick <= 4; tick += 1) {
        const value = min + ((max - min) * tick) / 4;
        const tickX = x(value);
        svg.append(svgElement("line", { x1: tickX, y1: margin.top, x2: tickX, y2: height - margin.bottom, class: "grid-line" }));
        addAxisLabel(svg, tickX, height - 18, formatTime(Math.round(value)), tick === 0 ? "start" : tick === 4 ? "end" : "middle");
      }
      const collision = new Map();
      events.forEach((event) => {
        const key = `${event.kind}:${event.observed_at_ms}`;
        const offset = collision.get(key) || 0;
        collision.set(key, offset + 1);
        const jitter = ((offset % 5) - 2) * 3;
        const mark = svgElement("circle", {
          cx: x(event.observed_at_ms),
          cy: y(event.kind) + jitter,
          r: 5,
          class: `mark ${event.kind} ${event.inferred ? "inferred" : ""}`,
        });
        const title = svgElement("title");
        title.textContent = `${formatTime(event.observed_at_ms)} · PID ${event.pid} · ${event.exact_value}`;
        mark.append(title);
        svg.append(mark);
      });
      container.append(svg);
    });
  }

  function renderProcessTree(containerId, processes, rootPid) {
    responsiveSvg(containerId, (container, width) => {
      if (!processes.length) {
        container.append(node("p", "empty-state", "No process records were normalized."));
        return;
      }
      const byPid = new Map(processes.map((process) => [process.pid, process]));
      const childrenByParent = new Map();
      processes.forEach((process) => {
        if (!byPid.has(process.parent_pid)) return;
        if (!childrenByParent.has(process.parent_pid)) childrenByParent.set(process.parent_pid, []);
        childrenByParent.get(process.parent_pid).push(process);
      });
      const branchColors = new Map(
        processes
          .filter((process) => process.pid !== rootPid && childrenByParent.has(process.pid))
          .sort((left, right) => left.pid - right.pid)
          .map((process, index) => [process.pid, branchColor(index)])
      );
      const branchOwner = (process) => {
        if (!process || process.pid === rootPid) return null;
        if (branchColors.has(process.pid)) return process.pid;
        const parent = byPid.get(process.parent_pid);
        return parent && branchColors.has(parent.pid) ? parent.pid : null;
      };
      const depthMemo = new Map();
      const depth = (process, trail = new Set()) => {
        if (depthMemo.has(process.pid)) return depthMemo.get(process.pid);
        if (trail.has(process.pid) || !byPid.has(process.parent_pid)) return 0;
        const nextTrail = new Set(trail);
        nextTrail.add(process.pid);
        const value = 1 + depth(byPid.get(process.parent_pid), nextTrail);
        depthMemo.set(process.pid, value);
        return value;
      };
      const ordered = processes.slice().sort((left, right) => depth(left) - depth(right) || left.observed_at_ms - right.observed_at_ms || left.pid - right.pid);
      const maximumDepth = Math.max(...ordered.map((process) => depth(process)), 1);
      const height = Math.max(300, ordered.length * 52 + 30);
      const left = 92;
      const right = 100;
      const x = (process) => left + (depth(process) / maximumDepth) * Math.max(180, width - left - right);
      const positions = new Map(ordered.map((process, index) => [process.pid, { x: x(process), y: 34 + index * 52 }]));
      const svg = svgRoot(width, height, "Parent-child relationships between normalized process records");
      ordered.forEach((process) => {
        const child = positions.get(process.pid);
        const parent = positions.get(process.parent_pid);
        if (parent) {
          const owner = branchOwner(process);
          const attributes = {
            d: `M ${parent.x + 68} ${parent.y} C ${parent.x + 100} ${parent.y}, ${child.x - 100} ${child.y}, ${child.x - 68} ${child.y}`,
            class: `tree-edge ${owner == null ? "" : "branch"}`,
            fill: "none",
          };
          if (owner != null) attributes.style = `--branch-color: ${branchColors.get(owner)}`;
          const edge = svgElement("path", attributes);
          const title = svgElement("title");
          title.textContent = owner == null
            ? `PID ${process.parent_pid} to PID ${process.pid} · leaf-only branch`
            : `PID ${process.parent_pid} to PID ${process.pid} · branch color owned by PID ${owner}`;
          edge.append(title);
          svg.append(edge);
        }
      });
      ordered.forEach((process) => {
        const position = positions.get(process.pid);
        const owner = branchOwner(process);
        const group = svgElement("g");
        const nodeAttributes = { x: position.x - 70, y: position.y - 18, width: 140, height: 36, rx: 2, class: `tree-node ${process.pid === rootPid ? "root" : ""} ${owner == null ? "" : "branch-node"}` };
        if (owner != null) nodeAttributes.style = `--branch-color: ${branchColors.get(owner)}`;
        group.append(svgElement("rect", nodeAttributes));
        const pidLabel = svgElement("text", { x: position.x - 60, y: position.y - 2, class: "node-pid" });
        pidLabel.textContent = `PID ${process.pid}`;
        const imageLabel = svgElement("text", { x: position.x - 60, y: position.y + 12, class: "node-label" });
        imageLabel.textContent = truncate(basename(process.image), 19);
        const title = svgElement("title");
        title.textContent = `${process.image}${process.command_line ? ` · ${process.command_line}` : ""}`;
        group.append(pidLabel, imageLabel, title);
        svg.append(group);
      });
      container.append(svg);
    });
  }

  function branchColor(index) {
    const hue = (18 + index * 137.508) % 360;
    return `hsl(${hue.toFixed(1)} 74% 64%)`;
  }

  function responsiveSvg(containerId, draw) {
    const container = document.getElementById(containerId);
    let scheduled = false;
    const render = () => {
      if (scheduled) return;
      scheduled = true;
      requestAnimationFrame(() => {
        scheduled = false;
        clear(containerId);
        draw(container, Math.max(320, Math.floor(container.clientWidth || 800)));
      });
    };
    render();
    if (window.ResizeObserver) new ResizeObserver(render).observe(container);
  }

  function svgRoot(width, height, description) {
    const svg = svgElement("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": description });
    const title = svgElement("title");
    title.textContent = description;
    svg.append(title);
    return svg;
  }

  function addAxisLabel(svg, x, y, value, anchor) {
    const label = svgElement("text", { x, y, "text-anchor": anchor, class: "axis-label" });
    label.textContent = value;
    svg.append(label);
  }

  function svgElement(tag, attributes = {}) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
    return element;
  }

  function node(tag, className = "", text = null) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null && text !== undefined) element.textContent = String(text);
    return element;
  }

  function appendCell(row, value, className = "") {
    const cell = node("td", className, value);
    row.append(cell);
    return cell;
  }

  function makeCopyableLabel(element, value, title) {
    const copyValue = String(value);
    const defaultLabel = `${element.textContent}. Click to copy the full value.`;
    let resetTimer;
    element.classList.add("copyable-label");
    element.tabIndex = 0;
    element.setAttribute("role", "button");
    element.setAttribute("aria-label", defaultLabel);
    element.title = `${title}\nClick to copy the full value`;

    const copy = async () => {
      const copied = await copyText(copyValue);
      const row = element.closest(".bar-row");
      const hint = row && row.querySelector(".copy-hint");
      window.clearTimeout(resetTimer);
      if (row) row.dataset.copyState = copied ? "copied" : "failed";
      if (hint) hint.textContent = copied ? "COPIED" : "FAILED";
      element.setAttribute("aria-label", copied ? `${element.textContent}. Copied.` : `${element.textContent}. Copy failed.`);
      announceCopy(copied ? `Copied ${copyValue}` : `Could not copy ${copyValue}`);
      resetTimer = window.setTimeout(() => {
        if (row) delete row.dataset.copyState;
        if (hint) hint.textContent = "COPY";
        element.setAttribute("aria-label", defaultLabel);
      }, 1600);
    };

    element.addEventListener("click", copy);
    element.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      copy();
    });
  }

  function wireCopyButton(button, value, label) {
    if (!button) return;
    const original = button.textContent;
    let resetTimer;
    button.addEventListener("click", async () => {
      const copied = await copyText(value);
      window.clearTimeout(resetTimer);
      button.textContent = copied ? "Copied" : "Copy failed";
      button.dataset.state = copied ? "copied" : "failed";
      announceCopy(copied ? `Copied ${label}` : `Could not copy ${label}`);
      resetTimer = window.setTimeout(() => {
        button.textContent = original;
        delete button.dataset.state;
      }, 1600);
    });
  }

  async function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(value);
        return true;
      } catch (_) {
        // Fall back to the selection-based copy path for offline file reports.
      }
    }
    const input = node("textarea", "copy-buffer");
    input.value = value;
    input.setAttribute("readonly", "");
    document.body.append(input);
    input.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_) {
      copied = false;
    }
    input.remove();
    return copied;
  }

  function announceCopy(message) {
    let status = document.getElementById("copy-status");
    if (!status) {
      status = node("span", "sr-only");
      status.id = "copy-status";
      status.setAttribute("role", "status");
      status.setAttribute("aria-live", "polite");
      document.body.append(status);
    }
    status.textContent = "";
    window.requestAnimationFrame(() => { status.textContent = message; });
  }

  function isSha256(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
  }

  function virusTotalUrl(sha256) {
    return `https://www.virustotal.com/gui/search?query=${encodeURIComponent(sha256)}`;
  }

  function virusTotalLink(sha256, label) {
    const link = node("a", "external-link", label);
    link.href = virusTotalUrl(sha256);
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.setAttribute("aria-label", `${label}: look up ${sha256} (opens in a new tab)`);
    link.append(node("span", "external-arrow", "↗"));
    return link;
  }

  function clear(id) {
    const element = typeof id === "string" ? document.getElementById(id) : id;
    while (element.firstChild) element.removeChild(element.firstChild);
    return element;
  }

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = String(value);
  }

  function countBy(values, selector) {
    return values.reduce((counts, value) => {
      const key = selector(value);
      counts[key] = (counts[key] || 0) + 1;
      return counts;
    }, {});
  }

  function sortedCounts(counts) {
    return Object.entries(counts).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  }

  function uniqueValues(values, selector) {
    return [...new Set(values.map(selector))].sort((left, right) => left.localeCompare(right));
  }

  function formatTime(milliseconds) {
    const value = Number(milliseconds) || 0;
    if (value < 1000) return `${value} ms`;
    return `${(value / 1000).toFixed(value % 1000 === 0 ? 0 : 3)} s`;
  }

  function percent(value) {
    return `${Math.round(Number(value) * 100)}%`;
  }

  function formatBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "—";
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KiB", "MiB", "GiB", "TiB"];
    let amount = bytes;
    let unit = -1;
    do {
      amount /= 1024;
      unit += 1;
    } while (amount >= 1024 && unit < units.length - 1);
    return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function humanize(value) {
    return String(value).replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
  }

  function basename(value) {
    const parts = String(value).replaceAll("/", "\\").split("\\");
    return parts[parts.length - 1] || value;
  }

  function safeId(value) {
    return String(value).toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  }

  function truncate(value, length) {
    return value.length > length ? `${value.slice(0, length - 1)}…` : value;
  }

  function plural(value) {
    return Number(value) === 1 ? "" : "s";
  }
})();
