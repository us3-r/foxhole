"use strict";

(() => {
  const run = (window.FOXHOLE_REPORT || {}).normalized;
  const container = document.getElementById("capture-health");
  if (!run || !container) return;
  const element = (tag, text, className = "") => {
    const node = document.createElement(tag);
    node.textContent = String(text ?? "").slice(0, 8192);
    if (className) node.className = className;
    return node;
  };
  const counter = value => value === null || value === undefined ? "unknown" : String(value);
  const flag = value => value === true ? "yes" : value === false ? "no" : "unknown";
  const list = value => Array.isArray(value) ? value : [];
  const limitation = "Network telemetry is never complete. Encrypted traffic content, events lost before instrumentation, capture byte/event bounds, and guest-admin tampering can prevent complete observation. Unknown loss counters do not mean zero loss.";
  container.append(element("p", limitation, "capture-limitation"));
  const health = list(run.capture_health);
  if (!health.length) container.append(element("p", "Capture-health metadata unavailable for this report. Network coverage cannot be confirmed.", "empty-state"));
  if (health.length) {
    for (const name of ["guest_wfp", "guest_pktmon", "host_ndis"]) {
      if (!health.some(channel => channel.channel === name)) container.append(element("p", `${name}: capture-health metadata unavailable; channel coverage cannot be confirmed.`, "empty-state"));
    }
  }
  health.forEach(channel => {
    const card = element("section", "", "capture-card");
    const status = !channel.requested ? "not requested" : !channel.started ? "unavailable" : !channel.stopped ? "stop unconfirmed" : "bounded capture stopped";
    card.append(element("h3", `${channel.channel} · ${status}`));
    const table = element("dl", "", "capture-metrics");
    const metrics = [
      ["Requested / started / stopped", [channel.requested, channel.started, channel.stopped].map(flag).join(" / ")],
      ["Byte / event / raw-event limits", [channel.byte_limit, channel.event_limit, channel.raw_event_limit].map(counter).join(" / ")],
      ["Captured bytes / packets", [channel.captured_bytes, channel.captured_packets].map(counter).join(" / ")],
      ["Captured / retained events", [channel.captured_events, channel.retained_events].map(counter).join(" / ")],
      ["Truncated / loss detected", [channel.truncated, channel.loss_detected].map(flag).join(" / ")],
      ["Dropped events / packets", [channel.dropped_events, channel.dropped_packets].map(counter).join(" / ")],
    ];
    metrics.forEach(([name, value]) => table.append(element("dt", name), element("dd", value)));
    card.append(table);
    const warnings = new Set([...list(channel.warnings), ...list(channel.provider_errors).map(error => `Provider error: ${error}`)]);
    if (channel.requested && !channel.started) warnings.add("Capture unavailable: instrumentation start was not confirmed.");
    if (channel.started && !channel.stopped) warnings.add("Capture incomplete: stop was not confirmed.");
    if (channel.truncated) warnings.add("Capture truncated at configured bounds; earlier or excess activity may be absent.");
    if (channel.loss_detected || channel.dropped_events > 0 || channel.dropped_packets > 0) warnings.add("Capture reports lost events or packets.");
    const warningList = element("ul", "", "capture-warnings");
    warnings.forEach(warning => warningList.append(element("li", warning)));
    card.append(warningList);
    const artifacts = element("div", "", "capture-artifacts");
    artifacts.append(element("strong", "Artifacts"));
    list(channel.artifacts).forEach(path => artifacts.append(element("code", path)));
    if (!list(channel.artifacts).length) artifacts.append(element("span", "No artifact paths reported."));
    card.append(artifacts);
    container.append(card);
  });

  const body = document.getElementById("wfp-table");
  if (!body) return;
  const events = list(run.network_attempts);
  const search = document.getElementById("wfp-search");
  const attribution = document.getElementById("wfp-attribution");
  const previous = document.getElementById("wfp-previous");
  const next = document.getElementById("wfp-next");
  const pageSize = 100;
  let page = 0;
  const endpoint = (address, port) => !address ? "unknown / not supplied" : `${address}${port ? `:${port}` : ""}`;
  const render = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = events.filter(event => {
      const correlation = event.correlation || {};
      if (attribution.value === "target" && correlation.target !== true) return false;
      if (attribution.value === "unattributed" && correlation.target === true) return false;
      return !query || [event.time_utc, event.event_id, event.action, event.protocol, event.pid, event.image,
        event.local_address, event.local_port, event.remote_address, event.remote_port,
        correlation.confidence, correlation.reason, event.source_artifact].join(" ").toLowerCase().includes(query);
    });
    const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
    page = Math.min(page, pages - 1);
    body.replaceChildren();
    filtered.slice(page * pageSize, (page + 1) * pageSize).forEach(event => {
      const correlation = event.correlation || {};
      const row = element("tr", "");
      const values = [
        `${event.time_utc || "unknown"} / ${counter(event.observed_at_ms)} ms`,
        `${counter(event.event_id)} · ${event.action || "unknown"}`,
        event.protocol || "unknown", `${event.pid == null ? "PID unknown" : `PID ${event.pid}`} · ${event.image || "image unavailable"}`,
        endpoint(event.local_address, event.local_port), endpoint(event.remote_address, event.remote_port),
        `${correlation.target === true ? "Target tree (inferred)" : "Unattributed"} · confidence: ${correlation.confidence || "unknown"}\n${correlation.reason || "No correlation metadata supplied."}`,
      ];
      values.forEach(value => row.append(element("td", value)));
      const source = element("td", "", "cell-source");
      source.append(element("span", event.source_artifact || "source unavailable"));
      const details = element("details", "");
      details.append(element("summary", "Raw event"), element("pre", JSON.stringify(event, null, 2)));
      source.append(details); row.append(source); body.append(row);
    });
    if (!filtered.length) {
      const row = element("tr", "");
      const cell = element("td", events.length ? "No WFP events match these filters." : "WFP attempt evidence unavailable or empty. This does not establish that no attempts occurred.", "empty-state");
      cell.colSpan = 8; row.append(cell); body.append(row);
    }
    document.getElementById("wfp-count").textContent = `${filtered.length} of ${events.length} archived events`;
    document.getElementById("wfp-page").textContent = `Page ${page + 1} of ${pages} · up to ${pageSize} events per page`;
    previous.disabled = page === 0; next.disabled = page + 1 >= pages;
  };
  search.addEventListener("input", () => { page = 0; render(); });
  attribution.addEventListener("change", () => { page = 0; render(); });
  previous.addEventListener("click", () => { page--; render(); });
  next.addEventListener("click", () => { page++; render(); });
  render();
})();
