"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const root = path.resolve(__dirname, "..");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const source = read("src/report_analysis/web.rs");
const script = read("src/report_analysis/web_assets/network-telemetry.js");
const app = read("src/report_analysis/web_assets/app.js");
const fixture = JSON.parse(read("tests/fixtures/detection/web-data.json"));
const hostile = '<img src=x onerror="window.pwned=1"><script>window.pwned=2</script>';
fixture.stages = [
  {stage:"execution", status:"completed", target:null, warnings:[]},
  {stage:"cleanup", status:"failed", target:null, warnings:[hostile]},
  {stage:"yara", status:"unavailable", target:"primary", warnings:["Interpreter missing"]},
];
fixture.normalized.capture_health = [
  { channel:"guest_wfp", requested:true, started:true, stopped:true, byte_limit:8388608, event_limit:10000, raw_event_limit:5000,
    captured_bytes:2000, captured_events:10000, retained_events:5000, captured_packets:null, dropped_events:null, dropped_packets:0,
    truncated:true, loss_detected:false, provider_errors:[hostile], warnings:[], artifacts:["extracted-files/telemetry-events.json"] },
  { channel:"host_ndis", requested:true, started:false, stopped:false, captured_bytes:null, captured_packets:null, warnings:[], artifacts:[] },
];
fixture.normalized.network_attempts = Array.from({length:101}, (_, index) => ({
  event_id:index === 100 ? 5158 : 5157, action:index === 100 ? "bind_permitted" : "connection_blocked",
  pid:index === 0 ? null : 42, image:hostile, time_utc:"2026-09-08T08:00:00Z", observed_at_ms:index,
  protocol:"udp", local_address:"10.0.0.2", local_port:50000, remote_address:"1.1.1.1", remote_port:443,
  correlation:{target:index !== 0, confidence:index === 0 ? "none" : "medium", reason:"PID and lifetime match"},
  source_artifact:"extracted-files/telemetry-events.json", data:{Application:hostile},
}));
for (const page of ["overview", "network"]) {
  const constant = page === "overview" ? "OVERVIEW" : "NETWORK";
  const body = source.match(new RegExp(`const ${constant}: &str = r#"([\\s\\S]*?)"#;`))[1];
  const dom = new JSDOM(`<body data-page="${page}"><div id="report-error" hidden></div>${body}</body>`, {runScripts:"outside-only", url:`file:///offline/${page}.html`});
  const w = dom.window;
  w.requestAnimationFrame = () => 0;
  w.ResizeObserver = class { observe() {} disconnect() {} };
  w.FOXHOLE_REPORT = structuredClone(fixture);
  w.eval(app);
  if (page === "overview") {
    const stages = w.document.getElementById("stage-results");
    assert.equal(stages.children.length, 3);
    assert(stages.textContent.includes("failed"));
    assert(stages.textContent.includes("unavailable"));
    assert(stages.textContent.includes(hostile));
  }
  w.eval(script);
  const text = w.document.getElementById("capture-health").textContent;
  for (const value of ["guest_wfp", "host_ndis", "8388608 / 10000 / 5000", "2000 / unknown", "unknown / 0", "Capture truncated", "Capture unavailable", "Provider error", "never complete", "encrypted traffic content".replace("encrypted", "Encrypted"), "guest-admin tampering", "extracted-files/telemetry-events.json"]) {
    assert(text.includes(value), `missing ${value}`);
  }
  assert.equal(w.pwned, undefined);
  assert.equal(w.document.querySelectorAll("img,script,iframe,object").length, 0);
  if (page === "network") {
    const table = w.document.getElementById("wfp-table");
    assert.equal(table.children.length, 100);
    assert(table.textContent.includes("PID unknown"));
    assert(table.textContent.includes("Unattributed"));
    assert(table.textContent.includes("confidence: medium"));
    assert(table.textContent.includes("PID and lifetime match"));
    assert(table.textContent.includes("10.0.0.2:50000"));
    assert(table.textContent.includes("2026-09-08T08:00:00Z"));
    w.document.getElementById("wfp-next").click();
    assert.equal(table.children.length, 1);
    assert(table.textContent.includes("bind_permitted"));
    const select = w.document.getElementById("wfp-attribution");
    select.value="unattributed"; select.dispatchEvent(new w.Event("change"));
    assert.equal(table.children.length, 1);
    assert.equal(w.document.getElementById("wfp-count").textContent, "1 of 101 archived events");
    const search = w.document.getElementById("wfp-search");
    search.value="absent"; search.dispatchEvent(new w.Event("input"));
    assert(table.textContent.includes("No WFP events match"));
  }
  dom.window.close();
}
// Old reports expose unavailable health instead of invented zero counters.
const legacy = new JSDOM('<div id="capture-health"></div>', {runScripts:"outside-only"});
legacy.window.FOXHOLE_REPORT={normalized:{}};
legacy.window.eval(script);
assert(legacy.window.document.body.textContent.includes("metadata unavailable"));
legacy.window.close();
console.log("PASS: offline Overview/Network capture health, WFP evidence, filters, pagination, unknown counts and hostile text.");
