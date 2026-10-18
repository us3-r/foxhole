// Run with NODE_PATH pointing to a trusted jsdom 26.1.0 installation.
// All hostile strings below are inert fixtures; no target executable is run.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { JSDOM } = require("jsdom");
const root = require("node:path").resolve(__dirname, "..");
const read = path => fs.readFileSync(`${root}/${path}`, "utf8");
const source = read("src/report_analysis/web.rs");
const fixture = JSON.parse(read("tests/fixtures/detection/web-data.json"));
const hostile = '</script><img src=x onerror="window.pwned=1"><script>window.pwned=2</script>';
fixture.normalized.detection.stages[0].findings[0].title = hostile;
fixture.verdict.findings[0].title = hostile;
fixture.verdict.findings[0].explanation = "x".repeat(8000);
fixture.normalized.detection.stages[0].findings[0].metadata = JSON.parse('{"__proto__":{"pwned":3}}');
fixture.iocs.indicators[0].value = hostile;
const scripts = ["app.js", "detection.js"].map(name=>read(`src/report_analysis/web_assets/${name}`));
assert(scripts.every(s=>!s.includes("innerHTML") && !s.includes("eval(")));
for (const page of ["detection", "findings", "iocs"]) {
  const body = page === "detection" ? '<div id="detection-stages"></div>' : source.match(new RegExp(`const ${page.toUpperCase()}: &str = r#"([\\s\\S]*?)"#;`))[1];
  const dom = new JSDOM(`<body data-page="${page}"><div id="report-error" hidden></div><main id="main-content">${body}</main></body>`, {runScripts:"outside-only", url:`file:///offline/${page}.html`});
  const w = dom.window;
  let downloaded;
  w.URL.createObjectURL = blob => { downloaded = blob; return "blob:fixture"; };
  w.ResizeObserver = class { observe() {} disconnect() {} };
  w.eval(`window.FOXHOLE_REPORT = JSON.parse(${JSON.stringify(JSON.stringify(fixture))});`);
  scripts.forEach(script => w.eval(script));
  assert.equal(w.pwned, undefined);
  assert.equal(w.document.querySelectorAll("img,script,iframe,object").length, 0);
  assert(!w.document.body.textContent.includes("x".repeat(2049)));
  assert(w.document.querySelector(".error-banner"));
  if(page === "detection") {
    assert(downloaded.size > 0);
    for (const link of w.document.querySelectorAll('a[href*="#evidence-"]')) {
      const fragment=link.getAttribute("href").split("#")[1];
      assert(w.document.getElementById(fragment), `unresolved ${fragment}`);
    }
  }
  if(page === "iocs") {
    const select = w.document.getElementById("ioc-source-category");
    select.value="analyst-supplied"; select.dispatchEvent(new w.Event("change"));
    assert.equal(w.document.getElementById("ioc-result-count").textContent,"0 indicators");
    select.value="packet"; select.dispatchEvent(new w.Event("change"));
    assert.notEqual(w.document.getElementById("ioc-result-count").textContent,"0 indicators");
  }
  if(page === "findings") {
    for(const id of ["finding-severity","finding-source","finding-file","finding-namespace","finding-attack","finding-confidence"]) assert(w.document.getElementById(id));
    const search=w.document.getElementById("finding-search");search.value="nonexistent-finding";search.dispatchEvent(new w.Event("input"));
    assert.equal(w.document.getElementById("finding-result-count").textContent,"0 findings");
  }
  dom.window.close();
}
console.log("Offline detection, finding, IOC filter, evidence link and hostile-text DOM checks passed.");
