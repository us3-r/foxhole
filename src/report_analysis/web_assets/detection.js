"use strict";
(() => {
  const data = window.FOXHOLE_REPORT;
  if (!data || !data.normalized) return;
  const detection = data.normalized.detection || { stages: [], warnings: [], behavioral_status: "unavailable" };
  const text = value => String(value == null ? "Not available" : value).slice(0, 2048);
  const node = (tag, value) => { const element = document.createElement(tag); if (value != null) element.textContent = text(value); return element; };
  const usedEvidence = new Set();
  const evidenceLinks = ids => {
    const list=node("p");
    for(const id of ids || []) {usedEvidence.add(id);const link=node("a", id);link.href=`detection.html#evidence-${encodeURIComponent(id)}`;list.append(link,node("span"," "));}
    return list;
  };
  const main = document.getElementById("main-content");
  const incomplete = detection.stages.filter(stage => !["completed", "disabled"].includes(stage.status));
  if (incomplete.length || detection.behavioral_status === "partial" || !detection.stages.length) {
    const warning = node("aside");
    warning.className = "error-banner";
    warning.append(node("strong", "Analysis coverage is incomplete. "));
    warning.append(node("span", incomplete.map(stage => `${stage.scanner}: ${stage.status}`).join(" · ") || "Scanner results are unavailable."));
    const link = node("a", " View coverage and warnings"); link.href = "detection.html"; warning.append(link);
    main.prepend(warning);
  }
  const container = document.getElementById("detection-stages");
  if (!container) return;
  const download = node("a", "Download complete bounded analysis JSON");
  download.href = URL.createObjectURL(new Blob([JSON.stringify(detection, null, 2)], {type:"application/json"}));
  download.download = "foxhole-detection.json";
  container.append(download, node("p", `Behavioral coverage: ${detection.behavioral_status}`));
  for(const [name,status] of Object.entries(detection.coverage || {})) container.append(node("p", `${name}: ${status}`));
  (detection.warnings || []).forEach(w => container.append(node("p", `${w.code}: ${w.message}`)));
  for (const stage of detection.stages) {
    const card = node("section"); card.className = "panel";
    card.append(node("h2", `${stage.scanner} · ${stage.status}`), node("p", `${stage.target} · SHA-256 ${stage.target_sha256}`), node("p", `Engine ${stage.version} · ${stage.truncated ? "Truncated" : "No reported truncation"}`));
    for (const pack of stage.rule_packs) card.append(node("p", `${pack.trusted ? "Foxhole" : "User"} rules: ${pack.id} ${pack.version} · ${pack.sha256}`));
    for (const w of stage.warnings) card.append(node("p", `${w.code}: ${w.message}`));
    const evidence = node("details"); evidence.append(node("summary", "Evidence and limits"));
    evidence.append(node("pre", JSON.stringify({evidence:stage.evidence_ids, original:stage.original, limits:stage.limits}, null, 2))); card.append(evidence, evidenceLinks(stage.evidence_ids));
    if (stage.pe) {
      const pe = node("details"); pe.append(node("summary", "PE properties · timestamps and section markers are untrusted"));
      for (const [key,value] of Object.entries(stage.pe)) pe.append(node("h3", key), node("pre", JSON.stringify(value, null, 2)));
      card.append(pe);
    }
    const findings = node("details"); findings.append(node("summary", `${stage.findings.length} findings / capabilities`));
    stage.findings.forEach(f => {const row=node("article");row.append(node("h3", f.title),node("p", `${f.namespace} · ${f.scope}`),node("pre", JSON.stringify({locations:f.locations,features:f.features,metadata:f.metadata,attack:f.attack,mbc:f.mbc,maec:f.maec,evidence:f.evidence_ids},null,2)));row.append(evidenceLinks(f.evidence_ids));findings.append(row);});card.append(findings);
    if (stage.strings.length) { const strings=node("details");strings.append(node("summary", `${stage.strings.length} plain / decoded strings`));stage.strings.slice(0,200).forEach(s=>strings.append(node("p",`${s.method} @ ${s.offset}: ${s.value}`)));if(stage.strings.length>200)strings.append(node("p","Preview limited to 200 strings. Download JSON for all retained values."));card.append(strings); }
    if (stage.packets.length) {
      const flows=(detection.network_flows || []).filter(f=>f.capture_sha256===stage.target_sha256);
      const flowView=node("details");flowView.append(node("summary",`${flows.length} flows · packet timestamps in UTC microseconds`));flows.slice(0,200).forEach(f=>flowView.append(node("pre",JSON.stringify(f,null,2)),evidenceLinks(f.evidence_ids)));card.append(flowView);
      const correlations=(detection.packet_correlations || []).filter(c=>c.capture_sha256===stage.target_sha256);
      const correlated=node("details");correlated.append(node("summary",`${correlations.length} inferred packet/process associations · exact endpoints and clock window`));correlations.slice(0,200).forEach(c=>correlated.append(node("pre",JSON.stringify(c,null,2)),evidenceLinks(c.evidence_ids)));card.append(correlated);
      const packets=node("details");packets.append(node("summary",`${stage.packets.length} packet observations · encrypted HTTP not inspected`));stage.packets.slice(0,200).forEach(p=>packets.append(node("pre",JSON.stringify(p,null,2))));card.append(packets);
    }
    container.append(card);
  }
  const evidenceIndex=new Map();
  const n=data.normalized;
  for(const record of [...n.artifacts,...n.file_events,...n.registry_events,...n.network_events,...n.processes.flatMap(p=>p.observations)]) evidenceIndex.set(record.evidence_id,record);
  if(n.target && n.target.sha256) evidenceIndex.set(`sha256:${n.target.sha256.toLowerCase()}`,n.target);
  const index=node("section");index.append(node("h2","Referenced evidence"));
  for(const id of [...usedEvidence].sort()) {
    const record=node("details");record.id=`evidence-${encodeURIComponent(id)}`;
    record.append(node("summary",id),node("pre",JSON.stringify(evidenceIndex.get(id) || {status:"Evidence unavailable"},null,2)));
    index.append(record);
  }
  container.append(index);
})();
