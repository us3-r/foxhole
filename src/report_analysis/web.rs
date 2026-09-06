use super::model::{IocReport, NormalizedRun, VerdictReport};
use serde::Serialize;
use std::io;
use std::path::{Path, PathBuf};

const STYLE: &str = include_str!("web_assets/style.css");
const APPLICATION: &str = include_str!("web_assets/app.js");

#[derive(Debug, Serialize)]
struct WebReportData<'a> {
    normalized: &'a NormalizedRun,
    verdict: &'a VerdictReport,
    iocs: &'a IocReport,
}

pub fn write_web_report(
    run_root: &Path,
    normalized: &NormalizedRun,
    verdict: &VerdictReport,
    iocs: &IocReport,
) -> io::Result<PathBuf> {
    write_bytes(
        run_root,
        Path::new("web/assets/style.css"),
        STYLE.as_bytes(),
    )?;
    write_bytes(
        run_root,
        Path::new("web/assets/app.js"),
        APPLICATION.as_bytes(),
    )?;
    let serialized = serde_json::to_string(&WebReportData {
        normalized,
        verdict,
        iocs,
    })
    .map_err(io::Error::other)?;
    let report_script = format!("window.FOXHOLE_REPORT = {serialized};\n");
    write_bytes(
        run_root,
        Path::new("web/data/report-data.js"),
        report_script.as_bytes(),
    )?;

    for page in PAGES {
        write_bytes(
            run_root,
            &Path::new("web").join(page.file),
            render_page(page).as_bytes(),
        )?;
    }
    Ok(run_root.join("web/index.html"))
}

#[derive(Clone, Copy)]
struct Page {
    file: &'static str,
    id: &'static str,
    title: &'static str,
    eyebrow: &'static str,
    heading: &'static str,
    description: &'static str,
    content: &'static str,
}

const PAGES: &[Page] = &[
    Page {
        file: "index.html",
        id: "overview",
        title: "Overview",
        eyebrow: "Deterministic analysis",
        heading: "Run overview",
        description: "A compact view of verdict, evidence volume, coverage, and extracted indicators.",
        content: OVERVIEW,
    },
    Page {
        file: "parameters.html",
        id: "parameters",
        title: "Run parameters",
        eyebrow: "Execution input",
        heading: "Run parameters",
        description: "The host-side Foxhole command and effective sandbox settings retained for this run.",
        content: PARAMETERS,
    },
    Page {
        file: "findings.html",
        id: "findings",
        title: "Findings",
        eyebrow: "Rule evidence",
        heading: "Explainable findings",
        description: "Every contribution is linked to exact evidence and its process association.",
        content: FINDINGS,
    },
    Page {
        file: "timeline.html",
        id: "timeline",
        title: "Timeline",
        eyebrow: "Event correlation",
        heading: "Evidence timeline",
        description: "Process, file, registry, and network activity aligned on one elapsed-time axis.",
        content: TIMELINE,
    },
    Page {
        file: "processes.html",
        id: "processes",
        title: "Processes",
        eyebrow: "Process identity",
        heading: "Process relationships",
        description: "Stable process records with every raw observation retained beneath them.",
        content: PROCESSES,
    },
    Page {
        file: "network.html",
        id: "network",
        title: "Network",
        eyebrow: "Network activity",
        heading: "Network observations",
        description: "Parsed connections, listeners, and DNS activity linked to the responsible process and source evidence.",
        content: NETWORK,
    },
    Page {
        file: "iocs.html",
        id: "iocs",
        title: "IOCs",
        eyebrow: "Indicator provenance",
        heading: "Indicators of compromise",
        description: "Deduplicated indicators with first-seen spelling, context, and complete provenance.",
        content: IOCS,
    },
];

fn render_page(page: &Page) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="theme-color" content="#1f2124">
  <meta name="description" content="Foxhole deterministic analyst report">
  <title>{} · Foxhole analyst report</title>
  <link rel="stylesheet" href="assets/style.css">
  <script defer src="data/report-data.js"></script>
  <script defer src="assets/app.js"></script>
</head>
<body data-page="{}">
  <a class="skip-link" href="#main-content">Skip to report</a>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="index.html" aria-label="Foxhole report overview">
        <span class="brand-mark" aria-hidden="true">F</span>
        <span><strong>FOXHOLE</strong><small>Analyst report</small></span>
      </a>
      <nav class="primary-nav" aria-label="Report sections">
        <a data-nav="overview" href="index.html">Overview</a>
        <a data-nav="parameters" href="parameters.html">Run</a>
        <a data-nav="findings" href="findings.html">Findings</a>
        <a data-nav="timeline" href="timeline.html">Timeline</a>
        <a data-nav="processes" href="processes.html">Processes</a>
        <a data-nav="network" href="network.html">Network</a>
        <a data-nav="iocs" href="iocs.html">IOCs</a>
      </nav>
      <div class="report-context">
        <div class="target-chip"><span>Analyzed file</span><code id="target-file-name">loading</code></div>
        <div class="run-chip"><span>Run</span><code id="run-id">loading</code></div>
      </div>
    </div>
  </header>
  <main id="main-content" class="page-shell">
    <div id="report-error" class="error-banner" role="alert" hidden></div>
    <header class="page-intro">
      <p class="eyebrow">{}</p>
      <h1>{}</h1>
      <p>{}</p>
    </header>
    {}
  </main>
  <footer class="site-footer">
    <span>Foxhole normalized schema <code id="schema-version">—</code></span>
    <span>Deterministic · offline · source-linked</span>
  </footer>
</body>
</html>
"##,
        page.title, page.id, page.eyebrow, page.heading, page.description, page.content
    )
}

fn write_bytes(root: &Path, relative: &Path, bytes: &[u8]) -> io::Result<()> {
    crate::artifact::secure_replace_in(
        root,
        relative,
        super::MAX_ANALYSIS_OUTPUT_BYTES,
        |writer| writer.write_all(bytes),
    )?;
    Ok(())
}

const OVERVIEW: &str = r#"
<section class="target-strip" aria-labelledby="target-heading">
  <div>
    <p class="section-kicker">Primary file</p>
    <h2 id="target-heading"><code id="overview-target-file">—</code></h2>
  </div>
  <div class="target-details">
    <div><span>Size</span><strong id="target-size">—</strong></div>
    <div class="target-hash">
      <span>SHA-256</span>
      <code id="target-sha256">—</code>
      <a id="target-virustotal" class="external-link" target="_blank" rel="noopener noreferrer" hidden>Check on VirusTotal <span aria-hidden="true">↗</span></a>
    </div>
  </div>
</section>

<section class="verdict-strip" aria-labelledby="verdict-heading">
  <div>
    <p class="section-kicker">Overall assessment</p>
    <h2 id="verdict-heading"><span id="verdict-label">—</span></h2>
    <p id="verdict-summary">Calculating report summary…</p>
  </div>
  <div id="score-gauge" class="score-gauge" role="img" aria-label="Verdict score">
    <div><strong id="score-value">—</strong><span>/ 100+</span></div>
  </div>
</section>

<section class="stat-grid" aria-label="Run summary">
  <article class="stat"><span>Findings</span><strong id="finding-count">—</strong><small id="finding-mix">—</small></article>
  <article class="stat"><span>Timeline events</span><strong id="timeline-count">—</strong><small>normalized observations</small></article>
  <article class="stat"><span>Indicators</span><strong id="ioc-count">—</strong><small id="ioc-context">—</small></article>
  <article class="stat"><span>Validation</span><strong id="warning-count">—</strong><small>normalization warnings</small></article>
</section>

<section class="panel file-hash-panel" aria-labelledby="created-file-heading">
  <div class="panel-heading">
    <div><p class="section-kicker">Guest file evidence</p><h2 id="created-file-heading">Files created or downloaded inside the VM</h2></div>
    <span id="created-file-count" class="result-count" aria-live="polite"></span>
  </div>
  <p id="created-file-empty" class="empty-state" hidden>No SHA-256 evidence was available for target-created files.</p>
  <div id="created-file-table-wrap" class="table-wrap"><table><thead><tr><th>Name</th><th>Guest path</th><th>Activity</th><th>Size</th><th>SHA-256</th><th>Hash source</th><th>Lookup</th></tr></thead><tbody id="created-file-table"></tbody></table></div>
</section>

<div class="dashboard-grid">
  <section class="panel panel-wide" aria-labelledby="activity-heading">
    <div class="panel-heading"><div><p class="section-kicker">Elapsed activity</p><h2 id="activity-heading">Event density</h2></div><a href="timeline.html">Explore timeline →</a></div>
    <div id="activity-chart" class="activity-chart"></div>
  </section>
  <section class="panel" aria-labelledby="events-heading">
    <div class="panel-heading"><div><p class="section-kicker">Input integrity</p><h2 id="events-heading">Event coverage</h2></div></div>
    <div id="event-bars" class="bar-chart"></div>
  </section>
  <section class="panel" aria-labelledby="ioc-heading">
    <div class="panel-heading"><div><p class="section-kicker">Extracted evidence</p><h2 id="ioc-heading">IOCs by type</h2></div><a href="iocs.html">View all →</a></div>
    <div id="ioc-bars" class="bar-chart compact"></div>
  </section>
  <section class="panel" aria-labelledby="coverage-heading">
    <div class="panel-heading"><div><p class="section-kicker">Collector status</p><h2 id="coverage-heading">Telemetry coverage</h2></div></div>
    <div id="coverage-grid" class="coverage-grid"></div>
  </section>
  <section class="panel" aria-labelledby="top-findings-heading">
    <div class="panel-heading"><div><p class="section-kicker">Rule output</p><h2 id="top-findings-heading">Findings</h2></div><a href="findings.html">Evidence detail →</a></div>
    <div id="finding-list" class="finding-list"></div>
  </section>
</div>
"#;

const PARAMETERS: &str = r#"
<section class="panel launch-panel" aria-labelledby="host-command-heading">
  <div class="panel-heading">
    <div><p class="section-kicker">Host launch</p><h2 id="host-command-heading">PowerShell invocation</h2></div>
    <span id="host-command-source" class="evidence-source">—</span>
  </div>
  <div class="command-block">
    <code id="host-command-line">—</code>
    <button id="copy-host-command" class="copy-button" type="button">Copy command</button>
  </div>
  <p id="host-command-note" class="fidelity-note">Target argument values are redacted in exported reports.</p>
</section>

<section class="parameter-grid" aria-label="Host run settings">
  <article class="parameter-card"><span>Output root</span><code id="parameter-output">—</code></article>
  <article class="parameter-card"><span>Requested sandbox</span><strong id="parameter-requested-backend">—</strong></article>
  <article class="parameter-card"><span>Selected backend</span><strong id="parameter-selected-backend">—</strong></article>
  <article class="parameter-card"><span>Hyper-V profile</span><strong id="parameter-hv-profile">—</strong></article>
  <article class="parameter-card"><span>Network policy</span><strong id="parameter-network-policy">—</strong></article>
  <article class="parameter-card"><span>Allowed IPs</span><code id="parameter-allowed-ips">—</code></article>
  <article class="parameter-card"><span>Mitigation profile</span><strong id="parameter-mitigation">—</strong></article>
  <article class="parameter-card"><span>Timeout</span><strong id="parameter-timeout">—</strong></article>
  <article class="parameter-card"><span>Target arguments</span><strong id="parameter-target-arguments">—</strong></article>
</section>

<section class="panel guest-launch-panel" aria-labelledby="guest-command-heading">
  <div class="panel-heading">
    <div><p class="section-kicker">Guest evidence</p><h2 id="guest-command-heading">Observed target process</h2></div>
    <span id="guest-command-source" class="evidence-source">—</span>
  </div>
  <code id="guest-command-line" class="guest-command-line">—</code>
  <p class="secondary-note">Captured from in-guest process telemetry. This can reveal runtime arguments, but it is behavioral evidence rather than trusted host configuration.</p>
</section>
"#;

const FINDINGS: &str = r#"
<section class="stat-grid compact-stats" aria-label="Finding summary">
  <article class="stat"><span>Score</span><strong id="findings-score">—</strong><small>deterministic points</small></article>
  <article class="stat"><span>Confidence</span><strong id="findings-confidence">—</strong><small>coverage-adjusted</small></article>
  <article class="stat"><span>Evidence refs</span><strong id="evidence-count">—</strong><small>traceable observations</small></article>
</section>
<section class="panel" aria-labelledby="severity-heading">
  <div class="panel-heading"><div><p class="section-kicker">Rule distribution</p><h2 id="severity-heading">Findings by severity</h2></div></div>
  <div id="severity-bars" class="bar-chart horizontal"></div>
</section>
<section class="filter-row" aria-label="Finding filters">
  <label for="finding-severity">Severity <select id="finding-severity"><option value="all">All severities</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="informational">Informational</option></select></label>
  <label for="finding-search">Search <input id="finding-search" type="search" placeholder="Rule, process, or evidence"></label>
  <span id="finding-result-count" class="result-count" aria-live="polite"></span>
</section>
<div id="findings-container" class="findings-container"></div>
"#;

const TIMELINE: &str = r#"
<section class="filter-row" aria-label="Timeline filters">
  <label for="timeline-kind">Event type <select id="timeline-kind"><option value="all">All events</option><option value="process">Process</option><option value="network">Network</option><option value="file">File</option><option value="registry">Registry</option></select></label>
  <label for="timeline-pid">Process ID <input id="timeline-pid" inputmode="numeric" placeholder="All PIDs"></label>
  <label class="check-label"><input id="timeline-inferred" type="checkbox"> Inferred associations only</label>
  <span id="timeline-result-count" class="result-count" aria-live="polite"></span>
</section>
<section class="panel timeline-panel" aria-labelledby="timeline-chart-heading">
  <div class="panel-heading"><div><p class="section-kicker">Milliseconds after observation start</p><h2 id="timeline-chart-heading">Activity by evidence type</h2></div></div>
  <div id="timeline-chart" class="svg-chart"></div>
  <div class="chart-legend" aria-label="Timeline legend"><span class="legend-process">Process</span><span class="legend-network">Network</span><span class="legend-file">File</span><span class="legend-registry">Registry</span></div>
</section>
<section class="panel" aria-labelledby="timeline-table-heading">
  <div class="panel-heading"><div><p class="section-kicker">Exact evidence</p><h2 id="timeline-table-heading">Ordered observations</h2></div></div>
  <div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Evidence</th><th>Association</th><th>Source</th></tr></thead><tbody id="timeline-table"></tbody></table></div>
</section>
"#;

const PROCESSES: &str = r#"
<section class="stat-grid compact-stats" aria-label="Process summary">
  <article class="stat"><span>Stable processes</span><strong id="process-count">—</strong><small>deduplicated by PID</small></article>
  <article class="stat"><span>Observations</span><strong id="observation-count">—</strong><small>all raw records retained</small></article>
  <article class="stat"><span>Root PID</span><strong id="root-pid">—</strong><small>target execution</small></article>
</section>
<div class="dashboard-grid process-layout">
  <section class="panel panel-wide" aria-labelledby="process-tree-heading">
    <div class="panel-heading"><div><p class="section-kicker">Parent / child graph</p><h2 id="process-tree-heading">Process tree</h2></div></div>
    <div id="process-tree" class="svg-chart process-tree"></div>
    <p class="tree-note">A colored branch begins when a process also launches children. Direct leaf-only branches remain gray.</p>
  </section>
  <section class="panel panel-wide" aria-labelledby="observation-bars-heading">
    <div class="panel-heading"><div><p class="section-kicker">Identity stability</p><h2 id="observation-bars-heading">Observations per PID</h2></div></div>
    <div id="process-bars" class="bar-chart"></div>
  </section>
</div>
<section class="panel" aria-labelledby="process-table-heading">
  <div class="panel-heading"><div><p class="section-kicker">Normalized records</p><h2 id="process-table-heading">Process detail</h2></div></div>
  <div class="table-wrap"><table><thead><tr><th>PID</th><th>Parent</th><th>Image</th><th>Command line</th><th>Status</th><th>First observed</th><th>Observations</th></tr></thead><tbody id="process-table"></tbody></table></div>
</section>
"#;

const NETWORK: &str = r#"
<section class="stat-grid" aria-label="Network summary">
  <article class="stat"><span>Events</span><strong id="network-count">—</strong><small>normalized observations</small></article>
  <article class="stat"><span>Remote endpoints</span><strong id="remote-endpoint-count">—</strong><small>unique address and port pairs</small></article>
  <article class="stat"><span>DNS domains</span><strong id="network-domain-count">—</strong><small>unique queried names</small></article>
  <article class="stat"><span>Inferred links</span><strong id="network-inferred-count">—</strong><small>process associations</small></article>
</section>
<div class="dashboard-grid network-summary-grid">
  <section class="panel" aria-labelledby="protocol-heading">
    <div class="panel-heading"><div><p class="section-kicker">Transport mix</p><h2 id="protocol-heading">Events by protocol</h2></div></div>
    <div id="network-protocol-bars" class="bar-chart"></div>
  </section>
  <section class="panel" aria-labelledby="network-state-heading">
    <div class="panel-heading"><div><p class="section-kicker">Observed result</p><h2 id="network-state-heading">Events by state</h2></div></div>
    <div id="network-state-bars" class="bar-chart"></div>
  </section>
</div>
<section class="filter-row" aria-label="Network filters">
  <label for="network-protocol">Protocol <select id="network-protocol"><option value="all">All protocols</option></select></label>
  <label for="network-direction">Direction <select id="network-direction"><option value="all">All directions</option></select></label>
  <label for="network-search">Search <input id="network-search" type="search" placeholder="Endpoint, domain, process, or state"></label>
  <label class="check-label"><input id="network-inferred" type="checkbox"> Inferred associations only</label>
  <span id="network-result-count" class="result-count" aria-live="polite"></span>
</section>
<section class="panel" aria-labelledby="network-table-heading">
  <div class="panel-heading"><div><p class="section-kicker">Parsed evidence</p><h2 id="network-table-heading">Network event detail</h2></div><small class="panel-note">A correlated download is labeled once per endpoint.</small></div>
  <div class="table-wrap"><table><thead><tr><th>Time</th><th>Protocol</th><th>Direction</th><th>Process</th><th>Local endpoint</th><th>Remote endpoint / domain</th><th>State</th><th>Association</th><th>Source</th></tr></thead><tbody id="network-table"></tbody></table></div>
</section>
"#;

const IOCS: &str = r#"
<section class="stat-grid compact-stats" aria-label="IOC summary">
  <article class="stat"><span>Total indicators</span><strong id="iocs-total">—</strong><small>after deduplication</small></article>
  <article class="stat"><span>Contextual</span><strong id="iocs-contextual">—</strong><small>retained for audit</small></article>
  <article class="stat"><span>Source links</span><strong id="ioc-source-count">—</strong><small>provenance references</small></article>
</section>
<section class="panel" aria-labelledby="ioc-distribution-heading">
  <div class="panel-heading"><div><p class="section-kicker">Indicator distribution</p><h2 id="ioc-distribution-heading">IOCs by type</h2></div></div>
  <div id="ioc-type-bars" class="bar-chart horizontal"></div>
</section>
<section class="filter-row" aria-label="IOC filters">
  <label for="ioc-type">Indicator type <select id="ioc-type"><option value="all">All indicator types</option></select></label>
  <label class="filter-search" for="ioc-search">Path or value <input id="ioc-search" type="search" placeholder="Search paths, values, or sources"></label>
  <label for="ioc-file-type">File type <select id="ioc-file-type"><option value="all">All file types</option></select></label>
  <label for="ioc-event-type">Event type <select id="ioc-event-type"><option value="all">All event types</option></select></label>
  <label for="ioc-scope">Evidence scope <select id="ioc-scope"><option value="all">All indicators</option><option value="observable">Observables only</option><option value="contextual">Contextual only</option></select></label>
  <span id="ioc-result-count" class="result-count" aria-live="polite"></span>
  <p class="filter-help"><strong>Contextual indicators</strong> are common or likely benign values retained to show the full evidence trail. Use “Observables only” to focus on values that may warrant investigation.</p>
</section>
<section class="ioc-results" aria-labelledby="ioc-groups-heading">
  <div class="results-heading"><div><p class="section-kicker">Grouped evidence</p><h2 id="ioc-groups-heading">Indicators by type</h2></div><small>Bars compare source references. Click any bar label to copy its full value.</small></div>
  <div id="ioc-groups" class="ioc-groups"></div>
</section>
<section id="ioc-warning-panel" class="panel" aria-labelledby="ioc-warning-heading">
  <div class="panel-heading"><div><p class="section-kicker">Extraction transparency</p><h2 id="ioc-warning-heading">Warnings</h2></div></div>
  <ul id="ioc-warnings" class="warning-list"></ul>
</section>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pages_include_target_identity_and_network_navigation() {
        for page in PAGES {
            let html = render_page(page);
            assert!(html.contains("id=\"target-file-name\""));
            assert!(html.contains("data-nav=\"parameters\" href=\"parameters.html\""));
            assert!(html.contains("data-nav=\"network\" href=\"network.html\""));
        }
    }

    #[test]
    fn run_parameters_page_shows_host_invocation_and_guest_evidence() {
        let parameters = PAGES
            .iter()
            .find(|page| page.id == "parameters")
            .expect("run parameters page");
        let html = render_page(parameters);
        for element in [
            "host-command-line",
            "copy-host-command",
            "parameter-output",
            "parameter-requested-backend",
            "parameter-selected-backend",
            "parameter-hv-profile",
            "parameter-network-policy",
            "parameter-allowed-ips",
            "parameter-mitigation",
            "parameter-timeout",
            "parameter-target-arguments",
            "guest-command-line",
        ] {
            assert!(html.contains(&format!("id=\"{element}\"")));
        }
        assert!(APPLICATION.contains("parameters: renderParameters"));
        assert!(APPLICATION.contains("function renderParameters()"));
        assert!(APPLICATION.contains("function reconstructHostCommand("));
    }

    #[test]
    fn network_page_and_application_ship_the_parser_together() {
        let network = PAGES
            .iter()
            .find(|page| page.id == "network")
            .expect("network page");
        let html = render_page(network);
        assert!(html.contains("id=\"network-table\""));
        assert!(html.contains("id=\"network-protocol\""));
        assert!(APPLICATION.contains("network: renderNetwork"));
        assert!(APPLICATION.contains("function renderNetwork()"));
        assert!(APPLICATION.contains("normalized.network_events"));
        assert!(APPLICATION.contains("function networkEndpoint(address, port)"));
        assert!(APPLICATION.contains("const annotatedEndpoints = new Set()"));
    }

    #[test]
    fn overview_prominently_identifies_the_analyzed_file() {
        let overview = PAGES
            .iter()
            .find(|page| page.id == "overview")
            .expect("overview page");
        let html = render_page(overview);
        assert!(html.contains("id=\"overview-target-file\""));
        assert!(html.contains("id=\"target-size\""));
        assert!(html.contains("id=\"target-sha256\""));
        assert!(html.contains("id=\"target-virustotal\""));
        assert!(html.contains("id=\"created-file-table\""));
        assert!(html.find("id=\"created-file-table\"") < html.find("class=\"dashboard-grid\""));
        assert!(APPLICATION.contains("setText(\"overview-target-file\", targetFileName)"));
        assert!(APPLICATION.contains("function renderCreatedFileHashes()"));
        assert!(APPLICATION.contains("function virusTotalUrl(sha256)"));
        assert!(APPLICATION.contains("https://www.virustotal.com/gui/search?query="));
    }

    #[test]
    fn process_and_ioc_explorers_ship_responsive_filters_and_copy_actions() {
        let processes = PAGES
            .iter()
            .find(|page| page.id == "processes")
            .expect("processes page");
        let process_html = render_page(processes);
        assert!(
            process_html.contains(
                "class=\"panel panel-wide\" aria-labelledby=\"observation-bars-heading\""
            )
        );
        assert!(process_html.contains("A colored branch begins"));
        assert!(APPLICATION.contains("function branchColor(index)"));

        let iocs = PAGES
            .iter()
            .find(|page| page.id == "iocs")
            .expect("IOCs page");
        let ioc_html = render_page(iocs);
        for control in ["ioc-file-type", "ioc-event-type", "ioc-scope", "ioc-groups"] {
            assert!(ioc_html.contains(&format!("id=\"{control}\"")));
        }
        assert!(!ioc_html.contains("id=\"ioc-hide-context\""));
        assert!(APPLICATION.contains("function renderIocGroups(indicators)"));
        assert!(APPLICATION.contains("function indicatorFileTypes(indicator)"));
        assert!(APPLICATION.contains("function makeCopyableLabel(element, value, title)"));
    }
}
