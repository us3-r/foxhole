"""Assert observable evidence from the harmless telemetry fixture; never run samples."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def load(path, limit=64 * 1024 * 1024):
    if path.stat().st_size > limit:
        raise ValueError(f"Oversized evidence: {path.name}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def verify(root, token, sample_hash, host_ip, port, require_scanners=False, require_host_pcapng=False):
    root = Path(root)
    checks = []

    def check(name, condition, detail="", required=True):
        checks.append(dict(name=name, status="pass" if condition else ("fail" if required else "not_observed"), detail=detail, required=required))

    reports = list((root / "reports").glob("*.json"))
    if len(reports) != 1:
        raise ValueError("Smoke output must contain exactly one host report")
    host = load(reports[0])
    runs = list((root / "hyperv" / "runs").glob("*"))
    runs = [p for p in runs if p.is_dir()]
    if len(runs) != 1:
        raise ValueError("Smoke output must contain exactly one guest run")
    run = runs[0]
    guest = run / "collected-artifacts" / "guest-output"
    envelope = load(guest / "result.json")
    execution = host["result"]
    check("sample_identity", host.get("target", {}).get("sha256", "").lower() == sample_hash.lower())
    check("execution", execution.get("exit_code") == 0 and not execution.get("timed_out", True))
    cleanup = execution.get("cleanup", {})
    check("cleanup", cleanup.get("attempted") is True and cleanup.get("success") is True and not cleanup.get("leftover_resources"))
    stdout = (guest / "stdout.txt").read_text(encoding="utf-8", errors="replace")
    stderr = (guest / "stderr.txt").read_text(encoding="utf-8", errors="replace")
    check("stdout", f"FOXHOLE_SMOKE_DONE {token} failures=0" in stdout)
    check("stderr", f"FOXHOLE_SMOKE_STDERR {token}" in stderr)
    actions = {}
    for line in stdout.splitlines():
        if line.startswith('{"action":'):
            row = json.loads(line)
            actions[row["action"]] = row.get("ok") is True
    for action in ("file_create", "file_rename", "file_delete", "registry", "child_process", "child_completed", "http_download", "unapproved_connection_failed"):
        check(f"fixture_{action}", actions.get(action) is True)

    raw = load(guest / "extracted-files" / "telemetry-events.json")
    if isinstance(raw, dict):
        raw = raw.get("raw_events", raw.get("events", []))
    if not isinstance(raw, list):
        raise ValueError("Unexpected raw telemetry format")
    root_pid = envelope.get("execution", {}).get("pid")
    check("root_process_identity", isinstance(root_pid, int) and root_pid > 0)
    def contains(row, text):
        return text.casefold() in json.dumps(row, ensure_ascii=False).casefold()
    def sysmon(event_id, text=token):
        return any(r.get("event_id") == event_id and contains(r, text) for r in raw if r.get("source") != "windows_filtering_platform")
    check("process_creation", sysmon(1))
    check("file_creation", sysmon(11) or sysmon(29))
    check("registry_set", sysmon(13))
    check("dns_query", sysmon(22, f"foxhole-smoke-{token}.invalid"), required=False)
    check("named_pipe", sysmon(17) or sysmon(18), required=False)
    check("file_delete", sysmon(23) or sysmon(26), required=False)
    check("process_access", any(r.get("event_id") == 10
          and str(r.get("data", {}).get("SourceProcessId")) == str(root_pid) for r in raw), required=False)
    check("image_load", any(r.get("event_id") == 7 and contains(r, "version.dll")
          and str(r.get("data", {}).get("ProcessId")) == str(root_pid) for r in raw), required=False)

    wfp = [r for r in raw if r.get("source") == "windows_filtering_platform"]
    def attempt(ids, endpoint_port):
        return any(r.get("event_id") in ids and r.get("pid") == root_pid
                   and r.get("remote_address") == host_ip and r.get("remote_port") == endpoint_port
                   and r.get("correlation", {}).get("target") is True for r in wfp)
    check("allowed_wfp_connection", attempt({5156}, port))
    for name, event_id in (("wfp_bind", 5158), ("wfp_listen", 5154)):
        check(name, any(r.get("event_id") == event_id and r.get("pid") == root_pid
              and r.get("correlation", {}).get("target") is True for r in wfp), required=False)
    check("unapproved_endpoint_attempt", attempt({5152, 5153, 5156, 5157}, port + 1),
          "Guest WFP may allow an attempt that the host switch blocks")
    check("guest_wfp_denial", attempt({5152, 5153, 5157}, port + 1),
          "Optional: host-switch blocking does not produce a guest WFP denial", required=False)
    network = host.get("backend_metadata", {}).get("network", {})
    check("host_server_policy", network.get("requested_mode") == "host_server"
          and network.get("host_service_endpoint") == f"http://{host_ip}:{port}")
    for phase in ("pre_run_verification", "post_run_verification"):
        value = network.get(phase, {})
        names = value.get("firewall_rule_ids", [])
        check(phase, value.get("verified") is True and value.get("nat_enabled") is False
              and value.get("host_ipv4") == host_ip and value.get("no_unexpected_routes") is True
              and f"Foxhole-{run.name}-block-outbound" in names
              and f"Foxhole-{run.name}-host-service" in names,
              "Host attestation of scoped allow and default-deny ACLs; failed connect alone is not proof of blocking")
    health = {h["channel"]: h for h in execution.get("capture_health", [])}
    for channel in ("guest_wfp", "guest_pktmon", "host_ndis"):
        value = health.get(channel, {})
        check(f"health_{channel}", value.get("requested") is True and value.get("started") is True and value.get("stopped") is True
              and not value.get("truncated", False) and not value.get("provider_errors") and not value.get("loss_detected", False)
              and not value.get("dropped_events") and not value.get("dropped_packets"), json.dumps(value))
    etl = run / "network-capture.etl"
    pcap = run / "network-capture.pcapng"
    check("host_etl", etl.is_file() and etl.stat().st_size > 0)
    check("host_pcapng", pcap.is_file() and pcap.stat().st_size > 0 and (health.get("host_ndis", {}).get("captured_packets") or 0) > 0, required=require_host_pcapng)
    check("host_http_request", pcap.is_file() and pcap.stat().st_size <= 128 * 1024 * 1024
          and ("foxhole_smoke=" + token).encode("ascii") in pcap.read_bytes(),
          "The host capture must contain this run's plaintext HTTP request", required=require_host_pcapng)
    normalized = load(root / "analysis" / "normalized.json")
    processes = normalized.get("processes", [])
    root_images = {r.get("image", "").casefold() for r in processes if r.get("pid") == root_pid and r.get("image")}
    check("child_process_tree", any(r.get("parent_pid") == root_pid and r.get("image", "").casefold() in root_images for r in processes))
    child_hash = hashlib.sha256(b"FOXHOLE_HARMLESS_TEST child\n").hexdigest()
    check("created_file_hash", any(contains(r.get("path", ""), token + "-child.txt") and r.get("sha256") == child_hash for r in normalized.get("file_events", [])))
    check("downloaded_file_hash", any(contains(r.get("path", ""), token + "-download.txt")
          and re.fullmatch(r"[0-9a-fA-F]{64}", r.get("sha256") or "") for r in normalized.get("file_events", [])))
    for name, field in (("normalized_files", "file_events"), ("normalized_registry", "registry_events")):
        check(name, any(contains(r, token) for r in normalized.get(field, [])))
    check("normalized_wfp", any(r.get("event_id") in (5152, 5153, 5156, 5157) and r.get("pid") == root_pid
          and r.get("remote_address") == host_ip and r.get("remote_port") == port + 1
          and r.get("correlation", {}).get("target") is True for r in normalized.get("network_attempts", [])))
    stages = normalized.get("detection", {}).get("stages", [])
    for scanner in ("yara", "pe", "capa", "network"):
        rows = [r for r in stages if r.get("scanner") == scanner]
        if scanner != "network":
            rows = [r for r in rows if r.get("target") == "primary"
                    and r.get("target_sha256", "").lower() == sample_hash.lower()]
        check(f"scanner_{scanner}", any(r.get("status") in ("completed", "partial") for r in rows), json.dumps([r.get("status") for r in rows]), required=require_scanners)
    check("yara_marker", any(contains(r.get("findings", []), "foxhole_harmless_test_marker") for r in stages if r.get("scanner") == "yara"), required=require_scanners)
    web = root / "web"
    check("html_pages", (web / "index.html").is_file() and (web / "network.html").is_file())
    script = (web / "data" / "report-data.js").read_text(encoding="utf-8")
    prefix = "window.FOXHOLE_REPORT = JSON.parse("
    if not script.startswith(prefix) or not script.rstrip().endswith(");"):
        raise ValueError("Unexpected report-data wrapper")
    web_data = json.loads(json.loads(script[len(prefix):].rstrip()[:-2]))
    check("html_evidence", web_data["normalized"]["network_attempts"] == normalized["network_attempts"]
          and web_data["normalized"]["file_events"] == normalized["file_events"])
    check("html_capture_view", 'id="capture-health"' in (web / "network.html").read_text(encoding="utf-8"))
    return dict(schema_version=1, token=token, sample_sha256=sample_hash, run_id=run.name,
                passed=all(c["status"] != "fail" for c in checks), checks=checks,
                limitations=["Does not test injection, credential access, destructive behavior, TLS decryption or every supported event.",
                             "Optional not_observed checks are coverage gaps, not passes."])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--token", required=True)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--host-ip", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--require-scanners", action="store_true")
    parser.add_argument("--require-host-pcapng", action="store_true")
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = hashlib.sha256(args.sample.read_bytes()).hexdigest()
        result = verify(args.root, args.token, digest, args.host_ip, args.port,
                        args.require_scanners, args.require_host_pcapng)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = dict(schema_version=1, passed=False, error=str(error), checks=[])
    args.result.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for check in result["checks"]:
        print(f"[{check['status']}] {check['name']}")
        if check["status"] == "fail" and check["detail"]:
            print("  " + check["detail"][:2048])
    if "error" in result:
        print(result["error"])
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
