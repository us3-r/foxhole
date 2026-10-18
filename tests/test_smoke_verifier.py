"""Negative tests ensure the smoke verifier cannot pass on a successful exit alone."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("smoke", Path(__file__).resolve().parents[1] / "scripts/verify_smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.token = "a" * 32
        self.sha = "b" * 64
        self.guest = self.root / "hyperv/runs/run/collected-artifacts/guest-output"
        self.health = [dict(channel=c, requested=True, started=True, stopped=True) for c in ("host_ndis", "guest_wfp", "guest_pktmon")]
        self.host = dict(target=dict(sha256=self.sha), result=dict(exit_code=0, timed_out=False,
            cleanup=dict(attempted=True, success=True, leftover_resources=[]), capture_health=self.health))
        self.raw = [dict(source="sysmon", event_id=i, data=dict(marker=self.token)) for i in (1, 11, 13)]
        self.raw += [dict(source="windows_filtering_platform", event_id=i, pid=42,
            remote_address="192.168.250.1", remote_port=p, correlation=dict(target=True)) for i, p in ((5156, 8080), (5156, 8081))]
        self.normalized = dict(network_attempts=[self.raw[-1]], file_events=[dict(path=self.token + "-child.txt", sha256=hashlib.sha256(b"FOXHOLE_HARMLESS_TEST child\n").hexdigest())], registry_events=[dict(path=self.token)], processes=[dict(pid=42, image="input/target.bin"), dict(pid=43, parent_pid=42, image="input/target.bin")])
        self.normalized["file_events"].append(dict(path=self.token + "-download.txt", sha256=self.sha))
        attestation = dict(verified=True, nat_enabled=False, host_ipv4="192.168.250.1", no_unexpected_routes=True,
                           firewall_rule_ids=["Foxhole-run-block-outbound", "Foxhole-run-host-service"])
        self.host["backend_metadata"] = dict(network=dict(requested_mode="host_server", host_service_endpoint="http://192.168.250.1:8080",
            pre_run_verification=attestation, post_run_verification=attestation.copy()))
        self.write("reports/host.json", self.host)
        self.write(self.guest / "result.json", dict(execution=dict(pid=42)))
        self.write(self.guest / "extracted-files/telemetry-events.json", self.raw)
        self.write("analysis/normalized.json", self.normalized)
        stdout = f"FOXHOLE_SMOKE_DONE {self.token} failures=0\n"
        for action in ("file_create", "file_rename", "file_delete", "registry", "child_process", "child_completed", "http_download", "unapproved_connection_failed"):
            stdout += json.dumps(dict(action=action, ok=True), separators=(",", ":")) + "\n"
        (self.guest / "stdout.txt").write_text(stdout)
        (self.guest / "stderr.txt").write_text("FOXHOLE_SMOKE_STDERR " + self.token)
        (self.root / "hyperv/runs/run/network-capture.etl").write_bytes(b"fixture")
        (self.root / "web/data").mkdir(parents=True)
        (self.root / "web/index.html").write_text("fixture")
        (self.root / "web/network.html").write_text('<div id="capture-health"></div>')
        (self.root / "web/data/report-data.js").write_text("window.FOXHOLE_REPORT = JSON.parse(" + json.dumps(json.dumps(dict(normalized=self.normalized))) + ");\n")

    def write(self, path, value):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def verify(self, **kwargs):
        return smoke.verify(self.root, self.token, self.sha, "192.168.250.1", 8080, **kwargs)

    def test_complete_required_evidence_passes_but_optional_gaps_remain_visible(self):
        result = self.verify()
        self.assertTrue(result["passed"])
        self.assertTrue(any(c["status"] == "not_observed" for c in result["checks"]))

    def test_exit_zero_without_attributed_attempt_fails(self):
        self.write(self.guest / "extracted-files/telemetry-events.json", self.raw[:-1])
        self.assertFalse(self.verify()["passed"])

    def test_unattributed_or_wrong_process_attempt_cannot_pass(self):
        for field, value in (("pid", 999), ("correlation", dict(target=False))):
            rows = json.loads(json.dumps(self.raw))
            rows[-1][field] = value
            self.write(self.guest / "extracted-files/telemetry-events.json", rows)
            self.assertFalse(self.verify()["passed"])

    def test_missing_host_attestation_fails(self):
        self.host["backend_metadata"]["network"]["post_run_verification"]["verified"] = False
        self.write("reports/host.json", self.host)
        self.assertFalse(self.verify()["passed"])

    def test_unrelated_child_does_not_satisfy_fixture_ancestry(self):
        self.normalized["processes"][-1]["image"] = "conhost.exe"
        self.write("analysis/normalized.json", self.normalized)
        self.assertFalse(self.verify()["passed"])

    def test_capture_loss_fails(self):
        self.health[1]["loss_detected"] = True
        self.write("reports/host.json", self.host)
        self.assertFalse(self.verify()["passed"])

    def test_optional_process_evidence_uses_pid_after_executable_is_renamed(self):
        self.raw += [dict(source="sysmon", event_id=10, data=dict(SourceProcessId="42", SourceImage="input/target.bin")),
                     dict(source="sysmon", event_id=7, data=dict(ProcessId="99", ImageLoaded="version.dll"))]
        self.write(self.guest / "extracted-files/telemetry-events.json", self.raw)
        checks = {r["name"]: r["status"] for r in self.verify()["checks"]}
        self.assertEqual(checks["process_access"], "pass")
        self.assertEqual(checks["image_load"], "not_observed")

    def test_cleanup_failure_and_hash_mismatch_fail(self):
        self.host["result"]["cleanup"]["success"] = False
        self.host["target"]["sha256"] = "c" * 64
        self.write("reports/host.json", self.host)
        self.assertFalse(self.verify()["passed"])

    def test_strict_scanners_and_host_capture_require_real_evidence(self):
        self.assertFalse(self.verify(require_scanners=True)["passed"])
        self.assertFalse(self.verify(require_host_pcapng=True)["passed"])

    def test_completed_scanner_results_must_match_the_primary_sample(self):
        stages = [dict(scanner=s, status="completed", target="primary", target_sha256=self.sha,
                       findings=[dict(rule_id="foxhole_harmless_test_marker")]) for s in ("yara", "pe", "capa", "network")]
        self.normalized["detection"] = dict(stages=stages)
        self.write("analysis/normalized.json", self.normalized)
        self.assertTrue(self.verify(require_scanners=True)["passed"])
        stages[2]["target_sha256"] = "c" * 64
        self.write("analysis/normalized.json", self.normalized)
        self.assertFalse(self.verify(require_scanners=True)["passed"])

    def test_html_without_matching_evidence_fails(self):
        data = dict(normalized=dict(network_attempts=[], file_events=[]))
        (self.root / "web/data/report-data.js").write_text("window.FOXHOLE_REPORT = JSON.parse(" + json.dumps(json.dumps(data)) + ");\n")
        self.assertFalse(self.verify()["passed"])


if __name__ == "__main__":
    unittest.main()
