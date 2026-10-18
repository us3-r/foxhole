"""Only synthetic, harmless bytes are parsed. Nothing in this suite executes a PE."""
import copy
import gc
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch
import random
import struct
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("worker", ROOT / "guest-agent/assets/detection_worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
LIMITS = dict(timeout_seconds=60, memory_bytes=536870912, input_bytes=33554432, output_bytes=4194304,
              findings=512, strings=2048, string_bytes=2048, match_bytes=64, offsets=256,
              features=256, depth=16, rules=10000, files=32, packets=100000, flows=4096)


def benign_pe():
    data = bytearray(1536)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x14c, 1, 0, 0, 0, 224, 0x102)
    struct.pack_into("<H", data, 152, 0x10b)
    for offset, value in [(16, 0x1000), (20, 0x1000), (28, 0x400000), (32, 0x1000), (36, 0x200),
                          (56, 0x2000), (60, 0x200), (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)]:
        struct.pack_into("<I", data, 152 + offset, value)
    struct.pack_into("<H", data, 152 + 68, 3)
    struct.pack_into("<II", data, 152 + 104, 0x1100, 40)
    struct.pack_into("<8sIIIIIIHHI", data, 376, b".text\0\0\0", 1024, 0x1000, 1024, 512, 0, 0, 0, 0, 0x60000020)
    data[512:521] = b"\x6a\x00\xff\x15\x80\x11\x40\x00\xc3"
    struct.pack_into("<IIIII", data, 768, 0x1140, 0, 0, 0x1160, 0x1180)
    struct.pack_into("<I", data, 832, 0x1190)
    data[864:877] = b"KERNEL32.dll\0"
    struct.pack_into("<I", data, 896, 0x1190)
    data[914:926] = b"ExitProcess\0"
    marker = b"FOXHOLE_HARMLESS_TEST\0https://example.com/fixture\0aHR0cHM6Ly9leGFtcGxlLm9yZy8=\0"
    data[1024:1024 + len(marker)] = marker
    return bytes(data)


def block(kind, body):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def ip_packet(payload, protocol, sport, dport, source=b"\x0a\0\0\x02", destination=b"\x01\x01\x01\x01"):
    if protocol == 17:
        transport = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0)
    else:
        transport = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 1024, 0, 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport) + len(payload), 0, 0, 64, protocol, 0, source, destination)
    return b"\0" * 12 + b"\x08\x00" + header + transport + payload


def capture():
    question = b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
    dns = struct.pack("!6H", 1, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x01\x01\x01"
    sni = b"example.com"
    extbody = struct.pack("!H", len(sni) + 3) + b"\0" + struct.pack("!H", len(sni)) + sni
    extension = struct.pack("!HH", 0, len(extbody)) + extbody
    hello = b"\x03\x03" + b"\0" * 32 + b"\0\0\x02\x13\x01\x01\0" + struct.pack("!H", len(extension)) + extension
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    tls = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    packets = [ip_packet(dns, 17, 53, 50000), ip_packet(b"GET /fixture HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Foxhole/1.0\r\n\r\n", 6, 50001, 80), ip_packet(tls, 6, 50002, 443)]
    result = block(0x0a0d0d0a, struct.pack("<IHHq", 0x1a2b3c4d, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535))
    for index, packet in enumerate(packets):
        result += block(6, struct.pack("<5I", 0, 0, 1000000 + index * 1000, len(packet), len(packet)) + packet)
    return result


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(gc.collect)
        self.root = Path(self.tmp.name)
        self.sample = self.root / "harmless.exe"
        self.sample.write_bytes(benign_pe())
        self.yara = self.root / "rules.yar"
        self.yara.write_text('rule harmless_marker { meta: description = "Harmless fixture" strings: $a = "FOXHOLE_HARMLESS_TEST" condition: $a }', encoding="utf-8")
        self.rules = self.root / "packet.json"
        self.rules.write_text(json.dumps(dict(schema_version=1, rules=[dict(id="foxhole_test_domain", field="http_host", equals="example.com")])))
        self.capa = self.root / "capa.zip"
        with zipfile.ZipFile(self.capa, "w") as z:
            z.writestr(zipfile.ZipInfo("harmless.yml", (2020, 1, 1, 0, 0, 0)), 'rule:\n  meta:\n    name: import harmless exit function\n    namespace: foxhole/test\n    authors: [Foxhole]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - import: kernel32.ExitProcess\n')

    def request(self, stage):
        path = self.rules if stage == "network" else self.capa if stage == "capa" else self.yara
        config = dict(enabled=True, executable=None, executable_sha256=None, user_rules=None, limits=copy.deepcopy(LIMITS),
                      rules=dict(id="foxhole-test", version="1", path=str(path), sha256=worker.digest(path.read_bytes())))
        return dict(stage=stage, config=config, target="primary", target_sha256=worker.digest(self.sample.read_bytes()), path=str(self.sample))

    def test_yara_real_engine_compile_scan_and_metadata(self):
        r = worker.analyze(self.request("yara"))
        self.assertEqual(r["status"], "completed", r)
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["findings"][0]["locations"][0]["offset"], 1024)

    def test_yara_bad_rules_integrity_and_offsets(self):
        request = self.request("yara")
        request["config"]["rules"]["sha256"] = "00" * 32
        self.assertEqual(worker.analyze(request)["status"], "invalid_output")
        self.yara.write_text("malformed yara")
        self.assertEqual(worker.analyze(self.request("yara"))["status"], "invalid_output")
        self.yara.write_text('include "outside.yar"\nrule x {condition:true}')
        self.assertEqual(worker.analyze(self.request("yara"))["status"], "invalid_output")

    def test_pe_metadata_imports_sections_and_strings(self):
        r = worker.analyze(self.request("pe"))
        self.assertIsNotNone(r["pe"], r)
        self.assertEqual(r["pe"]["architecture"], "x86")
        self.assertIn("KERNEL32.dll!ExitProcess", r["pe"]["imports"])
        self.assertEqual(r["pe"]["sections"][0]["permissions"], "RX")
        self.assertTrue(any(s["method"] == "base64" for s in r["strings"]))
        self.assertEqual(r["pe"]["authenticode_status"], "unsigned")

    def test_capa_real_json_capability(self):
        r = worker.analyze(self.request("capa"))
        self.assertEqual(r["status"], "completed", r)
        self.assertEqual(r["findings"][0]["rule"], "import harmless exit function")
        self.assertTrue(r["findings"][0]["features"])

    def test_network_dns_http_tls_and_alert(self):
        self.sample.write_bytes(capture())
        r = worker.analyze(self.request("network"))
        self.assertEqual(len(r["packets"]), 3, r)
        self.assertEqual(r["packets"][0]["dns_answers"], ["1.1.1.1"])
        self.assertEqual(r["packets"][1]["http_host"], "example.com")
        self.assertEqual(r["packets"][2]["tls_sni"], "example.com")
        self.assertIn("ja3", r["packets"][2]["tls"])
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["status"], "partial")

    def test_malformed_truncated_empty_and_packet_budgets(self):
        for data in [b"", b"bad capture", capture()[:-7]]:
            self.sample.write_bytes(data)
            self.assertNotEqual(worker.analyze(self.request("network"))["status"], "completed")
        self.sample.write_bytes(capture())
        request = self.request("network")
        request["config"]["limits"]["packets"] = 1
        r = worker.analyze(request)
        self.assertEqual(len(r["packets"]), 1)
        self.assertTrue(r["truncated"])
        request["config"]["limits"]["packets"] = 100
        request["config"]["limits"]["flows"] = 1
        self.assertTrue(worker.analyze(request)["truncated"])

    def test_missing_hash_mismatch_input_and_string_limits(self):
        for stage in worker.VERSIONS:
            req = self.request(stage)
            req["target_sha256"] = "00" * 32
            self.assertEqual(worker.analyze(req)["status"], "invalid_output")
            req["path"] = str(self.root / "missing")
            self.assertEqual(worker.analyze(req)["status"], "unavailable")
            req = self.request(stage)
            req["config"]["limits"]["input_bytes"] = 1
            self.assertEqual(worker.analyze(req)["status"], "partial")
        req = self.request("pe")
        req["config"]["limits"]["strings"] = 1
        result = worker.analyze(req)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["strings"]), 1)

    def test_unsupported_formats_and_capa_zip_traversal(self):
        self.sample.write_bytes(b"harmless script example.com")
        for stage in ["pe", "capa"]:
            self.assertEqual(worker.analyze(self.request(stage))["status"], "skipped")
        self.sample.write_bytes(benign_pe())
        with zipfile.ZipFile(self.capa, "w") as z:
            z.writestr("../outside.yml", "rule: invalid")
        self.assertEqual(worker.analyze(self.request("capa"))["status"], "invalid_output")
        self.assertFalse((self.root.parent / "outside.yml").exists())

    def test_bounded_json_negative_and_fuzz_properties(self):
        for value in [b'{"a":1,"a":2}', b"[" * 80 + b"]" * 80, b'"' + b"x" * 4097 + b'"']:
            with self.assertRaises((ValueError, RecursionError)):
                worker.bounded_json(value, LIMITS)
        rng = random.Random(1928)
        for size in range(256):
            self.sample.write_bytes(rng.randbytes(size))
            for stage in ["pe", "network"]:
                r = worker.analyze(self.request(stage))
                self.assertIn(r["status"], ("skipped", "invalid_output", "partial"))
                self.assertLess(len(json.dumps(r)), LIMITS["output_bytes"])

    def test_golden_outputs_are_stable(self):
        directory = ROOT / "tests/fixtures/detection"
        actual = {}
        original_parser = worker.capa_document
        def record_native(doc, config, result):
            sanitized = copy.deepcopy(doc)
            sanitized["meta"]["timestamp"] = "2020-01-01T00:00:00"
            sanitized["meta"]["argv"] = None
            sanitized["meta"]["sample"]["path"] = "harmless.exe"
            sanitized["meta"]["analysis"]["rules"] = ["foxhole-test"]
            actual["capa-native.json"] = json.dumps(sanitized, sort_keys=True, indent=2) + "\n"
            return original_parser(doc, config, result)
        for stage in ["yara", "pe", "capa", "network"]:
            gc.collect()
            self.sample.write_bytes(capture() if stage == "network" else benign_pe())
            with patch.object(worker, "capa_document", record_native):
                r = worker.analyze(self.request(stage))
            r["duration_ms"] = None
            actual[stage + ".json"] = json.dumps(r, sort_keys=True, indent=2) + "\n"
            if stage == "pe":
                actual["pe-metadata.json"] = json.dumps(r["pe"], sort_keys=True, indent=2) + "\n"
                actual["decoded-strings.json"] = json.dumps(r["strings"], sort_keys=True, indent=2) + "\n"
        if os.environ.get("FOXHOLE_UPDATE_DETECTION_GOLDENS") == "1":
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "benign.pe.bin").write_bytes(benign_pe())
            (directory / "network.pcapng").write_bytes(capture())
            for name, content in actual.items():
                (directory / name).write_text(content, encoding="utf-8")
        for name, content in actual.items():
            self.assertEqual((directory / name).read_text(encoding="utf-8"), content, name)

    def test_native_capa_schema_versions_hashes_and_depth_are_rejected(self):
        native = json.loads((ROOT / "tests/fixtures/detection/capa-native.json").read_text())
        request = self.request("capa")
        result = worker.analyze(request)
        for mutate in [lambda d: d["meta"].update(version="unknown"), lambda d: d["meta"]["sample"].update(sha256="00" * 32), lambda d: d.update(unknown=True)]:
            altered = copy.deepcopy(native)
            mutate(altered)
            with self.assertRaises(ValueError):
                worker.capa_document(altered, request["config"], result)

    def test_pe_boundary_signature_tls_callbacks_and_embedded_metadata(self):
        data = bytearray(benign_pe())
        # TLS directory within the synthetic section, with one callback then sentinel.
        struct.pack_into("<II", data, 152 + 96 + 9 * 8, 0x1200, 24)
        struct.pack_into("<6I", data, 1024, 0, 0, 0, 0x401230, 0, 0)
        struct.pack_into("<II", data, 1072, 0x401000, 0)
        self.sample.write_bytes(data)
        result = worker.analyze(self.request("pe"))
        self.assertEqual(result["pe"]["tls_callbacks"], [0x401000])
        struct.pack_into("<I", data, 376 + 16, 0xffffffff)
        self.sample.write_bytes(data)
        self.assertEqual(worker.analyze(self.request("pe"))["status"], "invalid_output")
        self.assertEqual(worker.authenticode_offline(None), "verification_unavailable")

    def test_duplicate_alerts_rule_limits_and_unknown_network_schema(self):
        self.sample.write_bytes(capture())
        request = self.request("network")
        request["config"]["limits"]["rules"] = 1
        rules = json.loads(self.rules.read_text())
        rules["rules"].append(dict(id="second", field="http_host", equals="example.com"))
        self.rules.write_text(json.dumps(rules))
        request = self.request("network")
        request["config"]["limits"]["rules"] = 1
        self.assertEqual(worker.analyze(request)["status"], "partial")
        rules["schema_version"] = 9
        self.rules.write_text(json.dumps(rules))
        self.assertEqual(worker.analyze(self.request("network"))["status"], "invalid_output")

    def test_capa_and_yara_engine_mismatch_and_malformed_json_are_visible(self):
        import yara
        with patch.object(yara, "__version__", "unknown"):
            self.assertEqual(worker.analyze(self.request("yara"))["status"], "invalid_output")
        with patch.object(worker.importlib.metadata, "version", return_value="unknown"):
            self.assertEqual(worker.analyze(self.request("capa"))["status"], "invalid_output")
        with self.assertRaises(ValueError):
            worker.bounded_json(b"not json", LIMITS)

    def test_offline_signature_and_visible_tls_certificate(self):
        from datetime import datetime, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        if os.name == "nt":
            self.assertEqual(worker.authenticode_offline(self.sample), "unsigned")
            import ctypes
            from types import SimpleNamespace
            calls = []
            def verify(_window, _action, pointer):
                trust = pointer._obj
                calls.append(trust.state_action)
                self.assertEqual(trust.flags & 0x1000, 0x1000, "certificate validation must forbid online retrieval")
                self.assertEqual(trust.flags & 0x10, 0x10)
                self.assertEqual(trust.ui, 2, "scanner must never show a trust dialog")
                return 0
            with patch.object(ctypes, "WinDLL", return_value=SimpleNamespace(WinVerifyTrust=verify)):
                self.assertEqual(worker.authenticode_offline(self.sample), "valid_offline_trust")
            self.assertEqual(calls, [1, 2], "trust provider state must be closed")
        key = ec.derive_private_key(7, ec.SECP256R1())  # public fixture key, never used as a credential
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.invalid")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc)).sign(key, hashes.SHA256()))
        der = cert.public_bytes(serialization.Encoding.DER)
        chain = (len(der) + 3).to_bytes(3, "big") + len(der).to_bytes(3, "big") + der
        handshake = b"\x0b" + len(chain).to_bytes(3, "big") + chain
        record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
        item = {"tls": {}}
        worker.tls_metadata(record, item)
        self.assertEqual(item["tls"]["certificate_sha256"], hashlib.sha256(der).hexdigest())
        self.assertEqual(item["tls"]["certificate_subject"], "CN=example.invalid")
        with self.assertRaises(ValueError):
            worker.tls_metadata(record[:-1], {"tls": {}})

    def test_rule_match_and_output_budgets_are_visible(self):
        self.yara.write_text('rule a { strings: $a="FOXHOLE" condition: $a }\nrule b {condition: true}')
        request = self.request("yara")
        request["config"]["limits"]["findings"] = 1
        result = worker.analyze(request)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["status"], "partial")
        request["config"]["limits"]["rules"] = 1
        self.assertEqual(worker.analyze(request)["status"], "partial")
        with self.assertRaises(worker.LimitError):
            worker.OutputBuffer(4).write("12345")
        self.assertEqual(worker.OutputBuffer(4).write("1234"), 4)


if __name__ == "__main__":
    unittest.main()
