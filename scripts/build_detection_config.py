"""Build a reviewable offline guest configuration and deterministic capa rule ZIP.

Only administrator-owned scanner/rule inputs are read; samples are never processed here.
"""
import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-binary", type=Path, required=True, help="Local copy of the exact guest python.exe to hash")
    parser.add_argument("--guest-python", required=True, help="Absolute guest path to that interpreter")
    parser.add_argument("--guest-rules", required=True, help="Absolute guest directory where these rule packs will be installed")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for value in [args.guest_python, args.guest_rules]:
        if not PureWindowsPath(value).is_absolute() or ".." in PureWindowsPath(value).parts:
            parser.error("Guest paths must be absolute without traversal")
    archive = ROOT / "rules/foxhole-capa-1.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zipped:
        for path in sorted((ROOT / "rules/capa").glob("*.yml")):
            zipped.writestr(zipfile.ZipInfo(path.name, (2020, 1, 1, 0, 0, 0)), path.read_bytes().replace(b"\r\n", b"\n"))
    def pack(name):
        path = ROOT / "rules" / name
        return dict(id=path.stem, version="1", path=str(PureWindowsPath(args.guest_rules) / name), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    config = dict(schema_version=1, behavioral=True)
    for stage, rules in [("yara", "foxhole-yara-1.yar"), ("capa", "foxhole-capa-1.zip"), ("network", "foxhole-packet-1.json"), ("pe", None)]:
        config[stage] = dict(enabled=True, executable=args.guest_python, executable_sha256=hashlib.sha256(args.python_binary.read_bytes()).hexdigest())
        if rules:
            config[stage]["rules"] = pack(rules)
    args.output.write_text(json.dumps(config, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
