"""Check measured line AND branch coverage, including a nondecreasing Git baseline."""
import argparse
import json
from pathlib import Path
import subprocess


def percentage(covered, count):
    if not count:
        raise ValueError("Coverage instrumentation produced no statements/branches")
    return covered * 100 / count


def metrics(rust, worker):
    data = rust["data"][0]
    totals = data["totals"]
    result = {f"rust_{kind}": percentage(totals[kind]["covered"], totals[kind]["count"]) for kind in ("lines", "branches")}
    critical = [f["summary"] for f in data["files"] if f["filename"].replace("\\", "/").endswith(("/src/detection/validation.rs", "/src/report_analysis/correlation.rs", "/src/report_analysis/publication.rs", "/src/report_analysis/telemetry.rs"))]
    if len(critical) != 4:
        raise ValueError("Missing security-critical Rust instrumentation")
    for kind in ("lines", "branches"):
        result[f"critical_{kind}"] = percentage(sum(s[kind]["covered"] for s in critical), sum(s[kind]["count"] for s in critical))
    totals = worker["totals"]
    result["worker_lines"] = percentage(totals["covered_lines"], totals["num_statements"])
    result["worker_branches"] = percentage(totals["covered_branches"], totals["num_branches"])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=Path("coverage/detection-baseline.json"))
    parser.add_argument("--base-ref", help="Pull-request base commit; read with Git, never executed as shell code")
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    if args.base_ref:
        if not all(c.isalnum() or c in "-_/ ." for c in args.base_ref) or args.base_ref.startswith("-"):
            parser.error("Invalid Git base reference")
        previous = subprocess.run(["git", "show", f"{args.base_ref}:{args.baseline.as_posix()}"], capture_output=True, check=False)
        if previous.returncode == 0:
            old = json.loads(previous.stdout)
            for key, minimum in old["minimum_percent"].items():
                if baseline["minimum_percent"].get(key, -1) < minimum:
                    raise SystemExit(f"Coverage baseline cannot decrease: {key}")
        elif subprocess.run(["git", "cat-file", "-e", f"{args.base_ref}^{{commit}}"], capture_output=True).returncode:
            raise SystemExit("Cannot verify baseline: base commit is unavailable")
    measured = metrics(json.loads(args.rust.read_text(encoding="utf-8")), json.loads(args.worker.read_text(encoding="utf-8")))
    failures = []
    for key, value in measured.items():
        minimum = baseline["minimum_percent"][key]
        print(f"{key}: {value:.2f}% (minimum {minimum:.2f}%)")
        if value < minimum:
            failures.append(key)
    if failures:
        raise SystemExit("Coverage regression: " + ", ".join(failures))


if __name__ == "__main__":
    main()
