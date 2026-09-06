#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cd -- "${REPO_ROOT}"
echo "[v1_audit] Auditing Cargo.lock for known vulnerabilities"

if ! cargo audit --version >/dev/null 2>&1; then
    echo "[v1_audit] cargo-audit is required; install it with: cargo install cargo-audit --locked" >&2
    exit 127
fi

cargo audit "$@"
