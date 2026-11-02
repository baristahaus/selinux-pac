#!/usr/bin/env bash
#
# record_soak_day.sh — Store one soak-monitor JSON under a root-owned state dir.
# Unparseable stdin is stored as a fail-closed day so a crash cannot look like a pass.
#
set -euo pipefail

STATE_DIR=""
DAY=""

usage() {
    echo "Usage: $(basename "$0") --state-dir DIR [--day YYYY-MM-DD]  < monitor.json" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --day) DAY="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "${STATE_DIR}" ]] || { echo "record_soak_day: --state-dir is required" >&2; exit 2; }
if [[ -z "${DAY}" ]]; then
    DAY="$(date -u +%Y-%m-%d)"
fi

mkdir -p "${STATE_DIR}/daily"
chmod 0755 "${STATE_DIR}" "${STATE_DIR}/daily" 2>/dev/null || true

raw="$(mktemp)"
cat >"${raw}"
dest="${STATE_DIR}/daily/${DAY}.json"
python3 - "${raw}" "${dest}" <<'PY'
import json
import sys

src, dest = sys.argv[1], sys.argv[2]
raw = open(src, encoding="utf-8").read()
try:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("not an object")
except (ValueError, json.JSONDecodeError):
    data = {
        "status": "fail",
        "avc_fail_closed": True,
        "net_new_count": -1,
        "count": -1,
        "fail_closed_reason": "monitor output was not JSON",
    }
with open(dest, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY
chmod 0644 "${dest}" 2>/dev/null || true
rm -f "${raw}"
echo "recorded ${dest}"
