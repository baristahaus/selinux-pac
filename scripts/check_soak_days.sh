#!/usr/bin/env bash
#
# check_soak_days.sh — Require consecutive passing daily soak files.
# A clean re-read of audit.log does not erase a stored failure.
# --min-days 0 succeeds with no files (lab inventory).
#
set -euo pipefail

STATE_DIR=""
MIN_DAYS=7
MAX_NET_NEW=0
TODAY=""

usage() {
    echo "Usage: $(basename "$0") --state-dir DIR [--min-days N] [--max-net-new N] [--today YYYY-MM-DD]" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --min-days) MIN_DAYS="$2"; shift 2 ;;
        --max-net-new) MAX_NET_NEW="$2"; shift 2 ;;
        --today) TODAY="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "${STATE_DIR}" ]] || { echo "check_soak_days: --state-dir is required" >&2; exit 2; }
if [[ -z "${TODAY}" ]]; then
    TODAY="$(date -u +%Y-%m-%d)"
fi

python3 - "${STATE_DIR}" "${MIN_DAYS}" "${MAX_NET_NEW}" "${TODAY}" <<'PY'
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

state_dir = Path(sys.argv[1])
min_days = int(sys.argv[2])
max_net_new = int(sys.argv[3])
today = datetime.strptime(sys.argv[4], "%Y-%m-%d").date()

if min_days <= 0:
    print("soak daily history not required (min-days 0)")
    raise SystemExit(0)

marker = None
marker_path = state_dir / "selinux_canary_deployed_at"
if marker_path.is_file():
    raw_marker = marker_path.read_text(encoding="utf-8").strip()
    if raw_marker.isdigit():
        marker = int(raw_marker)


def record_epoch(path: Path, record: dict) -> int:
    for key in ("marker_epoch", "since"):
        value = record.get(key)
        if isinstance(value, int) or (isinstance(value, str) and str(value).isdigit()):
            return int(value)
    return int(path.stat().st_mtime)


files = {}
daily = state_dir / "daily"
if daily.is_dir():
    for path in daily.glob("*.json"):
        try:
            day = datetime.strptime(path.stem, "%Y-%m-%d").date()
        except ValueError:
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                raise ValueError("not an object")
        except (json.JSONDecodeError, ValueError):
            record = {"status": "fail", "avc_fail_closed": True, "net_new_count": -1}
        if marker is not None and record_epoch(path, record) < marker:
            continue
        files[day] = record

if not files:
    print("Soak daily history not met: no daily results", file=sys.stderr)
    raise SystemExit(1)

newest = max(files)
if (today - newest).days > 1:
    print(
        f"Soak daily history not met: newest result {newest.isoformat()} is older than one day",
        file=sys.stderr,
    )
    raise SystemExit(1)

def passes(record: dict) -> bool:
    if record.get("avc_fail_closed"):
        return False
    if record.get("status") == "fail":
        return False
    try:
        net = int(record.get("net_new_count", -1))
    except (TypeError, ValueError):
        return False
    return 0 <= net <= max_net_new

for offset in range(min_days):
    day = newest - timedelta(days=offset)
    record = files.get(day)
    if record is None:
        print(f"Soak daily history not met: missing {day.isoformat()}", file=sys.stderr)
        raise SystemExit(1)
    if not passes(record):
        print(f"Soak daily history not met: {day.isoformat()} did not pass", file=sys.stderr)
        raise SystemExit(1)

print(f"soak daily history passed ({min_days} consecutive days ending {newest.isoformat()})")
PY
