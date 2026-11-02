#!/usr/bin/env bash
#
# collect_soak_facts.sh — Emit JSON soak gate inputs (target-side; no classifier).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/avc_query.sh
source "${SCRIPT_DIR}/lib/avc_query.sh"

export PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

DOMAIN=""
MARKER_FILE=""
REPORT_FILE=""
MONITOR_BIN="${MONITOR_AVC_BIN:-${SCRIPT_DIR}/monitor_avc.sh}"
MANIFEST=""
VAR_DIR=""
_APP_NAME=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Print JSON facts for soak gate evaluation (run on target; evaluate on controller).

Options:
  --domain NAME       SELinux domain (default: myapp_t)
  --marker-file PATH  Canary deploy epoch file
  --report-file PATH  Deploy report JSON
  --manifest PATH     App manifest for domain-context check
  --var-dir PATH      Application var dir (default: /var/lib/myapp)
  -h, --help          Show help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --app-name|--app) _APP_NAME="$2"; shift 2 ;;
        --marker-file) MARKER_FILE="$2"; shift 2 ;;
        --report-file) REPORT_FILE="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --var-dir) VAR_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "${MANIFEST}" ]]; then
    MANIFEST="$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" resolve --app-name "${_APP_NAME}" 2>/dev/null || true)"
fi

[[ -n "${_APP_NAME}" ]] || { echo "collect_soak_facts: --app-name NAME is required" >&2; exit 2; }
DOMAIN="${DOMAIN:-${_APP_NAME}_t}"
_OPS_DIR="/var/lib/selinux-policy-ops/${_APP_NAME}"
MARKER_FILE="${MARKER_FILE:-${_OPS_DIR}/selinux_canary_deployed_at}"
REPORT_FILE="${REPORT_FILE:-${_OPS_DIR}/selinux_deploy_report.json}"
VAR_DIR="${VAR_DIR:-/var/lib/${_APP_NAME}}"

marker_exists=0
days_elapsed=0
if [[ -f "${MARKER_FILE}" ]]; then
    marker_exists=1
    deploy_epoch="$(tr -d '[:space:]' < "${MARKER_FILE}")"
    if [[ "${deploy_epoch}" =~ ^[0-9]+$ ]]; then
        now_epoch="$(date +%s)"
        days_elapsed=$(( (now_epoch - deploy_epoch) / 86400 ))
    fi
fi

avc_count=-1
avc_net_new_count=-1
avc_fail_closed=0
if [[ -f "${MARKER_FILE}" ]]; then
    MONITOR_ARGS=(--domain "${DOMAIN}" --marker-file "${MARKER_FILE}" --max-avc -1 --show-lines 0 --format json)
    [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]] && MONITOR_ARGS+=(--manifest "${MANIFEST}")
    set +e
    avc_json="$(bash "${MONITOR_BIN}" "${MONITOR_ARGS[@]}" 2>/dev/null)"
    mon_rc=$?
    set -e
    parsed="$(python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    print("BAD")
    raise SystemExit(0)
if not isinstance(data, dict) or "count" not in data:
    print("BAD")
    raise SystemExit(0)
try:
    count = int(data.get("count"))
except (TypeError, ValueError):
    print("BAD")
    raise SystemExit(0)
try:
    net = int(data.get("net_new_count", -1))
except (TypeError, ValueError):
    net = -1
fail = 1 if data.get("avc_fail_closed") or net < 0 else 0
print(f"{count} {net} {fail}")
' <<< "${avc_json}" 2>/dev/null || echo BAD)"
    # Exit 1 with JSON is a threshold failure. Any other non-zero exit, or
    # unparseable JSON, is a crash. Do not substitute count 0.
    if [[ "${parsed}" == "BAD" || ( "${mon_rc}" -ne 0 && "${mon_rc}" -ne 1 ) ]]; then
        avc_count=-1
        avc_net_new_count=-1
        avc_fail_closed=1
    else
        read -r avc_count avc_net_new_count avc_fail_closed <<< "${parsed}"
    fi
fi

report_ok=0
report_status="missing"
if [[ -f "${REPORT_FILE}" ]]; then
    report_status="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1],encoding="utf-8").read()).get("status","fail"))' "${REPORT_FILE}" 2>/dev/null || echo fail)"
    report_ok="$(python3 - "${REPORT_FILE}" "${MANIFEST:-}" <<PY
import json, sys
from pathlib import Path

report = json.loads(open(sys.argv[1], encoding="utf-8").read())
manifest_path = sys.argv[2]
if report.get("status") != "pass":
    print(0)
    raise SystemExit
if not report.get("endpoints_exercised"):
    print(0)
    raise SystemExit
if report.get("domain_context_verified") is True:
    print(1)
    raise SystemExit
if manifest_path and Path(manifest_path).is_file():
    sys.path.insert(0, "${SCRIPT_DIR}/lib")
    from app_manifest import load_manifest, domain_context_matches
    manifest = load_manifest(Path(manifest_path))
    fake = {"domain_context": report.get("domain_context", {})}
    print(1 if domain_context_matches(fake, manifest) else 0)
else:
    ctx = report.get("domain_context", {})
    ok = ctx.get("myapp.service") == "myapp_t" and ctx.get("myapp-backend.service") == "myapp_backend_t"
    print(1 if ok else 0)
PY
)"
fi

if [[ -n "${SOAK_STATE_ROOT:-}" ]]; then
    STATE_ROOT="${SOAK_STATE_ROOT}"
elif [[ "${MARKER_FILE}" == */selinux_canary_deployed_at ]]; then
    STATE_ROOT="$(dirname "$(dirname "${MARKER_FILE}")")"
else
    STATE_ROOT=""
fi

python3 - <<PY
import json
import time
from pathlib import Path

stale = []
root = """${STATE_ROOT}"""
if root:
    cutoff = time.time() - 30 * 86400
    root_path = Path(root)
    if root_path.is_dir():
        for marker in sorted(root_path.glob("*/selinux_canary_deployed_at")):
            text = marker.read_text(encoding="utf-8", errors="replace").strip()
            if text.isdigit():
                opened = int(text)
            else:
                opened = int(marker.stat().st_mtime)
            if opened < cutoff:
                stale.append(str(marker))

print(json.dumps({
    "domain": "${DOMAIN}",
    "marker_file": "${MARKER_FILE}",
    "report_file": "${REPORT_FILE}",
    "marker_exists": ${marker_exists},
    "days_elapsed": ${days_elapsed},
    "avc_count_since_marker": ${avc_count},
    "avc_net_new_count": ${avc_net_new_count},
    "avc_fail_closed": bool(int("${avc_fail_closed}")),
    "report_status": "${report_status}",
    "report_gate_ok": bool(int("${report_ok:-0}")),
    "manifest": "${MANIFEST:-}",
    "stale_canary_markers": stale,
}, indent=2))
PY
