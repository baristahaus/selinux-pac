#!/usr/bin/env bash
#
# post_deploy_report.sh — Structured deploy/rollback feedback artifact.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PHASE="${DEPLOY_PHASE:-unknown}"
HOST="$(hostname -s 2>/dev/null || hostname)"
DOMAIN=""
APP_DOMAIN=""
BACKEND_DOMAIN=""
VAR_DIR=""
MARKER_FILE=""
REPORT_FILE=""
MANIFEST=""
APP_NAME=""
POLICY_VERSION_FILE=""
FINDINGS_JSON=""
POLICY_VERSION_OVERRIDE=""
FORCE_ENFORCE=0
SKIP_SOAK_DAYS=0
BREAK_GLASS_REASON="${BREAK_GLASS_REASON:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Write ${VAR_DIR}/selinux_deploy_report.json with deploy health summary.

Options:
  --phase NAME          canary | enforce | rollback (required)
  --host NAME           Host label (default: short hostname)
  --domain NAME         SELinux domain (default: myapp_t)
  --var-dir PATH        Data directory (default: /var/lib/myapp)
  --marker-file PATH    Soak marker for AVC/day calculations
  --report-file PATH    Output JSON path
  --project-root PATH   Repo root for policy version lookup
  --manifest PATH       App manifest YAML (required or --app-name)
  --findings-json PATH  Optional policy_out/findings.json (embeds host_admin_actions booleans)
  --force-enforce       Record that enforce skipped every soak gate
  --skip-soak-days      Record that enforce skipped only the day count and daily history
  --break-glass-reason  Why force_enforce was used (also read from BREAK_GLASS_REASON)
  -h, --help            Show help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --phase) PHASE="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --app-name|--app) APP_NAME="$2"; shift 2 ;;
        --var-dir) VAR_DIR="$2"; shift 2 ;;
        --marker-file) MARKER_FILE="$2"; shift 2 ;;
        --report-file) REPORT_FILE="$2"; shift 2 ;;
        --project-root) PROJECT_ROOT="$2"; shift 2 ;;
        --policy-version) POLICY_VERSION_OVERRIDE="$2"; shift 2 ;;
        --findings-json) FINDINGS_JSON="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --force-enforce) FORCE_ENFORCE=1; shift ;;
        --skip-soak-days) SKIP_SOAK_DAYS=1; shift ;;
        --break-glass-reason) BREAK_GLASS_REASON="$2"; shift 2 ;;
        --break-glass-reason=*) BREAK_GLASS_REASON="${1#--break-glass-reason=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

[[ "${PHASE}" != "unknown" ]] || { log_error "--phase is required"; usage; exit 1; }

if [[ -z "${MANIFEST}" && -n "${APP_NAME}" ]]; then
    MANIFEST="$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" resolve --app-name "${APP_NAME}" 2>/dev/null || true)"
elif [[ -z "${MANIFEST}" ]]; then
    : # No manifest, no app name — will use explicit flags
fi

if [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]]; then
    MANIFEST_JSON="$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" json "${MANIFEST}")"
    APP_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["app_name"])' <<< "${MANIFEST_JSON}")"
    VAR_DIR="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["paths"]["var_dir"])' <<< "${MANIFEST_JSON}")"
    MARKER_FILE="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["deploy"]["soak_marker_file"])' <<< "${MANIFEST_JSON}")"
    REPORT_FILE="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["deploy"]["deploy_report_file"])' <<< "${MANIFEST_JSON}")"
    APP_DOMAIN="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["services"]["primary"]["domain"])' <<< "${MANIFEST_JSON}")"
    BACKEND_BLOCK="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read())["services"].get("backend")))' <<< "${MANIFEST_JSON}")"
    if [[ "${BACKEND_BLOCK}" != "null" ]]; then
        BACKEND_DOMAIN="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["domain"])' <<< "${BACKEND_BLOCK}")"
    fi
fi

policy_version="unknown"
if [[ -n "${POLICY_VERSION_OVERRIDE:-}" ]]; then
    policy_version="${POLICY_VERSION_OVERRIDE}"
elif [[ -f "${POLICY_VERSION_FILE}" ]]; then
    policy_version="$(tr -d '[:space:]' < "${POLICY_VERSION_FILE}")"
fi

selinux_mode="$(getenforce 2>/dev/null || echo unknown)"
domain_permissive="null"
if command -v semanage >/dev/null 2>&1; then
    if semanage permissive -l 2>/dev/null | grep -qw "${DOMAIN}"; then
        domain_permissive="true"
    else
        domain_permissive="false"
    fi
fi

endpoint_tmp="$(mktemp)"
WAIT_ARGS=(--retries 5 --delay 1 --json)
[[ -n "${MANIFEST}" ]] && WAIT_ARGS+=(--manifest "${MANIFEST}")
if ! command -v semanage >/dev/null 2>&1; then
    WAIT_ARGS+=(--skip-domain-check)
fi
if bash "${SCRIPT_DIR}/wait_for_endpoints.sh" "${WAIT_ARGS[@]}" \
    > "${endpoint_tmp}" 2>/dev/null; then
    endpoint_status="pass"
else
    echo '{"status":"fail","endpoints":{},"domain_context":{}}' > "${endpoint_tmp}"
    endpoint_status="fail"
fi

avc_count=0
ignored_count=0
ignored_json='[]'
if [[ -f "${MARKER_FILE}" ]]; then
    MONITOR_ARGS=(--domain "${DOMAIN}" --marker-file "${MARKER_FILE}" --max-avc -1 --show-lines 0 --format json)
    [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]] && MONITOR_ARGS+=(--manifest "${MANIFEST}")
    avc_json="$(bash "${SCRIPT_DIR}/monitor_avc.sh" "${MONITOR_ARGS[@]}" 2>/dev/null || echo '{"count":0,"ignored_count":0,"ignored":[]}')"
    avc_count="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("count",0))' <<< "${avc_json}" 2>/dev/null || echo 0)"
    ignored_count="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("ignored_count",0))' <<< "${avc_json}" 2>/dev/null || echo 0)"
    ignored_json="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()).get("ignored", [])))' <<< "${avc_json}" 2>/dev/null || echo '[]')"
fi

soak_days=0
if [[ -f "${MARKER_FILE}" ]]; then
    deploy_epoch="$(tr -d '[:space:]' < "${MARKER_FILE}")"
    if [[ "${deploy_epoch}" =~ ^[0-9]+$ ]]; then
        now_epoch="$(date +%s)"
        soak_days=$(( (now_epoch - deploy_epoch) / 86400 ))
    fi
fi

overall_status="pass"
if [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]]; then
    if python3 "${SCRIPT_DIR}/lib/app_manifest.py" check-domain-context "${MANIFEST}" "${endpoint_tmp}" >/dev/null 2>&1; then
        domain_ctx_ok=yes
    else
        domain_ctx_ok=no
    fi
else
    domain_ctx_ok="$(python3 - "${endpoint_tmp}" "${APP_DOMAIN}" "${BACKEND_DOMAIN}" <<'PY'
import json, sys
data = json.loads(open(sys.argv[1], encoding="utf-8").read())
app_domain, backend_domain = sys.argv[2], sys.argv[3]
ctx = data.get("domain_context", {})
ok = ctx.get("myapp.service") == app_domain and ctx.get("myapp-backend.service") == backend_domain
print("yes" if ok else "no")
PY
)"
fi

if ! command -v semanage >/dev/null 2>&1 && [[ "${endpoint_status}" == "pass" ]]; then
    domain_ctx_ok=yes
fi

services_ok="$(python3 - "${endpoint_tmp}" "${MANIFEST:-}" <<PY
import json, sys, subprocess
from pathlib import Path

sys.path.insert(0, "${SCRIPT_DIR}/lib")
endpoint = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest_path = sys.argv[2]
services = {}
if manifest_path and Path(manifest_path).is_file():
    from app_manifest import load_manifest, service_roles
    manifest = load_manifest(Path(manifest_path))
    for role, unit in service_roles(manifest):
        try:
            state = subprocess.check_output(
                ["systemctl", "is-active", unit], text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            state = "unknown"
        services[role] = {"unit": unit, "state": state}
else:
    for role, unit in (("primary", "myapp.service"), ("backend", "myapp-backend.service")):
        try:
            state = subprocess.check_output(
                ["systemctl", "is-active", unit], text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            state = "unknown"
        services[role] = {"unit": unit, "state": state}

all_active = all(v["state"] == "active" for v in services.values())
print(json.dumps({"services": services, "all_active": all_active}))
PY
)"
services_all_active="$(python3 -c 'import json,sys; print("yes" if json.loads(sys.stdin.read())["all_active"] else "no")' <<< "${services_ok}")"

if [[ "${services_all_active}" != "yes" || "${endpoint_status}" != "pass" || "${domain_ctx_ok}" != "yes" ]]; then
    overall_status="fail"
fi

mkdir -p "$(dirname "${REPORT_FILE}")"

if [[ "${domain_permissive}" == "true" ]]; then
    domain_permissive_json="true"
elif [[ "${domain_permissive}" == "false" ]]; then
    domain_permissive_json="false"
else
    domain_permissive_json="null"
fi

if [[ -n "${BREAK_GLASS_REASON}" ]]; then
    BREAK_GLASS_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${BREAK_GLASS_REASON}")"
else
    BREAK_GLASS_JSON=None
fi

python3 - "${endpoint_tmp}" "${MANIFEST:-}" "${services_ok}" <<PY
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

endpoint_path = Path("${endpoint_tmp}")
endpoint_data = json.loads(endpoint_path.read_text(encoding="utf-8"))
services_payload = json.loads("""${services_ok}""")
domain_permissive = json.loads("${domain_permissive_json}")
manifest_path = """${MANIFEST:-}"""

domain_context_verified = """${domain_ctx_ok}""" == "yes"

host_admin_actions = []
findings_path = """${FINDINGS_JSON}"""
if findings_path and Path(findings_path).is_file():
    findings_payload = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    if isinstance(findings_payload, dict):
        host_admin_actions = findings_payload.get("host_admin_actions") or []

report = {
    "phase": "${PHASE}",
    "app_name": endpoint_data.get("app_name", "${APP_NAME}"),
    "policy_version": "${policy_version}",
    "host": "${HOST}",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "selinux_mode": "${selinux_mode}",
    "domain": "${DOMAIN}",
    "domain_permissive": domain_permissive,
    "manifest": manifest_path or None,
    "domain_context": endpoint_data.get("domain_context", {}),
    "domain_context_verified": domain_context_verified,
    "services": services_payload.get("services", {}),
    "endpoints": endpoint_data.get("endpoints", {}),
    "endpoints_exercised": endpoint_data.get("status") == "pass",
    "endpoints_all_passed": endpoint_data.get("status") == "pass",
    "avc_count_since_marker": int("${avc_count}"),
    "ignored_count": int("${ignored_count}"),
    "ignored": json.loads("""${ignored_json}"""),
    "soak_days_elapsed": int("${soak_days}"),
    "status": "${overall_status}",
    "host_admin_actions": host_admin_actions,
    "report_file": "${REPORT_FILE}",
    "force_enforce": ${FORCE_ENFORCE} == 1,
    "skip_soak_days": ${SKIP_SOAK_DAYS} == 1,
    "break_glass_reason": ${BREAK_GLASS_JSON},
    "daily_history_bypassed": ${FORCE_ENFORCE} == 1 or ${SKIP_SOAK_DAYS} == 1,
}
Path("${REPORT_FILE}").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
PY

rm -f "${endpoint_tmp}"
chmod 0755 "$(dirname "${REPORT_FILE}")" 2>/dev/null || true
chmod 0644 "${REPORT_FILE}" 2>/dev/null || true

log_info "Wrote deploy report: ${REPORT_FILE} (status=${overall_status})"

[[ "${overall_status}" == "pass" ]]
