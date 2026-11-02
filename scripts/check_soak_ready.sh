#!/usr/bin/env bash
#
# check_soak_ready.sh — Gate production enforce on soak duration + AVC count + deploy coverage
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/avc_query.sh
source "${SCRIPT_DIR}/lib/avc_query.sh"

DOMAIN=""
MARKER_FILE=""
REPORT_FILE=""
MIN_DAYS="${SOAK_MIN_DAYS:-7}"
MAX_AVC="${SOAK_MAX_AVC:-0}"
SKIP_SELINUX="${SKIP_SELINUX:-0}"
AUTO_TIER="${SOAK_AUTO_TIER:-0}"
BASE_POLICY="${SOAK_BASE_POLICY:-}"
CANDIDATE_POLICY="${SOAK_CANDIDATE_POLICY:-}"
APP_DOMAIN=""
BACKEND_DOMAIN=""
CLASSIFY_SCRIPT="${SCRIPT_DIR}/classify_policy_blast_radius.sh"
MANIFEST=""
_APP_NAME=""

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Exit 0 when canary soak period elapsed, domain event count is within threshold,
and last deploy report shows endpoint coverage.

Options:
  --domain NAME         SELinux domain (default: myapp_t)
  --marker-file PATH    Canary deploy timestamp file (epoch seconds)
  --report-file PATH    Deploy report JSON (default: /var/lib/selinux-policy-ops/myapp/selinux_deploy_report.json)
  --min-days N          Minimum soak days (default: 7)
  --max-avc N           Maximum allowed AVC events since canary (default: 0)
  --auto-tier           Set minimum soak from classify_policy_blast_radius.sh (requires base + candidate policy paths)
  --base-policy PATH    Previous module (.pp or .te) for --auto-tier
  --candidate-policy PATH  Candidate module (.pp or .te) for --auto-tier
  --manifest PATH       App manifest for deploy report domain verification
  --skip-if-unavailable Exit 0 when marker or audit tools missing (CI smoke)
  -h, --help            Show help
EOF
}

SKIP_IF_UNAVAILABLE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --app-name|--app) _APP_NAME="$2"; shift 2 ;;
        --marker-file) MARKER_FILE="$2"; shift 2 ;;
        --report-file) REPORT_FILE="$2"; shift 2 ;;
        --min-days) MIN_DAYS="$2"; shift 2 ;;
        --max-avc) MAX_AVC="$2"; shift 2 ;;
        --auto-tier) AUTO_TIER=1; shift ;;
        --base-policy) BASE_POLICY="$2"; shift 2 ;;
        --candidate-policy) CANDIDATE_POLICY="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --skip-if-unavailable) SKIP_IF_UNAVAILABLE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [[ "${SKIP_SELINUX}" == "1" ]]; then
    log_info "SKIP_SELINUX=1 — skipping soak gate"
    exit 0
fi

[[ -n "${_APP_NAME}" ]] || { log_error "--app-name NAME is required"; exit 2; }
DOMAIN="${DOMAIN:-${_APP_NAME}_t}"
APP_DOMAIN="${APP_DOMAIN:-${_APP_NAME}_t}"
BACKEND_DOMAIN="${BACKEND_DOMAIN:-${_APP_NAME}_backend_t}"
_OPS_DIR="/var/lib/selinux-policy-ops/${_APP_NAME}"
MARKER_FILE="${MARKER_FILE:-${_OPS_DIR}/selinux_canary_deployed_at}"
REPORT_FILE="${REPORT_FILE:-${_OPS_DIR}/selinux_deploy_report.json}"

if [[ ! -f "${MARKER_FILE}" ]]; then
    if [[ "${SKIP_IF_UNAVAILABLE}" -eq 1 ]]; then
        log_info "Marker file missing — skipping soak check"
        exit 0
    fi
    log_error "Canary marker not found: ${MARKER_FILE} (run deploy_canary.yml first)"
    exit 1
fi

if [[ "${AUTO_TIER}" == "1" || "${SOAK_AUTO_TIER:-0}" == "1" ]]; then
    configured_floor="${MIN_DAYS}"
    if [[ -z "${BASE_POLICY}" || -z "${CANDIDATE_POLICY}" ]]; then
        log_error "--auto-tier requires --base-policy and --candidate-policy (or SOAK_BASE_POLICY / SOAK_CANDIDATE_POLICY)"
        MIN_DAYS="${configured_floor}"
        log_error "Blast-radius classifier not run — using fail-closed soak minimum ${MIN_DAYS} day(s)"
    elif [[ ! -f "${BASE_POLICY}" || ! -f "${CANDIDATE_POLICY}" ]]; then
        log_error "Policy path missing for --auto-tier (base=${BASE_POLICY}, candidate=${CANDIDATE_POLICY})"
        MIN_DAYS="${configured_floor}"
        log_error "Blast-radius classifier not run — using fail-closed soak minimum ${MIN_DAYS} day(s)"
    else
        classify_json="$(mktemp)"
        classify_err="$(mktemp)"
        if ! bash "${CLASSIFY_SCRIPT}" "${BASE_POLICY}" "${CANDIDATE_POLICY}" >"${classify_json}" 2>"${classify_err}"; then
            log_error "classify_policy_blast_radius.sh failed:"
            cat "${classify_err}" >&2
            MIN_DAYS="${configured_floor}"
            log_error "Blast-radius classifier error — fail-closed soak minimum ${MIN_DAYS} day(s)"
        else
            auto_tier_out="$(python3 - "${classify_json}" "${configured_floor}" <<'PY'
import json, sys
floor = int(sys.argv[2])
try:
    p = json.load(open(sys.argv[1], encoding="utf-8"))
except json.JSONDecodeError:
    print(f"FAIL {floor} unparseable JSON from classifier")
    raise SystemExit
if p.get("fail_closed"):
    print(f"FAIL {floor} {p.get('reason', 'fail-closed')}")
    raise SystemExit
tier = p.get("tier", "")
days = p.get("min_days", floor)
reason = p.get("reason", "")
if tier not in ("low", "medium", "high") or not isinstance(days, int):
    print(f"FAIL {floor} invalid classifier payload")
    raise SystemExit
print(f"OK {days} {tier} {reason}")
PY
)"
            if [[ "${auto_tier_out}" == FAIL* ]]; then
                read -r _ fail_days fail_reason <<< "${auto_tier_out}"
                MIN_DAYS="${fail_days}"
                log_error "Blast-radius classifier fail-closed — using soak minimum ${MIN_DAYS} day(s): ${fail_reason}"
            else
                read -r _ classified_days tier reason <<< "${auto_tier_out}"
                MIN_DAYS="${classified_days}"
                log_info "Blast-radius tier: ${tier} → minimum soak ${MIN_DAYS} day(s)"
                log_info "Classifier reason: ${reason}"
            fi
        fi
        rm -f "${classify_json}" "${classify_err}"
    fi
fi

deploy_epoch="$(tr -d '[:space:]' < "${MARKER_FILE}")"
if ! [[ "${deploy_epoch}" =~ ^[0-9]+$ ]]; then
    log_error "Invalid epoch in marker file: ${MARKER_FILE}"
    exit 1
fi

now_epoch="$(date +%s)"
days_elapsed=$(( (now_epoch - deploy_epoch) / 86400 ))
avc_count="$(count_domain_events_since "${DOMAIN}" "${deploy_epoch}")"

log_info "Soak: ${days_elapsed} day(s) elapsed (minimum ${MIN_DAYS})"
log_info "Events since canary deploy for ${DOMAIN}: ${avc_count} (maximum ${MAX_AVC})"

if [[ "${days_elapsed}" -lt "${MIN_DAYS}" ]]; then
    log_error "Soak period not met — wait $((MIN_DAYS - days_elapsed)) more day(s) or use force_enforce=true (break-glass only)"
    exit 1
fi

if [[ "${avc_count}" == "-1" ]]; then
    if [[ "${SKIP_IF_UNAVAILABLE}" -eq 1 ]]; then
        log_info "Audit tools unavailable — treating event count as 0 for this check"
        avc_count=0
    else
        log_error "Could not determine AVC count (install audit / ensure auditd running)"
        exit 1
    fi
fi

if [[ "${avc_count}" -gt "${MAX_AVC}" ]]; then
    log_error "Too many SELinux events since canary deploy (${avc_count} > ${MAX_AVC})"
    exit 1
fi

if [[ -f "${REPORT_FILE}" ]]; then
    if [[ -z "${MANIFEST}" ]]; then
        MANIFEST="$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" resolve 2>/dev/null || true)"
    fi
    report_ok="$(python3 - "${REPORT_FILE}" "${MANIFEST:-}" <<PY
import json, sys
from pathlib import Path

report = json.loads(open(sys.argv[1], encoding="utf-8").read())
manifest_path = sys.argv[2]

if report.get("status") != "pass":
    print("no")
    raise SystemExit
if not report.get("endpoints_exercised"):
    print("no")
    raise SystemExit
if report.get("domain_context_verified") is True:
    print("yes")
    raise SystemExit
if manifest_path and Path(manifest_path).is_file():
    sys.path.insert(0, "${SCRIPT_DIR}/lib")
    from app_manifest import load_manifest, domain_context_matches
    manifest = load_manifest(Path(manifest_path))
    ctx = report.get("domain_context", {})
    fake = {"domain_context": ctx}
    print("yes" if domain_context_matches(fake, manifest) else "no")
else:
    ctx = report.get("domain_context", {})
    ok = ctx.get("myapp.service") == "${APP_DOMAIN}" and ctx.get("myapp-backend.service") == "${BACKEND_DOMAIN}"
    print("yes" if ok else "no")
PY
)"
    if [[ "${report_ok}" != "yes" ]]; then
        log_error "Deploy report ${REPORT_FILE} missing pass status, endpoint coverage, or domain context (${APP_DOMAIN}/${BACKEND_DOMAIN})"
        exit 1
    fi
    log_info "Deploy report confirms endpoint coverage and domain context"
else
    log_error "Deploy report not found: ${REPORT_FILE}"
    exit 1
fi

log_info "Soak gate passed — safe to enforce ${DOMAIN}"
