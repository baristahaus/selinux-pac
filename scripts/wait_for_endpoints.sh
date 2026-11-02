#!/usr/bin/env bash
#
# wait_for_endpoints.sh — Unified service + HTTP endpoint readiness checks.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOST="127.0.0.1"
HTTP_PORT=8091
RETRIES=15
DELAY=2
JSON=0
CHECK_SYSTEMD=1
CHECK_DOMAIN=1
MANIFEST=""
APP_NAME="shopapi"
APP_DOMAIN=""
BACKEND_DOMAIN=""
PRIMARY_SERVICE="shopapi.service"
BACKEND_SERVICE=""
HAS_BACKEND=0
BACKEND_HTTP_PORT=0
BACKEND_HEALTH_PATH="/health"
ENDPOINTS=(
    /health
    /state
    /log
)

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Wait for application systemd units and HTTP endpoints from app manifest or defaults.
Verifies each service MainPID runs in the expected SELinux domain.

Options:
  --manifest PATH     App manifest YAML
  --app-name NAME     App name for default manifest lookup
  --host HOST         HTTP host (overrides manifest)
  --retries N         Attempts per check (default: 15)
  --delay SEC         Seconds between attempts (default: 2)
  --json              Print JSON result on stdout
  --skip-systemd      Skip systemctl active checks
  --skip-domain-check Skip SELinux domain verification
  --app-domain TYPE   Override expected primary domain
  --backend-domain TYPE Override expected backend domain
  -h, --help          Show help

Exit codes:
  0  all checks passed
  1  systemd service not active
  2  endpoint HTTP failure
  3  timeout / usage
  4  SELinux domain mismatch
EOF
}

load_manifest_config() {
    local manifest_path="$1"
    if [[ ! -f "${manifest_path}" ]]; then
        log_info "Manifest not found (${manifest_path}) — using built-in shopapi defaults"
        return 0
    fi
    log_info "Loading app manifest: ${manifest_path}"
    # shellcheck disable=SC1090
    eval "$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" shell-export "${manifest_path}")"
    APP_NAME="${APP_NAME}"
    HOST="${HTTP_HOST}"
    HTTP_PORT="${HTTP_PORT}"
    APP_DOMAIN="${APP_DOMAIN}"
    PRIMARY_SERVICE="${PRIMARY_SERVICE}"
    mapfile -t ENDPOINTS < <(python3 -c 'import json,sys; [print(p) for p in json.loads(sys.argv[1])]' "${ENDPOINT_PATHS}")
    if [[ "${HAS_BACKEND}" == "1" ]]; then
        BACKEND_DOMAIN="${BACKEND_DOMAIN}"
        BACKEND_SERVICE="${BACKEND_SERVICE}"
        BACKEND_HTTP_PORT="${BACKEND_HTTP_PORT}"
        BACKEND_HEALTH_PATH="${BACKEND_HEALTH_PATH}"
    else
        HAS_BACKEND=0
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --retries) RETRIES="$2"; shift 2 ;;
        --delay) DELAY="$2"; shift 2 ;;
        --json) JSON=1; shift ;;
        --skip-systemd) CHECK_SYSTEMD=0; shift ;;
        --skip-domain-check) CHECK_DOMAIN=0; shift ;;
        --app-domain) APP_DOMAIN="$2"; shift 2 ;;
        --backend-domain) BACKEND_DOMAIN="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 3 ;;
    esac
done

if [[ -z "${MANIFEST}" ]]; then
    MANIFEST="$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" resolve 2>/dev/null || true)"
fi
if [[ -n "${MANIFEST}" ]]; then
    load_manifest_config "${MANIFEST}"
fi

wait_systemd() {
    local unit="$1"
    local attempt
    for ((attempt = 1; attempt <= RETRIES; attempt++)); do
        if systemctl is-active --quiet "${unit}" 2>/dev/null; then
            return 0
        fi
        sleep "${DELAY}"
    done
    log_error "systemd unit not active: ${unit}"
    systemctl status "${unit}" --no-pager 2>/dev/null | head -15 || true
    return 1
}

service_domain() {
    local unit="$1"
    local pid ctx

    pid="$(systemctl show -p MainPID --value "${unit}" 2>/dev/null || echo 0)"
    if [[ -z "${pid}" || "${pid}" -le 0 ]]; then
        echo "unknown"
        return 1
    fi
    ctx="$(ps -o label= -p "${pid}" 2>/dev/null | awk '{print $1}' | awk -F: '{print $3}')"
    if [[ -z "${ctx}" ]]; then
        echo "unknown"
        return 1
    fi
    echo "${ctx}"
}

verify_service_domain() {
    local unit="$1"
    local expected="$2"
    local observed attempt

    for ((attempt = 1; attempt <= RETRIES; attempt++)); do
        observed="$(service_domain "${unit}" || true)"
        if [[ "${observed}" == "${expected}" ]]; then
            log_info "${unit} running as ${expected} (pid domain verified)"
            echo "${observed}"
            return 0
        fi
        sleep "${DELAY}"
    done

    log_error "FATAL: ${unit} running as ${observed:-unknown}, not ${expected}"
    local pid
    pid="$(systemctl show -p MainPID --value "${unit}" 2>/dev/null || echo 0)"
    log_error "${unit} MainPID=${pid}"
    systemctl status "${unit}" --no-pager 2>/dev/null | head -20 || true
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u "${unit}" -n 20 --no-pager 2>/dev/null || true
    fi
    return 4
}

wait_http() {
    local path="$1"
    local url="http://${HOST}:${HTTP_PORT}${path}"
    local attempt code
    for ((attempt = 1; attempt <= RETRIES; attempt++)); do
        code="$(curl -sf -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || echo "000")"
        if [[ "${code}" == "200" ]]; then
            ENDPOINT_CODES["${path}"]=200
            return 0
        fi
        ENDPOINT_CODES["${path}"]="${code}"
        sleep "${DELAY}"
    done
    log_error "endpoint not ready: ${path} (last HTTP ${code})"
    return 2
}

wait_backend_health() {
    local attempt code
    local url="http://${HOST}:${BACKEND_HTTP_PORT}${BACKEND_HEALTH_PATH}"
    for ((attempt = 1; attempt <= RETRIES; attempt++)); do
        code="$(curl -sf -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || echo "000")"
        if [[ "${code}" == "200" ]]; then
            return 0
        fi
        sleep "${DELAY}"
    done
    log_error "backend health not ready at ${url} (last HTTP ${code})"
    return 2
}

declare -A ENDPOINT_CODES=()
declare -A SERVICE_STATUS=()
declare -A DOMAIN_CONTEXT=()
APP_DOMAIN_OBSERVED="unknown"
BACKEND_DOMAIN_OBSERVED="unknown"

SYSTEMD_UNITS=()
if [[ "${HAS_BACKEND}" == "1" ]]; then
    SYSTEMD_UNITS=("${BACKEND_SERVICE}" "${PRIMARY_SERVICE}")
else
    SYSTEMD_UNITS=("${PRIMARY_SERVICE}")
fi

if [[ "${CHECK_SYSTEMD}" -eq 1 ]]; then
    for unit in "${SYSTEMD_UNITS[@]}"; do
        if ! wait_systemd "${unit}"; then
            SERVICE_STATUS["${unit}"]="inactive"
            if [[ "${JSON}" -eq 1 ]]; then
                python3 -c "import json; print(json.dumps({'status':'fail','reason':'systemd','services':{'${unit}':'inactive'}}, indent=2))"
            fi
            exit 1
        fi
        SERVICE_STATUS["${unit}"]="active"
    done
fi

if [[ "${CHECK_DOMAIN}" -eq 1 ]]; then
    if [[ "${HAS_BACKEND}" == "1" ]]; then
        if ! BACKEND_DOMAIN_OBSERVED="$(verify_service_domain "${BACKEND_SERVICE}" "${BACKEND_DOMAIN}")"; then
            exit 4
        fi
        DOMAIN_CONTEXT["${BACKEND_SERVICE}"]="${BACKEND_DOMAIN_OBSERVED}"
    fi
    if ! APP_DOMAIN_OBSERVED="$(verify_service_domain "${PRIMARY_SERVICE}" "${APP_DOMAIN}")"; then
        exit 4
    fi
    DOMAIN_CONTEXT["${PRIMARY_SERVICE}"]="${APP_DOMAIN_OBSERVED}"
fi

if [[ "${HAS_BACKEND}" == "1" ]]; then
    if ! wait_backend_health; then
        [[ "${JSON}" -eq 1 ]] && python3 -c 'import json; print(json.dumps({"status":"fail","reason":"backend_health"}, indent=2))'
        exit 2
    fi
fi

for path in "${ENDPOINTS[@]}"; do
    if ! wait_http "${path}"; then
        if [[ "${JSON}" -eq 1 ]]; then
            ENDPOINTS_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${ENDPOINTS[@]}")"
            python3 - "${ENDPOINTS_JSON}" <<'PY'
import json, sys
paths = json.loads(sys.argv[1])
print(json.dumps({"status": "fail", "reason": "endpoint", "endpoints": {p: "000" for p in paths}}, indent=2))
PY
        fi
        exit 2
    fi
done

log_info "All endpoints ready on ${HOST}:${HTTP_PORT} (${#ENDPOINTS[@]} checks)"

if [[ "${JSON}" -eq 1 ]]; then
    ENDPOINTS_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${ENDPOINTS[@]}")"
    python3 - "${ENDPOINTS_JSON}" "${PRIMARY_SERVICE}" "${APP_DOMAIN_OBSERVED}" \
        "${BACKEND_SERVICE}" "${BACKEND_DOMAIN_OBSERVED}" "${HAS_BACKEND}" "${APP_NAME}" <<'PY'
import json, sys

paths = json.loads(sys.argv[1])
primary_svc = sys.argv[2]
primary_ctx = sys.argv[3]
backend_svc = sys.argv[4]
backend_ctx = sys.argv[5]
has_backend = sys.argv[6] == "1"
app_name = sys.argv[7]

endpoints = {p: 200 for p in paths}
domain_context = {primary_svc: primary_ctx}
if has_backend:
    domain_context[backend_svc] = backend_ctx

print(json.dumps({
    "status": "pass",
    "app_name": app_name,
    "endpoints": endpoints,
    "domain_context": domain_context,
}, indent=2))
PY
fi

exit 0
