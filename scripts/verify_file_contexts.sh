#!/usr/bin/env bash
#
# verify_file_contexts.sh — Fail-closed path labeling check before service restart
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT=""
VAR_DIR=""
LOG_DIR=""
RUNTIME_DIR=""
APP_NAME=""
BIN_DIR=""
SKIP_SELINUX="${SKIP_SELINUX:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Verify file contexts with matchpathcon and restorecon dry-run (-n).
Exits non-zero if paths would be relabeled or tools are missing (unless --skip-if-unavailable).

Options:
  --install-root PATH   Application root (default: /opt/myapp)
  --var-dir PATH        Data directory (default: /var/lib/myapp)
  --log-dir PATH        Log directory (default: /var/log/myapp)
  --runtime-dir PATH    Runtime directory (default: /run/myapp)
  --app-name NAME       Module name (default: myapp)
  --skip-if-unavailable Exit 0 when SELinux tools or paths absent (for CI smoke)
  --pre-service-restart Skip runtime dir matchpathcon (canary before systemd restart)
  -h, --help            Show help
EOF
}

SKIP_IF_UNAVAILABLE=0
PRE_SERVICE_RESTART=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-root) INSTALL_ROOT="$2"; shift 2 ;;
        --var-dir) VAR_DIR="$2"; shift 2 ;;
        --log-dir) LOG_DIR="$2"; shift 2 ;;
        --runtime-dir) RUNTIME_DIR="$2"; shift 2 ;;
        --app-name|--app) APP_NAME="$2"; shift 2 ;;
        --skip-if-unavailable) SKIP_IF_UNAVAILABLE=1; shift ;;
        --pre-service-restart) PRE_SERVICE_RESTART=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

BIN_DIR="${INSTALL_ROOT}/bin"

[[ -n "${APP_NAME}" ]] || { log_error "--app-name NAME is required"; exit 2; }
INSTALL_ROOT="${INSTALL_ROOT:-/opt/${APP_NAME}}"
VAR_DIR="${VAR_DIR:-/var/lib/${APP_NAME}}"
LOG_DIR="${LOG_DIR:-/var/log/${APP_NAME}}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/${APP_NAME}}"
BIN_DIR="${INSTALL_ROOT}/bin"

if [[ "${SKIP_SELINUX}" == "1" ]]; then
    log_info "SKIP_SELINUX=1 — skipping file context verification"
    exit 0
fi

for cmd in matchpathcon restorecon; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        if [[ "${SKIP_IF_UNAVAILABLE}" -eq 1 ]]; then
            log_info "${cmd} not available — skipping verification"
            exit 0
        fi
        log_error "${cmd} not found (install policycoreutils)"
        exit 1
    fi
done

if ! getenforce 2>/dev/null | grep -qiE 'enforcing|permissive'; then
    if [[ "${SKIP_IF_UNAVAILABLE}" -eq 1 ]]; then
        log_info "SELinux not enabled — skipping verification"
        exit 0
    fi
    log_error "SELinux is not enabled on this host"
    exit 1
fi

fail=0
check_path() {
    local path="$1"
    if [[ ! -e "${path}" ]]; then
        log_info "Skipping missing path: ${path}"
        return 0
    fi
    log_info "matchpathcon -V ${path}"
    if ! matchpathcon -V "${path}"; then
        log_error "matchpathcon -V failed for ${path}"
        fail=1
    fi
}

check_path "${INSTALL_ROOT}/app.py"
check_path "${INSTALL_ROOT}/backend_stub.py"
check_path "${BIN_DIR}/backup.sh"
if [[ -x "${INSTALL_ROOT}/venv/bin/python" ]]; then
    check_path "${INSTALL_ROOT}/venv/bin/python"
fi
if [[ -d "${VAR_DIR}" ]]; then
    check_path "${VAR_DIR}"
fi
if [[ -d "${LOG_DIR}" ]]; then
    check_path "${LOG_DIR}"
fi
if [[ -d "${RUNTIME_DIR}" ]] && [[ "${PRE_SERVICE_RESTART}" -eq 0 ]]; then
    check_path "${RUNTIME_DIR}"
fi

restorecon_dry() {
    local target="$1"
    if [[ ! -e "${target}" ]]; then
        return 0
    fi
    if [[ "${target}" == *.sock ]]; then
        log_info "Skipping runtime socket in restorecon dry-run: ${target}"
        return 0
    fi
    log_info "restorecon dry-run (-n): ${target}"
    local output
    output="$(restorecon -Rv -n "${target}" 2>&1 || true)"
    output="$(echo "${output}" | grep -Ev '\.sock($| )' || true)"
    if [[ -n "${output}" ]]; then
        log_error "Mislabeled paths under ${target} (restorecon would change):"
        echo "${output}" >&2
        fail=1
    fi
}

check_labeled_dir() {
    local dir="$1"
    local expected_type="${APP_NAME}_var_lib_t"
    local actual

    if [[ ! -d "${dir}" ]]; then
        return 0
    fi

    actual="$(stat -c '%C' "${dir}" 2>/dev/null || true)"
    if [[ "${actual}" == *"${expected_type}"* ]]; then
        log_info "${dir} labeled ${expected_type}"
        return 0
    fi

    restorecon_dry "${dir}"
}

# Narrow restorecon scope: data dir + app entrypoints (skip the venv tree).
check_labeled_dir "${VAR_DIR}"
if [[ -d "${LOG_DIR}" ]]; then
    restorecon_dry "${LOG_DIR}"
fi
restorecon_dry "${INSTALL_ROOT}/app.py"
if [[ -d "${BIN_DIR}" ]]; then
    restorecon_dry "${BIN_DIR}"
fi

if [[ "${fail}" -ne 0 ]]; then
    log_error "File context verification failed — run restorecon before restarting the service"
    exit 1
fi

log_info "File context verification passed for ${APP_NAME}"
