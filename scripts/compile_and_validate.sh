#!/usr/bin/env bash
#
# compile_and_validate.sh — CI gate: syntax-check and build .pp from selinux/ or policy_out/
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=lib/app_identity.sh
source "${SCRIPT_DIR}/lib/app_identity.sh"
# shellcheck source=lib/compile_policy.sh
source "${SCRIPT_DIR}/lib/compile_policy.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse flags. Positional arg is still accepted for the policy dir.
POLICY_DIR=""
_APP_FLAG=""
_MANIFEST_FLAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --app|--app-name) _APP_FLAG="$2"; shift 2 ;;
        --manifest)       _MANIFEST_FLAG="$2"; shift 2 ;;
        -*)               shift ;;
        *)
            if [[ -z "${POLICY_DIR}" ]]; then
                POLICY_DIR="$1"
            fi
            shift
            ;;
    esac
done

if [[ -n "${_APP_FLAG}" || -n "${_MANIFEST_FLAG}" ]]; then
    if [[ -n "${_MANIFEST_FLAG}" ]]; then
        resolve_app_identity --manifest "${_MANIFEST_FLAG}"
        POLICY_DIR="${POLICY_DIR:-${MODULE_DIR}}"
    elif [[ -f "${PROJECT_ROOT}/config/${_APP_FLAG}.manifest.yml" ]]; then
        resolve_app_identity --app "${_APP_FLAG}"
        POLICY_DIR="${POLICY_DIR:-${MODULE_DIR}}"
    else
        MODULE_NAME="${_APP_FLAG}"
        DOMAIN="${_APP_FLAG}_t"
    fi
    POLICY_DIR="${POLICY_DIR:-${PROJECT_ROOT}/selinux}"
    MODULE_NAME="${MODULE_NAME:-${_APP_FLAG}}"
    DOMAIN="${DOMAIN:-${_APP_FLAG}_t}"
else
    _guard_old_identity_vars
    POLICY_DIR="${POLICY_DIR:-${PROJECT_ROOT}/selinux}"
    MODULE_NAME="$(cd "${POLICY_DIR}" && ls -1 *.te 2>/dev/null | sed 's/\.te$//' | head -1)"
    [[ -n "${MODULE_NAME}" ]] || { log_error "No .te in ${POLICY_DIR}; pass --app NAME"; exit 1; }
    DOMAIN="${MODULE_NAME}_t"
fi

te="${POLICY_DIR}/${MODULE_NAME}.te"
fc="${POLICY_DIR}/${MODULE_NAME}.fc"
pp="${POLICY_DIR}/${MODULE_NAME}.pp"

if [[ ! -f "${te}" ]] || [[ ! -f "${fc}" ]]; then
    log_error "Missing ${te} or ${fc}"
    exit 1
fi

bash "${SCRIPT_DIR}/validate_forbidden_patterns.sh" "${POLICY_DIR}" --app "${MODULE_NAME}"

log_info "Static checks on ${te}"
log_info "Compiling ${MODULE_NAME} in ${POLICY_DIR} via refpolicy Makefile"
compile_policy_module "${POLICY_DIR}" "${MODULE_NAME}" "${pp}"
log_info "Built ${pp}"
log_info "Validation passed for ${MODULE_NAME} (domain ${DOMAIN})"
