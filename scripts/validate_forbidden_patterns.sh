#!/usr/bin/env bash
#
# validate_forbidden_patterns.sh — CI gate for over-permissive or invalid SELinux syntax
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=lib/app_identity.sh
source "${SCRIPT_DIR}/lib/app_identity.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse flags. Positional arg is the policy dir.
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
    _resolved=0
    if [[ -n "${_MANIFEST_FLAG}" ]]; then
        if resolve_app_identity --manifest "${_MANIFEST_FLAG}" 2>/dev/null; then
            _resolved=1
            POLICY_DIR="${POLICY_DIR:-${MODULE_DIR}}"
        fi
    fi
    if [[ "${_resolved}" -eq 0 && -n "${_APP_FLAG}" && -f "${PROJECT_ROOT}/config/${_APP_FLAG}.manifest.yml" ]]; then
        if resolve_app_identity --app "${_APP_FLAG}" 2>/dev/null; then
            _resolved=1
            POLICY_DIR="${POLICY_DIR:-${MODULE_DIR}}"
        fi
    fi
    if [[ "${_resolved}" -eq 0 ]]; then
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

[[ -f "${te}" ]] || { log_error "Missing ${te}"; exit 1; }
[[ -f "${fc}" ]] || { log_error "Missing ${fc}"; exit 1; }

fail=0

check_fail() {
    log_error "$1"
    fail=1
}

log_info "Checking forbidden patterns in ${te}"

if grep -qE 'allow\s+\w+\s+\*:' "${te}"; then
    check_fail "Wildcard object type in allow rule"
fi

if grep -qE 'allow\s+\w+\s+\w+:\*\s' "${te}"; then
    check_fail "Wildcard object class in allow rule"
fi

if grep -qE 'allow\s+\w+\s+\*:\*\s+\*\s+\*' "${te}"; then
    check_fail "Fully wildcard allow rule"
fi

if grep -qE 'allow\s+\w+\s+self:\*' "${te}"; then
    check_fail "Forbidden allow rule targeting self:* (over-broad)"
fi

# Rules only: a generated note in a comment line must not trip or satisfy a check.
te_rules="$(sed 's/#.*//' "${te}")"

# A raw allow on bin_t (or its alias java_exec_t) is always refused. App
# binaries get their own exec type in the .fc.
if grep -qE 'allow[[:space:]]+[^[:space:]]+[[:space:]]+(bin_t|java_exec_t):file[[:space:]]+(\{[^}]*\bexecute|execute)' <<<"${te_rules}"; then
    check_fail "Forbidden raw allow of execute on bin_t — label app binaries with dedicated exec types in .fc; the system JVM needs the reviewed corecmd_exec_bin exception"
fi

# On RHEL 9 java_exec_t is an alias of bin_t, so these macros all compile to
# execute on bin_t. They pass only with a reviewed reason in the app manifest.
if grep -qE '\b(corecmd_exec_bin|java_exec)[[:space:]]*\(|\bcan_exec[[:space:]]*\([^,]+,[[:space:]]*(bin_t|java_exec_t)[[:space:]]*\)' <<<"${te_rules}"; then
    manifest="${_MANIFEST_FLAG:-${PROJECT_ROOT}/config/${MODULE_NAME}.manifest.yml}"
    set +e
    reason="$(python3 "${PROJECT_ROOT}/scripts/lib/app_manifest.py" exception "${manifest}" --key exec_bin 2>&1)"
    rc=$?
    set -e
    if [[ "${rc}" -eq 0 ]]; then
        log_info "bin_t execute accepted: reviewed exception selinux_exceptions.exec_bin in ${manifest}"
    elif [[ "${rc}" -eq 1 ]]; then
        check_fail "corecmd_exec_bin / java_exec / can_exec on bin_t needs a reviewed reason in the app manifest: selinux_exceptions.exec_bin (${manifest})"
    else
        check_fail "Cannot read selinux_exceptions from ${manifest}: ${reason}"
    fi
fi

if grep -qE '^module\s+' "${te}"; then
    check_fail "Use policy_module() syntax, not bare 'module' declaration"
fi

if ! python3 -c "
import re, pathlib, sys
te = pathlib.Path('${te}').read_text()
prefix = '${MODULE_NAME}_'
if re.search(r'require\s*\{[^}]*\btype\s+' + re.escape(prefix), te, re.DOTALL):
    sys.exit(1)
" 2>/dev/null; then
    check_fail "Custom types declared inside require block"
fi

while IFS= read -r priv; do
    [[ -n "${priv}" ]] || continue
    if grep -qE "allow[[:space:]]+[^[:space:]]+[[:space:]]+${priv}[[:space:]]*:" "${te}"; then
        check_fail "Forbidden allow rule targeting high-privilege type: ${priv}"
    fi
done < <(PYTHONPATH="${PROJECT_ROOT}/cli" python3 -c 'from policy_rules import FORBIDDEN_TARGET_TYPES
print("\n".join(sorted(FORBIDDEN_TARGET_TYPES)))')

if grep -qE 'allow[[:space:]]+[^[:space:]]+[[:space:]]+var_t:file[[:space:]]+\{[^}]*write' "${te}"; then
    check_fail "Forbidden broad var_t:file write — use dedicated application types"
fi

if ! grep -q 'policy_module' "${te}"; then
    check_fail "Missing policy_module() declaration"
fi

if ! grep -q "${DOMAIN}" "${te}"; then
    check_fail "Domain ${DOMAIN} not referenced in ${te}"
fi

# .fc content: require paths from manifest when available, else /opt/MODULE and /var/lib/MODULE.
_manifest="${_MANIFEST_FLAG:-${PROJECT_ROOT}/config/${MODULE_NAME}.manifest.yml}"
if [[ -f "${_manifest}" ]]; then
    _fc_paths="$(python3 -c "
import yaml, sys, json
m = yaml.safe_load(open(sys.argv[1]))
paths = m.get('paths', {})
out = []
for key in ('install_root', 'var_dir', 'log_dir', 'runtime_dir'):
    v = paths.get(key)
    if v:
        out.append(v)
print(json.dumps(out))
" "${_manifest}" 2>/dev/null || echo '[]')"
    for token in $(python3 -c "import json,sys; [print(p) for p in json.loads(sys.argv[1])]" "${_fc_paths}"); do
        if ! grep -q "${token}" "${fc}"; then
            check_fail "fc_content missing expected manifest path: ${token}"
        fi
    done
    for token in "${MODULE_NAME}_exec_t" "${MODULE_NAME}_var_lib_t"; do
        if ! grep -q "${token}" "${fc}"; then
            check_fail "fc_content missing expected type: ${token}"
        fi
    done
else
    for token in "/opt/${MODULE_NAME}" "/var/lib/${MODULE_NAME}" "${MODULE_NAME}_exec_t" "${MODULE_NAME}_var_lib_t"; do
        if ! grep -q "${token}" "${fc}"; then
            check_fail "fc_content missing expected path/type: ${token}"
        fi
    done
fi

if [[ "${fail}" -ne 0 ]]; then
    exit 1
fi

log_info "Forbidden-pattern checks passed for ${MODULE_NAME}"
