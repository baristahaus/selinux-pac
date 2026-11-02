#!/usr/bin/env bash
#
# validate_policy_semantics.sh — sesearch assertions on compiled policy module.
# Uses an isolated targeted store (does not load the module into the live kernel).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=lib/app_identity.sh
source "${SCRIPT_DIR}/lib/app_identity.sh"
# shellcheck source=lib/compile_policy.sh
source "${SCRIPT_DIR}/lib/compile_policy.sh"
# shellcheck source=lib/policy_isolated_store.sh
source "${SCRIPT_DIR}/lib/policy_isolated_store.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Types this module declares. A type only mentioned inside require { } is
# foreign: an entrypoint allow on it is not "our" exec type.
module_declared_types() {
    awk '
        /^[[:space:]]*require[[:space:]]*\{/ { in_require = 1 }
        in_require && /\}/ { in_require = 0; next }
        in_require { next }
        /^[[:space:]]*type[[:space:]]+[A-Za-z_]/ {
            gsub(/;/, "", $2)
            print $2
        }
    ' "$1"
}

if [[ "${1:-}" == "--print-declared-types" ]]; then
    [[ -n "${2:-}" && -f "${2}" ]] || exit 2
    module_declared_types "${2}"
    exit 0
fi

# Parse flags. Positional arg is the policy dir.
POLICY_DIR=""
_APP_FLAG=""
_MANIFEST_FLAG=""
_positional_done=0
for arg in "$@"; do
    case "${arg}" in
        --app|--app-name) _next_app=1; continue ;;
        --manifest)       _next_manifest=1; continue ;;
    esac
    if [[ "${_next_app:-}" == "1" ]]; then _APP_FLAG="${arg}"; _next_app=0; continue; fi
    if [[ "${_next_manifest:-}" == "1" ]]; then _MANIFEST_FLAG="${arg}"; _next_manifest=0; continue; fi
    if [[ "${_positional_done}" -eq 0 && "${arg}" != -* ]]; then
        POLICY_DIR="${arg}"
        _positional_done=1
    fi
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

if [[ "${EUID}" -ne 0 ]]; then
    log_error "validate_policy_semantics.sh needs root (isolated policy store copy)"
    exit 1
fi
if ! has_selinux_devel || ! command -v sesearch >/dev/null 2>&1 || ! command -v seinfo >/dev/null 2>&1 || [[ ! -d /var/lib/selinux/targeted ]]; then
    log_error "Need selinux-policy-devel, setools-console, and selinux-policy-targeted (run on rhel-qa or CI Stream 9)"
    exit 1
fi

pp="${POLICY_DIR}/${MODULE_NAME}.pp"
compile_policy_module "${POLICY_DIR}" "${MODULE_NAME}" "${pp}"

store_prefix="$(isolated_store_create)"
trap 'isolated_store_destroy "${store_prefix}"' EXIT
kern="$(isolated_store_kern "${store_prefix}")"

semodule -n -r "${MODULE_NAME}" -s targeted -p "${store_prefix}" 2>/dev/null || true

control_dir="$(mktemp -d)"
cat >"${control_dir}/pac_control.te" <<'EOF'
policy_module(pac_control, 1.0.0)

type pac_control_t;
type pac_control_exec_t;

domain_type(pac_control_t)
files_type(pac_control_exec_t)
EOF
printf '%s\n' '/opt/pac_control -- gen_context(system_u:object_r:pac_control_exec_t,s0)' \
    >"${control_dir}/pac_control.fc"
compile_policy_module "${control_dir}" pac_control "${control_dir}/pac_control.pp"
semodule -n -s targeted -p "${store_prefix}" -i "${control_dir}/pac_control.pp"
rm -rf "${control_dir}"

if ! semodule -n -s targeted -p "${store_prefix}" -i "${pp}"; then
    log_error "semodule rejected ${MODULE_NAME}"
    exit 1
fi
[[ -f "${kern}" ]] || {
    log_error "missing ${kern} after semodule -i"
    exit 1
}

# sesearch without --direct so an attribute grant is visible. A permission
# the control domain also has is a base rule, not this module.
grant_beyond_control() {
    local target="$1" class="$2" perm="$3" message="$4"
    local cand ctrl extra
    local -a query=(--allow -c "${class}" -p "${perm}" "${kern}")
    if [[ -n "${target}" ]]; then
        query=(-t "${target}" "${query[@]}")
    fi
    cand="$(sesearch -s "${DOMAIN}" "${query[@]}" 2>/dev/null | sed -n '/^[[:space:]]*allow /p' || true)"
    ctrl="$(sesearch -s pac_control_t "${query[@]}" 2>/dev/null | sed -n '/^[[:space:]]*allow /p' || true)"
    extra="$(comm -13 <(printf '%s\n' "${ctrl}" | sed '/^$/d' | sort -u) <(printf '%s\n' "${cand}" | sed '/^$/d' | sort -u) || true)"
    if [[ -n "${extra}" ]]; then
        log_error "${message}"
        fail=1
    fi
}

fail=0
grant_beyond_control security_t security setenforce "attribute grant beyond control: setenforce on security"
grant_beyond_control security_t security load_policy "attribute grant beyond control: load_policy on security"
grant_beyond_control shadow_t file read "attribute grant beyond control: read on shadow_t"
grant_beyond_control shadow_t file write "attribute grant beyond control: write on shadow_t"
grant_beyond_control "" capability sys_admin "attribute grant beyond control: capability sys_admin"
grant_beyond_control "" capability sys_module "attribute grant beyond control: capability sys_module"

# java_exec_t is an alias of bin_t on RHEL 9, so java_exec(), corecmd_exec_bin(),
# can_exec(x, java_exec_t) and a raw allow all land here. Only the reviewed
# manifest exception accepts it.
exec_bin_manifest="${PROJECT_ROOT}/config/${MODULE_NAME}.manifest.yml"
if python3 "${PROJECT_ROOT}/scripts/lib/app_manifest.py" exception "${exec_bin_manifest}" --key exec_bin >/dev/null 2>&1; then
    log_info "bin_t execute is a reviewed exception (selinux_exceptions.exec_bin in ${exec_bin_manifest})"
else
    grant_beyond_control bin_t file execute "bin_t execute beyond control without selinux_exceptions.exec_bin in ${exec_bin_manifest}"
fi

# Attributes the control domain also has (domain, file_type, …) are base
# policy. Membership in an attribute that exempts a neverallow is a grant
# even when that attribute has no allow rule of its own.
type_attr_list() {
    local type="$1"
    seinfo -x -t "${type}" "${kern}" 2>/dev/null \
        | sed -n "s/.*type[[:space:]]\\+${type}//p" \
        | tr ',' '\n' \
        | sed 's/[ ;]//g' \
        | sed '/^$/d' \
        | sort -u
}
while IFS= read -r attr; do
    [[ -n "${attr}" ]] || continue
    case "${attr}" in
        can_setenforce|can_load_policy|can_read_shadow_passwords|can_write_shadow_passwords)
            log_error "attribute grant beyond control: ${attr}"
            fail=1
            ;;
    esac
done < <(comm -13 <(type_attr_list pac_control_t) <(type_attr_list "${DOMAIN}") || true)

# -ds is this setools' direct-source match. Inherited attribute rules
# (every domain can map file_type, dontaudit domain security_t, …) are
# base policy. A rule whose source is the domain itself is this module.
if sesearch --allow -s "${DOMAIN}" -ds -t shadow_t -c file -p read "${kern}" 2>/dev/null | grep -q '^[[:space:]]*allow '; then
    log_error "unexpected allow ${DOMAIN} -> shadow_t:read"
    fail=1
fi
if sesearch --allow -s "${DOMAIN}" -ds -t unlabeled_t "${kern}" 2>/dev/null | grep -q '^[[:space:]]*allow '; then
    log_error "unexpected allow ${DOMAIN} -> unlabeled_t"
    fail=1
fi
allows_file="$(mktemp)"
declared_file="$(mktemp)"
seinfo_file="$(mktemp)"
perm_file="$(mktemp)"
dontaudit_file="$(mktemp)"
sesearch --allow -s "${DOMAIN}" "${kern}" >"${allows_file}" 2>/dev/null || true
sesearch --dontaudit -s "${DOMAIN}" -ds "${kern}" >"${dontaudit_file}" 2>/dev/null || true
seinfo -x -t "${DOMAIN}" "${kern}" >"${seinfo_file}" 2>/dev/null || true
seinfo --permissive "${kern}" >"${perm_file}" 2>/dev/null || true
# Stream 9 links (typepermissive DOMAIN) into the module CIL and then omits
# it from policy.kern, so seinfo --permissive stays empty. The CIL is the
# compiled module.
cil_path="${store_prefix}/var/lib/selinux/targeted/active/modules/400/${MODULE_NAME}/cil"
if [[ -f "${cil_path}" ]]; then
    python3 - "${cil_path}" "${DOMAIN}" >>"${perm_file}" <<'PY'
import bz2
import sys

path, domain = sys.argv[1], sys.argv[2]
text = bz2.decompress(open(path, "rb").read()).decode("utf-8", "replace")
if f"(typepermissive {domain})" in text:
    print(domain)
PY
fi
module_declared_types "${POLICY_DIR}/${MODULE_NAME}.te" >"${declared_file}"
if ! python3 "${PROJECT_ROOT}/cli/policy_audit.py" \
    --allows-file "${allows_file}" \
    --dontaudit-file "${dontaudit_file}" \
    --seinfo-file "${seinfo_file}" \
    --permissive-file "${perm_file}" \
    --declared-types-file "${declared_file}" \
    --domain "${DOMAIN}"; then
    fail=1
fi
fc_active="${store_prefix}/var/lib/selinux/targeted/active/file_contexts"
if [[ -f "${fc_active}" ]] && awk -v declared="${declared_file}" '
    BEGIN {
        while ((getline line < declared) > 0) {
            if (line != "") types[line] = 1
        }
        close(declared)
    }
    /^#/ || NF < 2 { next }
    {
        path = $1
        if (index(path, "/etc/shadow") != 1) next
        n = split($NF, parts, ":")
        if (n >= 3 && (parts[3] in types)) hit = 1
    }
    END { exit hit ? 0 : 1 }
' "${fc_active}"; then
    log_error "compiled file contexts relabel /etc/shadow to a type this module declares"
    fail=1
fi
rm -f "${allows_file}" "${seinfo_file}" "${perm_file}" "${declared_file}" "${dontaudit_file}"

if [[ "${fail}" -ne 0 ]]; then
    log_error "Semantic policy check failed"
    exit 1
fi

log_info "Semantic policy checks passed for ${DOMAIN}"
