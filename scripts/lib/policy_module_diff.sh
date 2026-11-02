#!/usr/bin/env bash
#
# policy_module_diff.sh — Diff application-domain allows between two module sources.
#
# sediff(1) requires a binary kernel policy, not standalone .pp module packages
# (see: "Invalid policy ... A binary policy must be specified"). We compile each
# side from .te/.fc, install with semodule -i into an isolated policy store per side,
# dump sorted sesearch --allow lines for app domains, then comm (option b).
#
set -euo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${LIB_DIR}/../.." && pwd)"
# shellcheck source=compile_policy.sh
source "${LIB_DIR}/compile_policy.sh"

APP_NAME=""
DOMAINS=""
BASE_DIR=""
CAND_DIR=""
OUTPUT=""
FROM_MERGE_BASE=0
FORMAT="markdown"
work=""
run_dir=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --app-name NAME           Module name (required if multiple .te in --cand-dir)
  --base-dir PATH           Directory with \${APP_NAME}.{te,fc} for merge-base side
  --cand-dir PATH           Candidate directory (default: selinux/)
  --from-merge-base         Extract base from git merge-base vs origin/main
  --domains CSV             Source domains for sesearch (default: \${APP_NAME}_t,...)
  --output PATH             Write diff text (required)
  --format markdown|text    Output format (default: markdown)
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-name) APP_NAME="$2"; shift 2 ;;
        --base-dir) BASE_DIR="$2"; shift 2 ;;
        --cand-dir) CAND_DIR="$2"; shift 2 ;;
        --from-merge-base) FROM_MERGE_BASE=1; shift ;;
        --domains) DOMAINS="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -n "${OUTPUT}" ]] || { echo "policy_module_diff: --output is required" >&2; exit 1; }
CAND_DIR="${CAND_DIR:-${PROJECT_ROOT}/selinux}"

infer_single_te_module() {
    local dir="$1"
    local count=0 name=""
    local te
    for te in "${dir}"/*.te; do
        [[ -f "${te}" ]] || continue
        name="$(basename "${te}" .te)"
        count=$((count + 1))
    done
    if [[ "${count}" -eq 1 ]]; then
        echo "${name}"
        return 0
    fi
    return 1
}

if [[ -z "${APP_NAME}" ]]; then
    APP_NAME="$(infer_single_te_module "${CAND_DIR}")" || {
        echo "policy_module_diff: pass --app-name (multiple .te in ${CAND_DIR})" >&2
        exit 1
    }
fi

MANIFEST_PY="${PROJECT_ROOT}/scripts/lib/app_manifest.py"
if [[ -z "${DOMAINS}" ]]; then
    manifest="${PROJECT_ROOT}/config/${APP_NAME}.manifest.yml"
    if [[ ! -f "${manifest}" ]]; then
        manifest="$(python3 "${MANIFEST_PY}" resolve --app-name "${APP_NAME}" 2>/dev/null || true)"
    fi
    if [[ -f "${manifest}" ]]; then
        DOMAINS="$(python3 "${MANIFEST_PY}" domains-csv "${manifest}")"
    else
        echo "policy_module_diff: set --domains or provide manifest for ${APP_NAME}" >&2
        exit 1
    fi
fi

resolve_merge_base_ref() {
    local ref=""
    ref="$(git -C "${PROJECT_ROOT}" merge-base HEAD origin/main 2>/dev/null || true)"
    [[ -n "${ref}" ]] || ref="$(git -C "${PROJECT_ROOT}" merge-base HEAD origin/master 2>/dev/null || true)"
    [[ -n "${ref}" ]] || ref="$(git -C "${PROJECT_ROOT}" rev-parse HEAD~1 2>/dev/null || true)"
    [[ -n "${ref}" ]] || { echo "policy_module_diff: cannot resolve merge-base ref" >&2; exit 1; }
    echo "${ref}"
}

if [[ "${FROM_MERGE_BASE}" -eq 1 ]]; then
    base_ref="$(resolve_merge_base_ref)"
    work="$(mktemp -d)"
    # Resolve the module_dir relative path from the manifest.
    manifest="${PROJECT_ROOT}/config/${APP_NAME}.manifest.yml"
    mod_rel="selinux"
    if [[ -f "${manifest}" ]]; then
        mod_rel="$(python3 -c "
import sys, yaml
m = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
print(m.get('policy', {}).get('module_dir', 'selinux'))
" "${manifest}" 2>/dev/null || echo "selinux")"
    fi
    te_path="${mod_rel}/${APP_NAME}.te"
    fc_path="${mod_rel}/${APP_NAME}.fc"
    if ! git -C "${PROJECT_ROOT}" show "${base_ref}:${te_path}" > "${work}/${APP_NAME}.te" 2>/dev/null; then
        # Module may not exist at merge-base (new module). Use an empty base.
        echo "policy_module(${APP_NAME}, 0.0.0)" > "${work}/${APP_NAME}.te"
        echo "" > "${work}/${APP_NAME}.fc"
    elif ! git -C "${PROJECT_ROOT}" show "${base_ref}:${fc_path}" > "${work}/${APP_NAME}.fc" 2>/dev/null; then
        echo "" > "${work}/${APP_NAME}.fc"
    fi
    BASE_DIR="${work}"
fi

cleanup() {
    rm -rf "${work}" "${run_dir}"
}
trap cleanup EXIT

[[ -n "${BASE_DIR}" && -f "${BASE_DIR}/${APP_NAME}.te" && -f "${BASE_DIR}/${APP_NAME}.fc" ]] || {
    echo "policy_module_diff: missing base ${APP_NAME}.{te,fc} in ${BASE_DIR:-<unset>}" >&2
    exit 1
}
[[ -f "${CAND_DIR}/${APP_NAME}.te" && -f "${CAND_DIR}/${APP_NAME}.fc" ]] || {
    echo "policy_module_diff: missing candidate ${APP_NAME}.{te,fc} in ${CAND_DIR}" >&2
    exit 1
}

run_dir="$(mktemp -d)"
mkdir -p "${run_dir}/base" "${run_dir}/cand"
cp "${LIB_DIR}/policy_module_sesearch.sh" "${LIB_DIR}/policy_module_diff_side.sh" "${run_dir}/"
cp "${BASE_DIR}/${APP_NAME}.te" "${BASE_DIR}/${APP_NAME}.fc" "${run_dir}/base/"
cp "${CAND_DIR}/${APP_NAME}.te" "${CAND_DIR}/${APP_NAME}.fc" "${run_dir}/cand/"
if [[ -f "${BASE_DIR}/${APP_NAME}.if" ]]; then
    cp "${BASE_DIR}/${APP_NAME}.if" "${run_dir}/base/"
fi
if [[ -f "${CAND_DIR}/${APP_NAME}.if" ]]; then
    cp "${CAND_DIR}/${APP_NAME}.if" "${run_dir}/cand/"
fi

compile_policy_module "${run_dir}/base" "${APP_NAME}" "${run_dir}/base/${APP_NAME}.pp" || {
    echo "policy_module_diff: failed to compile merge-base ${APP_NAME} module" >&2
    exit 1
}
compile_policy_module "${run_dir}/cand" "${APP_NAME}" "${run_dir}/cand/${APP_NAME}.pp" || {
    echo "policy_module_diff: failed to compile candidate ${APP_NAME} module" >&2
    exit 1
}

collect_side_native() {
    local label="$1"
    local pp="$2"
    local out="${run_dir}/${label}_rules.txt"
    # shellcheck source=policy_module_diff_side.sh
    bash "${LIB_DIR}/policy_module_diff_side.sh" "${pp}" "${out}" "${DOMAINS}" "${APP_NAME}"
}

if has_selinux_devel && command -v sesearch >/dev/null 2>&1; then
    collect_side_native base "${run_dir}/base/${APP_NAME}.pp"
    collect_side_native cand "${run_dir}/cand/${APP_NAME}.pp"
else
    echo "policy_module_diff: need selinux-policy-devel + setools-console (run on rhel-qa or CI Stream 9)" >&2
    exit 1
fi

comm -23 "${run_dir}/cand_rules.txt" "${run_dir}/base_rules.txt" > "${run_dir}/added.txt"
comm -13 "${run_dir}/cand_rules.txt" "${run_dir}/base_rules.txt" > "${run_dir}/removed.txt"

added="$(cat "${run_dir}/added.txt")"
removed="$(cat "${run_dir}/removed.txt")"

if [[ "${FORMAT}" == "text" ]]; then
    {
        echo "Rules ADDED:"
        [[ -n "${added}" ]] && echo "${added}" || echo "(none)"
        echo ""
        echo "Rules REMOVED:"
        [[ -n "${removed}" ]] && echo "${removed}" || echo "(none)"
    } > "${OUTPUT}"
else
    if [[ -z "${added}" && -z "${removed}" ]]; then
        {
            echo "### Policy access delta (sesearch)"
            echo ""
            echo "No access change for application domains (${DOMAINS})."
        } > "${OUTPUT}"
    else
        {
            echo "### Policy access delta (sesearch)"
            echo ""
            echo "**Rules ADDED:**"
            echo '```'
            [[ -n "${added}" ]] && echo "${added}" || echo "(none)"
            echo '```'
            echo ""
            echo "**Rules REMOVED:**"
            echo '```'
            [[ -n "${removed}" ]] && echo "${removed}" || echo "(none)"
            echo '```'
        } > "${OUTPUT}"
    fi
fi
