#!/usr/bin/env bash
#
# classify_policy_blast_radius.sh — Recommend soak duration from policy module delta.
#
# sediff(1) does not accept standalone .pp module packages on EL9 (same as
# policy_module_diff.sh). We install each module with semodule -i, diff sorted
# sesearch --allow and sesearch -T output, and classify added rule lines.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/compile_policy.sh
source "${SCRIPT_DIR}/lib/compile_policy.sh"

BASE_INPUT="${1:-}"
CANDIDATE_INPUT="${2:-}"
CLASSIFY_PY="${SCRIPT_DIR}/lib/blast_radius_classify.py"
COLLECT_SH="${SCRIPT_DIR}/lib/blast_radius_collect.sh"
MANIFEST_PY="${SCRIPT_DIR}/lib/app_manifest.py"

module_from_policy_input() {
    local input="$1"
    if [[ "${input}" == *.te ]]; then
        basename "${input}" .te
    else
        basename "${input}" .pp
    fi
}

resolve_blast_radius_domains() {
    local module_name="$1"
    if [[ -n "${BLAST_RADIUS_DOMAINS:-}" ]]; then
        echo "${BLAST_RADIUS_DOMAINS}"
        return 0
    fi
    local manifest="${BLAST_RADIUS_MANIFEST:-}"
    if [[ -z "${manifest}" ]]; then
        manifest="$(python3 "${MANIFEST_PY}" resolve --app-name "${module_name}" 2>/dev/null || true)"
    fi
    if [[ -z "${manifest}" || ! -f "${manifest}" ]]; then
        echo "classify_policy_blast_radius: cannot resolve domains for module ${module_name}" >&2
        echo "  Set BLAST_RADIUS_DOMAINS or pass --app NAME (config/${module_name}.manifest.yml)" >&2
        return 1
    fi
    python3 "${MANIFEST_PY}" domains-csv "${manifest}"
}

usage() {
    cat <<EOF
Usage: $(basename "$0") BASE.{pp,te} CANDIDATE.{pp,te}

Prints JSON: {"tier":"low|medium|high","min_days":1|3|7,"reason":"...","sediff_excerpt":"..."}

Tiers:
  low    — added allows only on myapp_* types           → 1 day
  medium — refpolicy expansion (non-myapp, non-base)    → 3 days
  high   — base types, entrypoint, transitions          → 7 days

On analysis failure, returns tier high / min_days 7 (fail-closed).
EOF
}

fail_closed_json() {
    local reason="$1"
    local excerpt="${2:-}"
    BLAST_FAIL_REASON="${reason}" BLAST_FAIL_EXCERPT="${excerpt}" python3 - <<'PY'
import json, os
print(json.dumps({
    "tier": "high",
    "min_days": 7,
    "reason": os.environ["BLAST_FAIL_REASON"],
    "sediff_excerpt": os.environ.get("BLAST_FAIL_EXCERPT", ""),
    "fail_closed": True,
}, indent=2))
PY
}

if [[ $# -lt 2 ]]; then
    usage >&2
    exit 1
fi

[[ -f "${BASE_INPUT}" && -f "${CANDIDATE_INPUT}" ]] || {
    echo "classify_policy_blast_radius: missing input file(s)" >&2
    fail_closed_json "Base or candidate policy input not found"
    exit 0
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
resolve_pp() {
    local input="$1"
    local out_pp="$2"
    if [[ "${input}" == *.te ]]; then
        local dir base
        dir="$(cd "$(dirname "${input}")" && pwd)"
        base="$(basename "${input}" .te)"
        [[ -f "${dir}/${base}.fc" ]] || {
            echo "classify_policy_blast_radius: missing ${dir}/${base}.fc for ${input}" >&2
            return 1
        }
        compile_policy_module "${dir}" "${base}" "${out_pp}"
    else
        cp "${input}" "${out_pp}"
    fi
}

compile_log="${work_dir}/compile.log"
: > "${compile_log}"

if ! resolve_pp "${BASE_INPUT}" "${work_dir}/base.pp" >>"${compile_log}" 2>&1; then
    fail_closed_json "Failed to compile or read base policy"
    exit 0
fi
if ! resolve_pp "${CANDIDATE_INPUT}" "${work_dir}/candidate.pp" >>"${compile_log}" 2>&1; then
    fail_closed_json "Failed to compile or read candidate policy"
    exit 0
fi

if [[ "${CLASSIFY_SKIP_SELINUX:-0}" == "1" ]]; then
    fail_closed_json "Classification skipped — conservative soak"
    exit 0
fi

CAND_MODULE="$(module_from_policy_input "${CANDIDATE_INPUT}")"
MODULE_NAME="${CAND_MODULE}"
BLAST_RADIUS_DOMAINS="$(resolve_blast_radius_domains "${MODULE_NAME}")" || {
    fail_closed_json "Cannot resolve BLAST_RADIUS_DOMAINS for ${MODULE_NAME} — pass --app NAME or set BLAST_RADIUS_DOMAINS"
    exit 0
}

if ! command -v semodule >/dev/null 2>&1 || ! command -v sesearch >/dev/null 2>&1 || [[ ! -d /var/lib/selinux/targeted ]]; then
    fail_closed_json "selinux-policy-targeted + setools-console required for blast-radius classification"
    exit 0
fi

mkdir -p "${work_dir}/out"
collect_log="${work_dir}/collect.log"
export BLAST_RADIUS_MODULE="${MODULE_NAME}"
export BLAST_RADIUS_DOMAINS
if ! bash "${COLLECT_SH}" "${work_dir}/base.pp" "${work_dir}/candidate.pp" "${work_dir}/out" \
    >"${collect_log}" 2>&1; then
    excerpt="$(tail -40 "${collect_log}")"
    fail_closed_json "Policy rule diff failed — conservative soak" "${excerpt}"
    exit 0
fi

[[ -f "${work_dir}/out/added_all.txt" ]] || {
    fail_closed_json "Missing added rule set after collection"
    exit 0
}

python3 "${CLASSIFY_PY}" "${work_dir}/out/added_all.txt"
