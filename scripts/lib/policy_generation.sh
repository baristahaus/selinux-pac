#!/usr/bin/env bash
# policy_generation.sh — Shared deterministic policy generation (source only)
set -euo pipefail

run_write_avc_summary() {
    local avc_log="$1"
    local existing_te="$2"
    local out="${3:-${PROJECT_ROOT}/policy_out/avc_summary.txt}"
    local domain="${4:?domain argument is required}"
    python3 - "${PROJECT_ROOT}" "${avc_log}" "${existing_te}" "${out}" "${domain}" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "cli"))
from avc_preprocess import preprocess_avc_file

avc = Path(sys.argv[2])
te = Path(sys.argv[3]).read_text(encoding="utf-8")
out = Path(sys.argv[4])
domain = sys.argv[5]
summary, stats = preprocess_avc_file(avc, domain, existing_te=te)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(summary + "\n", encoding="utf-8")
print(f"Wrote {out} (raw={stats['raw']} merged={stats['merged']} net_new={stats['net_new']})")
PY
}

run_deterministic_policy_gen() {
    local avc_log="$1"
    local manifest="$2"
    local policy_te="$3"
    local policy_fc="$4"
    local policy_version_file="$5"
    local policy_out="$6"
    local app_name="$7"

    mkdir -p "${policy_out}"
    cp "${policy_version_file}" "${policy_out}/policy_version.txt"
    local -a cmd=(
        python3 "${PROJECT_ROOT}/cli/deterministic_gen.py"
        --avc-log "${avc_log}"
        --manifest "${manifest}"
        --existing-te "${policy_te}"
        --existing-fc "${policy_fc}"
        --out-dir "${policy_out}"
        --version-file "${policy_out}/policy_version.txt"
        --bump-version
    )
    if [[ "${POLICY_ALLOW_DEGRADED:-0}" == "1" ]]; then
        cmd+=(--allow-degraded)
    fi
    if [[ "${POLICY_ALLOW_NEEDS_REVIEW:-0}" == "1" ]]; then
        cmd+=(--allow-needs-review)
    fi
    for _perm in "${ALLOW_NEEDS_REVIEW_PERMS[@]+"${ALLOW_NEEDS_REVIEW_PERMS[@]}"}"; do
        cmd+=(--allow-needs-review-perm "${_perm}")
    done
    if [[ -f "${policy_out}/vendor_override.json" ]]; then
        cmd+=(--vendor-override "${policy_out}/vendor_override.json")
    fi
    "${cmd[@]}"
    bash "${SCRIPT_DIR}/validate_forbidden_patterns.sh" "${policy_out}" --app "${app_name}"
    bash "${SCRIPT_DIR}/compile_and_validate.sh" "${policy_out}" --app "${app_name}"
    run_write_avc_summary "${avc_log}" "${policy_te}" "${policy_out}/avc_summary.txt" "${app_name}_t"
}
