#!/usr/bin/env bash
#
# run_deterministic_payments_check.sh — Generator must not emit myapp artifacts for payments manifest.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST="${PROJECT_ROOT}/config/payments.manifest.example.yml"
OUT="${PROJECT_ROOT}/policy_out/_payments_ci_check"
AVC_WORK="$(mktemp)"
trap 'rm -rf "${OUT}" "${AVC_WORK}"' EXIT
printf '%s\n' "# no AVC lines for this check" > "${AVC_WORK}"

rm -rf "${OUT}"
mkdir -p "${OUT}"

python3 "${PROJECT_ROOT}/cli/deterministic_gen.py" \
    --avc-log "${AVC_WORK}" \
    --manifest "${MANIFEST}" \
    --out-dir "${OUT}"

for name in payments.te payments.fc findings.json pr_summary.md; do
    [[ -f "${OUT}/${name}" ]] || {
        echo "missing ${OUT}/${name}" >&2
        exit 1
    }
done

if [[ -f "${OUT}/myapp.te" || -f "${OUT}/myapp.fc" ]]; then
    echo "deterministic_gen wrote myapp.* for payments manifest" >&2
    exit 1
fi

if grep -ri 'myapp' "${OUT}" >/dev/null 2>&1; then
    echo "deterministic_gen output contains 'myapp' (see grep below)" >&2
    grep -ri 'myapp' "${OUT}" >&2 || true
    exit 1
fi

echo "deterministic payments manifest check OK"
