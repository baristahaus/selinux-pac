#!/usr/bin/env bash
#
# stage_offline_fixture.sh — Populate policy_out/ from offline demo fixtures.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE_ROOT="${PROJECT_ROOT}/tests/fixtures/offline"
POLICY_OUT="${PROJECT_ROOT}/policy_out"
APP_NAME="${1:?Usage: stage_offline_fixture.sh APP_NAME}"
SELINUX_DIR="${PROJECT_ROOT}/selinux"
VERSION_FILE="${SELINUX_DIR}/policy_version.txt"

log_error() { echo "[ERROR] $*" >&2; }

[[ -d "${FIXTURE_ROOT}/generated" ]] || {
    log_error "Missing ${FIXTURE_ROOT}/generated — run tests/refresh_offline_fixture.sh"
    exit 1
}

canonical_version=""
if [[ -f "${VERSION_FILE}" ]]; then
    canonical_version="$(tr -d '[:space:]' < "${VERSION_FILE}")"
fi

generated_version=""
if [[ -f "${FIXTURE_ROOT}/generated/${APP_NAME}.te" ]]; then
    generated_version="$(grep -oE 'policy_module\([^,]+,\s*[0-9.]+\)' \
        "${FIXTURE_ROOT}/generated/${APP_NAME}.te" \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi

if [[ -n "${canonical_version}" && -n "${generated_version}" && "${generated_version}" != "${canonical_version}" ]]; then
    log_error "Fixture generated/ is ${generated_version} but selinux/myapp/policy_version.txt is ${canonical_version}"
    log_error "Run: bash tests/refresh_offline_fixture.sh"
    exit 1
fi

mkdir -p "${POLICY_OUT}"
cp "${FIXTURE_ROOT}/avc.log" "${POLICY_OUT}/avc.log"
cp "${FIXTURE_ROOT}/generated/${APP_NAME}.te" "${POLICY_OUT}/${APP_NAME}.te"
cp "${FIXTURE_ROOT}/generated/${APP_NAME}.fc" "${POLICY_OUT}/${APP_NAME}.fc"
if [[ -n "${canonical_version}" ]]; then
    echo "${canonical_version}" > "${POLICY_OUT}/policy_version.txt"
fi
