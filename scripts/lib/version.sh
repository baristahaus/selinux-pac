#!/usr/bin/env bash
#
# version.sh — Read and validate selinux/MODULE/policy_version.txt (single source of truth).
#
# Source from other scripts:
#   source "${SCRIPT_DIR}/lib/version.sh"
#
set -euo pipefail

VERSION_FILE_DEFAULT="${VERSION_FILE_DEFAULT:-selinux/myapp/policy_version.txt}"
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+$'

policy_version() {
    local file="${1:-}"
    if [[ -z "${file}" ]]; then
        if [[ -n "${PROJECT_ROOT:-}" ]]; then
            file="${PROJECT_ROOT}/${VERSION_FILE_DEFAULT}"
        else
            local lib_dir
            lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            file="$(cd "${lib_dir}/../.." && pwd)/${VERSION_FILE_DEFAULT}"
        fi
    fi
    [[ -f "${file}" ]] || {
        echo "policy_version: missing ${file}" >&2
        return 1
    }
    local v
    v="$(tr -d '[:space:]' < "${file}")"
    [[ "${v}" =~ ${SEMVER_RE} ]] || {
        echo "policy_version: invalid SemVer in ${file}: ${v}" >&2
        return 1
    }
    echo "${v}"
}

policy_module_version_from_te() {
    local te_file="${1:?te file required}"
    local app_name="${2:-}"
    if [[ -z "${app_name}" ]]; then
        app_name="$(basename "${te_file}" .te)"
    fi
    [[ -f "${te_file}" ]] || {
        echo "policy_module_version_from_te: missing ${te_file}" >&2
        return 1
    }
    local line match
    line="$(grep -E "^policy_module\\(${app_name}," "${te_file}" | head -1 || true)"
    [[ -n "${line}" ]] || {
        echo "policy_module_version_from_te: no policy_module(${app_name}, ...) in ${te_file}" >&2
        return 1
    }
    match="$(printf '%s\n' "${line}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [[ -n "${match}" && "${match}" =~ ${SEMVER_RE} ]] || {
        echo "policy_module_version_from_te: cannot parse version from: ${line}" >&2
        return 1
    }
    echo "${match}"
}
