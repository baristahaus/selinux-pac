#!/usr/bin/env bash
#
# validate_version_consistency.sh — Fail if any policy module's version sources disagree.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/version.sh
source "${SCRIPT_DIR}/lib/version.sh"

SELINUX_ROOT="${SELINUX_ROOT:-${PROJECT_ROOT}/selinux}"
# Packaging checks belong to this repo. An app repo sets SELINUX_ROOT to its own tree.
own_tree=0
if [[ "${SELINUX_ROOT}" == "${PROJECT_ROOT}/selinux" ]]; then
    own_tree=1
fi
errors=0

check_module() {
    local module="$1"
    local version_file="$2"
    local te_file="$3"
    local spec_file="${4:-}"

    if [[ ! -f "${version_file}" ]]; then
        echo "validate_version_consistency: missing ${version_file} for module ${module}" >&2
        errors=$((errors + 1))
        return
    fi
    if [[ ! -f "${te_file}" ]]; then
        echo "validate_version_consistency: missing ${te_file} for module ${module}" >&2
        errors=$((errors + 1))
        return
    fi

    canonical="$(policy_version "${version_file}")"
    from_te="$(policy_module_version_from_te "${te_file}" "${module}")"

    if [[ "${canonical}" != "${from_te}" ]]; then
        echo "validate_version_consistency: ${module}: ${version_file} (${canonical}) != policy_module in ${te_file} (${from_te})" >&2
        errors=$((errors + 1))
    fi

    if [[ -n "${spec_file}" && -f "${spec_file}" ]]; then
        if ! grep -qE '^Version:[[:space:]]*%{modver}[[:space:]]*$' "${spec_file}"; then
            echo "validate_version_consistency: ${module}: ${spec_file} must use 'Version: %{modver}'" >&2
            errors=$((errors + 1))
        fi
    fi

    echo "validate_version_consistency: ${module} OK (${canonical})"
}

while IFS= read -r version_file; do
    [[ -n "${version_file}" ]] || continue
    dir="$(dirname "${version_file}")"
    if [[ "${dir}" == "${SELINUX_ROOT}" ]]; then
        # Flat layout: infer module from the single .te in the directory.
        module="$(cd "${dir}" && ls -1 *.te 2>/dev/null | sed 's/\.te$//' | head -1)"
        [[ -n "${module}" ]] || { echo "validate_version_consistency: no .te in ${dir}" >&2; errors=$((errors + 1)); continue; }
        te_file="${SELINUX_ROOT}/${module}.te"
        spec_file="${PROJECT_ROOT}/packaging/${module}-selinux.spec"
        if [[ ! -f "${spec_file}" ]]; then
            spec_file=""
        fi
    else
        module="$(basename "${dir}")"
        te_file="${dir}/${module}.te"
        spec_file="${PROJECT_ROOT}/packaging/${module}-selinux.spec"
        if [[ ! -f "${spec_file}" ]]; then
            spec_file=""
        fi
    fi
    check_module "${module}" "${version_file}" "${te_file}" "${spec_file}"
done < <(find "${SELINUX_ROOT}" -name policy_version.txt | sort)

if [[ "${own_tree}" -eq 1 ]]; then
    if ! grep -qE 'define "modver \$\{VERSION\}"' "${PROJECT_ROOT}/packaging/build_rpms.sh"; then
        echo "validate_version_consistency: packaging/build_rpms.sh must pass --define \"modver \${VERSION}\" from policy_version.txt" >&2
        errors=$((errors + 1))
    fi

    myapp_version="${SELINUX_ROOT}/myapp/policy_version.txt"
    if [[ -f "${myapp_version}" ]]; then
        modver_from_build="$(policy_version "${myapp_version}")"
        canonical_myapp="$(policy_version "${myapp_version}")"
        if [[ "${modver_from_build}" != "${canonical_myapp}" ]]; then
            echo "validate_version_consistency: build_rpms modver (${modver_from_build}) != ${myapp_version} (${canonical_myapp})" >&2
            errors=$((errors + 1))
        fi
    fi
fi

if [[ "${errors}" -ne 0 ]]; then
    exit 1
fi

echo "validate_version_consistency: all modules OK"
