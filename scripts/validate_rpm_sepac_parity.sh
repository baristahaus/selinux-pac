#!/usr/bin/env bash
#
# validate_rpm_sepac_parity.sh — Ensure selinux-pac.spec ships every file
# listed in packaging/sepac_scripts.list.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST="${ROOT}/packaging/sepac_scripts.list"
SPEC="${ROOT}/packaging/selinux-pac.spec"

if [[ ! -f "${LIST}" ]]; then
    echo "MISSING packaging/sepac_scripts.list" >&2
    exit 1
fi
if [[ ! -f "${SPEC}" ]]; then
    echo "MISSING packaging/selinux-pac.spec" >&2
    exit 1
fi

missing=0
while IFS= read -r rel || [[ -n "${rel}" ]]; do
    rel="${rel%%#*}"
    rel="${rel#"${rel%%[![:space:]]*}"}"
    rel="${rel%"${rel##*[![:space:]]}"}"
    [[ -z "${rel}" ]] && continue

    # Check source file exists
    if [[ ! -f "${ROOT}/${rel}" ]]; then
        echo "MISSING source: ${rel}" >&2
        missing=1
    fi
done < "${LIST}"

# Check spec ships cli/ and scripts/
if ! grep -q 'selinux-pac/cli/\*\.py' "${SPEC}"; then
    echo "SPEC does not install cli Python modules" >&2
    missing=1
fi
if ! grep -q 'selinux-pac/scripts/\*\.sh' "${SPEC}"; then
    echo "SPEC does not install scripts" >&2
    missing=1
fi
if ! grep -q 'selinux-pac/scripts/lib/\*\.sh' "${SPEC}"; then
    echo "SPEC does not install scripts/lib shell modules" >&2
    missing=1
fi
if ! grep -q 'selinux-pac/scripts/lib/\*\.py' "${SPEC}"; then
    echo "SPEC does not install scripts/lib Python modules" >&2
    missing=1
fi
if ! grep -q 'bash-completion/completions/sepac' "${SPEC}"; then
    echo "SPEC does not install bash completion" >&2
    missing=1
fi
if ! grep -q 'sepac\.8\.gz' "${SPEC}"; then
    echo "SPEC does not install man page" >&2
    missing=1
fi
if ! grep -q 'selinux-pac/sepac.conf' "${SPEC}"; then
    echo "SPEC does not install sepac.conf" >&2
    missing=1
fi

if [[ "${missing}" -ne 0 ]]; then
    exit 1
fi
echo "OK selinux-pac sources match packaging spec"
