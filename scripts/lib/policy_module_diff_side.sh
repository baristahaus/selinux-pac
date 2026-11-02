#!/usr/bin/env bash
#
# policy_module_diff_side.sh — Install one .pp and dump sorted sesearch allows.
#
# sediff(1) does not accept standalone module .pp files on EL9; we use semodule -i
# into an isolated copy of the targeted store, then sesearch --allow per app domain.
#
set -euo pipefail

PP="${1:?module.pp path}"
OUT="${2:?output rules file}"
DOMAINS="${3:?csv domains}"
APP="${4:?module name}"

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=policy_module_sesearch.sh
source "${LIB_DIR}/policy_module_sesearch.sh"
# shellcheck source=policy_isolated_store.sh
source "${LIB_DIR}/policy_isolated_store.sh"

store_root="$(isolated_store_create)"
kern="$(isolated_store_kern "${store_root}")"

semodule -n -r "${APP}" -s targeted -p "${store_root}" 2>/dev/null || true
if ! semodule -n -s targeted -p "${store_root}" -i "${PP}"; then
    echo "policy_module_diff_side: semodule -i failed for ${PP}" >&2
    isolated_store_destroy "${store_root}"
    exit 1
fi

[[ -f "${kern}" ]] || {
    echo "policy_module_diff_side: missing ${kern} after semodule -i" >&2
    isolated_store_destroy "${store_root}"
    exit 1
}

: > "${OUT}"
IFS=',' read -r -a doms <<< "${DOMAINS}"
for dom in "${doms[@]}"; do
    dom="${dom// /}"
    [[ -n "${dom}" ]] || continue
    append_domain_allows "${kern}" "${dom}" "${OUT}"
done
sort -u -o "${OUT}" "${OUT}"
isolated_store_destroy "${store_root}"
