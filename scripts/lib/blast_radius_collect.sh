#!/usr/bin/env bash
#
# blast_radius_collect.sh — Diff sesearch rule lines between two installed modules.
# Invoked on a host with selinux-policy-targeted (isolated store; not live kernel).
#
# sediff(1) does not accept standalone .pp module packages on EL9 (same as
# policy_module_diff_side.sh). Each side installs into an isolated copy of the
# targeted store; we diff sorted sesearch --allow -s <domain> plus filtered -T lines.
#
set -euo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=policy_module_sesearch.sh
source "${LIB_DIR}/policy_module_sesearch.sh"

# shellcheck source=policy_isolated_store.sh
source "${LIB_DIR}/policy_isolated_store.sh"

if [[ -z "${BLAST_RADIUS_MODULE:-}" ]]; then
    echo "blast_radius_collect: BLAST_RADIUS_MODULE is required (set by classify_policy_blast_radius.sh)" >&2
    exit 1
fi
if [[ -z "${BLAST_RADIUS_DOMAINS:-}" ]]; then
    echo "blast_radius_collect: BLAST_RADIUS_DOMAINS is required — pass --app NAME or set BLAST_RADIUS_DOMAINS" >&2
    exit 1
fi

MODULE="${BLAST_RADIUS_MODULE}"
DOMAINS="${BLAST_RADIUS_DOMAINS}"
BASE_PP="${1:?base.pp path}"
CAND_PP="${2:?candidate.pp path}"
OUT_DIR="${3:?output dir}"
mkdir -p "${OUT_DIR}"

filter_type_lines_for_domains() {
    local raw="$1"
    local out="$2"
    local -a doms=()
    IFS=',' read -r -a doms <<< "${DOMAINS}"
    : > "${out}"
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        for dom in "${doms[@]}"; do
            dom="${dom// /}"
            if [[ -n "${dom}" && "${line}" == *"${dom}"* ]]; then
                echo "${line}" >> "${out}"
                break
            fi
        done
    done < "${raw}"
    sort -u -o "${out}" "${out}"
}

collect_side() {
    local pp="$1"
    local allow_out="$2"
    local type_out="$3"

    local store_prefix kern errf ec
    store_prefix="$(isolated_store_create)"
    kern="$(isolated_store_kern "${store_prefix}")"

    semodule -n -r "${MODULE}" -s targeted -p "${store_prefix}" 2>/dev/null || true
    if ! semodule -n -s targeted -p "${store_prefix}" -i "${pp}"; then
        echo "blast_radius_collect: semodule -i failed for ${pp}" >&2
        isolated_store_destroy "${store_prefix}"
        return 1
    fi
    [[ -f "${kern}" ]] || {
        echo "blast_radius_collect: missing ${kern} after semodule -i ${pp}" >&2
        isolated_store_destroy "${store_prefix}"
        return 1
    }

    : > "${allow_out}"
    IFS=',' read -r -a doms <<< "${DOMAINS}"
    for dom in "${doms[@]}"; do
        dom="${dom// /}"
        [[ -n "${dom}" ]] || continue
        append_domain_allows "${kern}" "${dom}" "${allow_out}"
    done
    sort -u -o "${allow_out}" "${allow_out}"

    errf="$(mktemp)"
    # set -e would abort on sesearch's exit 1 before the status check below.
    ec=0
    sesearch -T "${kern}" >"${type_out}.raw" 2>"${errf}" || ec=$?
    if [[ -s "${errf}" ]]; then
        cat "${errf}" >&2
        rm -f "${errf}" "${type_out}.raw"
        isolated_store_destroy "${store_prefix}"
        return 1
    fi
    if [[ ${ec} -ne 0 && ${ec} -ne 1 ]]; then
        rm -f "${errf}" "${type_out}.raw"
        isolated_store_destroy "${store_prefix}"
        return "${ec}"
    fi
    rm -f "${errf}"
    filter_type_lines_for_domains "${type_out}.raw" "${type_out}"
    rm -f "${type_out}.raw"
    isolated_store_destroy "${store_prefix}"
}

collect_side "${BASE_PP}" "${OUT_DIR}/base_allow.txt" "${OUT_DIR}/base_type.txt"
collect_side "${CAND_PP}" "${OUT_DIR}/cand_allow.txt" "${OUT_DIR}/cand_type.txt"

comm -23 "${OUT_DIR}/cand_allow.txt" "${OUT_DIR}/base_allow.txt" > "${OUT_DIR}/added_allow.txt"
comm -23 "${OUT_DIR}/cand_type.txt" "${OUT_DIR}/base_type.txt" > "${OUT_DIR}/added_type.txt"
{
    cat "${OUT_DIR}/added_type.txt"
    cat "${OUT_DIR}/added_allow.txt"
} > "${OUT_DIR}/added_all.txt"
