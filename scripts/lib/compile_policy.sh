#!/usr/bin/env bash
#
# compile_policy.sh — Shared refpolicy Makefile compile (native selinux-policy-devel).
#
# Source from other scripts:
#   source "${SCRIPT_DIR}/lib/compile_policy.sh"
#
set -euo pipefail

has_selinux_devel() {
    [[ -f /usr/share/selinux/devel/Makefile ]]
}

compile_toolchain_available() {
    has_selinux_devel
}

infer_policy_module_name() {
    local policy_dir="$1"
    local explicit="${2:-}"

    if [[ -n "${explicit}" ]]; then
        echo "${explicit}"
        return 0
    fi
    local te name="" count=0
    for te in "${policy_dir}"/*.te; do
        [[ -e "${te}" ]] || continue
        name="$(basename "${te}" .te)"
        count=$((count + 1))
    done
    if [[ "${count}" -eq 1 ]]; then
        echo "${name}"
        return 0
    fi
    echo "[ERROR] compile_policy_module: pass module name (${count} .te files in ${policy_dir})" >&2
    return 1
}

compile_policy_module() {
    local policy_dir="$1"
    local module_name="${2:-}"
    module_name="$(infer_policy_module_name "${policy_dir}" "${module_name}")" || return 1
    local output_pp="${3:-${policy_dir}/${module_name}.pp}"

    local te="${policy_dir}/${module_name}.te"
    local fc="${policy_dir}/${module_name}.fc"
    local if_file="${policy_dir}/${module_name}.if"

    [[ -f "${te}" && -f "${fc}" ]] || {
        echo "[ERROR] Missing ${te} or ${fc}" >&2
        return 1
    }

    rm -f "${output_pp}" "${policy_dir}/${module_name}.mod"

    if ! has_selinux_devel; then
        if [[ "$(uname -s)" == Darwin ]]; then
            echo "[ERROR] macOS has no selinux-policy-devel. Compile on rhel-qa, then copy the .pp here:" >&2
            echo "  ssh \${SSH_USER}@\${QA_HOST} 'cd ~/selinux-pac && bash scripts/compile_and_validate.sh selinux'" >&2
            echo "  scp \${SSH_USER}@\${QA_HOST}:~/selinux-pac/selinux/${module_name}.pp ${policy_dir}/" >&2
        else
            echo "[ERROR] Install selinux-policy-devel (dnf install selinux-policy-devel). Compile on rhel-qa, not a non-SELinux host." >&2
        fi
        return 1
    fi

    local work_dir
    work_dir="$(mktemp -d)"
    cp "${te}" "${fc}" "${work_dir}/"
    if [[ -f "${if_file}" ]]; then
        cp "${if_file}" "${work_dir}/"
    fi
    # Callers often invoke this from `if !`, which disables set -e for the
    # whole function. A failing make must still return non-zero; otherwise
    # `rm -rf` below succeeds and the caller treats a missing .pp as success.
    if ! make -C "${work_dir}" -f /usr/share/selinux/devel/Makefile "${module_name}.pp"; then
        rm -rf "${work_dir}"
        return 1
    fi
    cp "${work_dir}/${module_name}.pp" "${output_pp}"
    rm -rf "${work_dir}"
}

verify_pp_matches_sources() {
    local policy_dir="$1"
    local module_name="${2:-}"
    module_name="$(infer_policy_module_name "${policy_dir}" "${module_name}")" || return 1

    local committed_pp="${policy_dir}/${module_name}.pp"
    local built_pp
    built_pp="$(mktemp)"

    compile_policy_module "${policy_dir}" "${module_name}" "${built_pp}"

    if [[ ! -f "${committed_pp}" ]]; then
        echo "[ERROR] Committed policy package missing: ${committed_pp}" >&2
        rm -f "${built_pp}"
        return 1
    fi

    if ! cmp -s "${committed_pp}" "${built_pp}"; then
        echo "[ERROR] ${committed_pp} drifts from ${module_name}.te/.fc — rebuild and commit" >&2
        rm -f "${built_pp}"
        return 1
    fi

    rm -f "${built_pp}"
    echo "[INFO] ${committed_pp} matches compiled output from sources"
}
