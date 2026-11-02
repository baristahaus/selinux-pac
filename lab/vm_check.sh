#!/usr/bin/env bash
#
# vm_check.sh — Sync this checkout to the QA VM and run the compile checks there.
# Prints one PASS or FAIL line per check. The live policy store must not gain
# a bypass_* or pac_control module.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/lab_env.sh
source "${SCRIPT_DIR}/lib/lab_env.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0")

Sync to \$QA_HOST, then run:
  make integration-compile
  make integration-semantics
  bash scripts/reject_compiled_bypasses.sh
  bash tests/test_avc_epoch_window.sh
  bash tests/test_avc_query_epoch.sh
  make integration-blast-radius

After those, semodule -l on the host must not list bypass_* or pac_control.

Requires QA_HOST, PROD_HOST, and SSH_USER (lab/lab.env).
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

lab_env_require
bash "${SCRIPT_DIR}/sync_rhel_dev.sh"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR)
TARGET="${SSH_USER}@${QA_HOST}"
REMOTE="$(ssh "${SSH_OPTS[@]}" "${TARGET}" 'printf %s "$HOME/selinux-pac"')"
fail=0

run_check() {
    local name="$1"
    shift
    local out rc
    set +e
    out="$(ssh "${SSH_OPTS[@]}" "${TARGET}" "sudo -n bash -lc $(printf '%q' "cd $(printf '%q' "${REMOTE}") && $*")")"
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]] || grep -q 'SKIP ' <<<"${out}"; then
        echo "FAIL ${name}"
        printf '%s\n' "${out}" >&2
        fail=1
        return 0
    fi
    echo "PASS ${name}"
}

policy_before="$(ssh "${SSH_OPTS[@]}" "${TARGET}" "sudo -n sha256sum /sys/fs/selinux/policy")"

run_check integration-compile make integration-compile
run_check integration-semantics make integration-semantics
run_check reject_compiled_bypasses bash scripts/reject_compiled_bypasses.sh
run_check test_avc_epoch_window bash tests/test_avc_epoch_window.sh
run_check test_avc_query_epoch bash tests/test_avc_query_epoch.sh
run_check integration-blast-radius make integration-blast-radius

policy_after="$(ssh "${SSH_OPTS[@]}" "${TARGET}" "sudo -n sha256sum /sys/fs/selinux/policy")"

set +e
modules="$(ssh "${SSH_OPTS[@]}" "${TARGET}" "sudo -n semodule -l" 2>&1)"
mod_rc=$?
set -e
if [[ "${mod_rc}" -ne 0 ]] || [[ "${policy_before}" != "${policy_after}" ]] || printf '%s\n' "${modules}" | awk '{print $1}' | grep -Eq '^(bypass_|pac_control$)'; then
    echo "FAIL host-unchanged"
    printf '%s\n' "${modules}" >&2
    fail=1
else
    echo "PASS host-unchanged"
fi

exit "${fail}"
