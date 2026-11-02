#!/usr/bin/env bash
#
# reject_compiled_bypasses.sh — Compile each review-bypass fixture and fail
# unless the compiled-policy gate rejects it with that fixture's expected
# message. A clean types-only module must be accepted. A fixture that does
# not compile does not prove the gate.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=lib/compile_policy.sh
source "${SCRIPT_DIR}/lib/compile_policy.sh"

fixtures=(
    interface-macro
    split-line
    permissive-declaration
    file-type-star
    unconfined-domain-type
    load-policy-setenforce
    sys-module-sys-admin
    fc-relabel-shadow
    foreign-entrypoint
    dontaudit-forbidden
    can-setenforce
    can-load-policy
    can-read-shadow-passwords
    can-write-shadow-passwords
    exec-bin-alias
)

root="${PROJECT_ROOT}/tests/fixtures/compiled-bypasses"

run_gate() {
    local dir="$1"
    local pp
    pp="$(mktemp)"
    if ! compile_policy_module "${dir}" bypass "${pp}"; then
        rm -f "${pp}"
        return 2
    fi
    rm -f "${pp}"
    set +e
    out="$(bash "${SCRIPT_DIR}/validate_policy_semantics.sh" "${dir}" --app bypass 2>&1)"
    rc=$?
    set -e
    rm -f "${dir}/bypass.pp" "${dir}/bypass.mod"
    printf '%s\n' "${out}"
    return "${rc}"
}

clean="${root}/clean"
if [[ ! -f "${clean}/bypass.te" ]]; then
    echo "clean fixture is missing" >&2
    exit 1
fi
set +e
clean_out="$(run_gate "${clean}")"
clean_rc=$?
set -e
if [[ "${clean_rc}" -eq 2 ]]; then
    echo "clean fixture did not compile" >&2
    exit 1
fi
if [[ "${clean_rc}" -ne 0 ]]; then
    echo "clean fixture was rejected" >&2
    printf '%s\n' "${clean_out}" >&2
    exit 1
fi
echo "accepted clean"

fail=0
for name in "${fixtures[@]}"; do
    dir="${root}/${name}"
    if [[ ! -f "${dir}/bypass.te" || ! -f "${dir}/bypass.fc" || ! -f "${dir}/expected.txt" ]]; then
        echo "bypass fixture ${name} is missing bypass.te, bypass.fc, or expected.txt" >&2
        exit 1
    fi
    expected="$(tr -d '\n' <"${dir}/expected.txt")"
    set +e
    out="$(run_gate "${dir}")"
    rc=$?
    set -e
    if [[ "${rc}" -eq 2 ]]; then
        echo "bypass fixture ${name} did not compile" >&2
        exit 1
    fi
    if [[ "${rc}" -eq 0 ]]; then
        echo "bypass fixture ${name} was accepted" >&2
        printf '%s\n' "${out}" >&2
        fail=1
        continue
    fi
    if ! grep -F -q "${expected}" <<<"${out}"; then
        echo "bypass fixture ${name} was rejected without expected message: ${expected}" >&2
        printf '%s\n' "${out}" >&2
        fail=1
        continue
    fi
    echo "rejected ${name}"
done

if [[ "${fail}" -ne 0 ]]; then
    echo "compiled-policy gate did not reject every review bypass with its expected message" >&2
    exit 1
fi
echo "compiled-policy gate rejected every review bypass"
