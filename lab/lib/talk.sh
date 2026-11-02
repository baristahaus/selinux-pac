#!/usr/bin/env bash
# lab/lib/talk.sh — everything the demo scripts share (source only):
# colours, the step runner (one caption, type, Enter, run), quiet lab plumbing,
# banners and pauses, and the two-host window handoffs.
# shellcheck disable=SC2034  # colours and flags are read by the scripts that source this

TLAB_RED='\033[0;31m'
TLAB_GREEN='\033[0;32m'
TLAB_YELLOW='\033[1;33m'
TLAB_CYAN='\033[0;36m'
TLAB_BOLD='\033[1m'
TLAB_DIM='\033[2m'
TLAB_NC='\033[0m'

TLAB_TYPE_DELAY="${TLAB_TYPE_DELAY:-0.02}"
TLAB_NO_TYPE="${TLAB_NO_TYPE:-0}"
TLAB_AUTO="${TLAB_AUTO:-0}"
PRESENT_STEP="${PRESENT_STEP:-1}"

E2E_DRY="${E2E_DRY:-0}"
E2E_PART="${E2E_PART:-all}"
E2E_SKIP_EXPORT="${E2E_SKIP_EXPORT:-0}"
E2E_SHORT="${E2E_SHORT:-0}"
E2E_ALL_URLS="${E2E_ALL_URLS:-0}"
# shellcheck source=lab_env.sh
_talk_here="${BASH_SOURCE[0]%/*}"
source "${_talk_here}/lab_env.sh"
unset _talk_here
lab_env_load

# ── The step runner ──────────────────────────────────────────────────────────
# One caption line above a command, shown as a shell comment.
say() {
    echo -e "${TLAB_DIM}# $*${TLAB_NC}"
}

# Type the command and leave the cursor at the end of the line.
present_type() {
    local cmd="$1" i ps1="${TLAB_PS1}"
    [[ "${ps1}" == *" " ]] || ps1+=" "
    echo -n -e "${TLAB_GREEN}${ps1}${TLAB_NC}"
    if [[ "${TLAB_NO_TYPE}" -eq 1 ]]; then
        printf '%s' "${cmd}"
        return 0
    fi
    for ((i = 0; i < ${#cmd}; i++)); do
        printf '%s' "${cmd:i:1}"
        sleep "${TLAB_TYPE_DELAY}"
    done
}

# Wait for Enter. Keys are not echoed, so a stray key cannot garble the line.
present_wait() {
    if [[ "${TLAB_AUTO}" -eq 0 && "${PRESENT_STEP}" -eq 1 ]]; then
        read -r -s _ || true
    fi
    echo
}

# present_cmd COMMAND [run|fail] [DRY_RUN_SAMPLE]
#   run   A non-zero exit is shown in yellow and the talk keeps going.
#   fail  The step is meant to be refused. Exit 0 is the surprise.
# --dry-run prints DRY_RUN_SAMPLE (what a good screen shows) instead of running.
present_cmd() {
    local cmd="$1" mode="${2:-run}" sample="${3:-}" rc
    present_type "${cmd}"
    present_wait
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        echo -e "${TLAB_DIM}(dry-run)${sample:+ ${sample}}${TLAB_NC}"
        echo
        return 0
    fi
    set +e
    eval "${cmd}"
    rc=$?
    set -e
    echo
    if [[ "${mode}" == "fail" ]]; then
        if [[ "${rc}" -ne 0 ]]; then
            echo -e "${TLAB_YELLOW}exit ${rc}: blocked on purpose${TLAB_NC}"
        else
            echo -e "${TLAB_RED}exit 0: this step should have been blocked${TLAB_NC}"
        fi
        echo
    elif [[ "${rc}" -ne 0 ]]; then
        echo -e "${TLAB_YELLOW}exit ${rc}${TLAB_NC}"
        echo
    fi
    return 0
}

# Lab plumbing: host prep, copying files between the VMs, serving the repo.
# Not what the demo is about, so it is not typed and does not wait for Enter.
# One dim line; the output appears only if it fails.
lab_quiet() {
    local what="$1" cmd="$2" log rc
    echo -e "${TLAB_DIM}· ${what}${TLAB_NC}"
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        echo -e "${TLAB_DIM}  (dry-run) ${cmd}${TLAB_NC}"
        return 0
    fi
    # A file, not $(...): a step may leave a server running in the background,
    # and a command substitution would wait for it forever.
    log="$(mktemp "${TMPDIR:-/tmp}/lab_quiet.XXXXXX")"
    set +e
    eval "${cmd}" >"${log}" 2>&1
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then
        cat "${log}"
        echo -e "${TLAB_YELLOW}exit ${rc}: ${what}${TLAB_NC}"
    fi
    rm -f "${log}"
    return 0
}

# ── Banners and pauses ───────────────────────────────────────────────────────

tlab_lab_only_banner() {
    echo
    echo -e "${TLAB_RED}${TLAB_BOLD}LAB ONLY${TLAB_NC}${TLAB_RED} — $*${TLAB_NC}"
    echo
}

tlab_checkpoint() {
    echo -e "${TLAB_GREEN}Checkpoint:${TLAB_NC} $*"
    echo
}

tlab_pause() {
    if [[ "${TLAB_AUTO}" -eq 1 ]]; then
        return 0
    fi
    read -r -p "$(echo -e "${TLAB_DIM}Press Enter for the next step…${TLAB_NC} ")" _
}

e2e_banner() {
    echo
    echo -e "${TLAB_BOLD}${TLAB_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${TLAB_NC}"
    echo -e "${TLAB_BOLD}  $*${TLAB_NC}"
    echo -e "${TLAB_BOLD}${TLAB_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${TLAB_NC}"
    echo
}

# ── The two-host demo ───────────────────────────────────────────────────────

e2e_usage_common() {
    cat <<EOF
The one-host sepac demo (~20 min) is lab/demo_present.sh.
Guides: docs/demo.md  ·  docs/guides/302-TECHNICAL.md

Options:
  --auto       No Enter pauses. On the Mac script, also SSH and run the VM talk tracks.
  --no-type    Print commands instantly (no typewriter)
  --dry-run    Type the commands only; run nothing (no SSH client required)
  --short      Happy-path 302: complete module, no outage/rollback (~20 min)
  --all-urls   (rhel-qa --part app) capture /feature-spool too, so the module is complete
  --skip-export  (rhel-qa --part generate) use existing policy_out/avc.log
  -h, --help   Show help
EOF
}

# Hide OpenSSH PQ / banner warnings in talk-track output. Displayed commands
# stay plain `ssh` / `scp`; the wrapper is on PATH for the rest of the script.
e2e_install_quiet_ssh() {
    local real_ssh real_scp bindir
    # Dry-run never opens a connection (laptop eval with no VMs / no SSH client).
    [[ "${E2E_DRY:-0}" -eq 1 ]] && return 0
    if [[ -n "${E2E_SSH_WRAP_DIR:-}" && -x "${E2E_SSH_WRAP_DIR}/ssh" ]]; then
        return 0
    fi
    real_ssh="$(command -v ssh || true)"
    real_scp="$(command -v scp || true)"
    [[ -n "${real_ssh}" && -x "${real_ssh}" && -n "${real_scp}" && -x "${real_scp}" ]] || return 0
    bindir="$(mktemp -d "${TMPDIR:-/tmp}/selinux-pac-e2e-ssh.XXXXXX")"
    cat >"${bindir}/ssh" <<EOF
#!/bin/sh
exec $(printf '%q' "${real_ssh}") -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR "\$@"
EOF
    cat >"${bindir}/scp" <<EOF
#!/bin/sh
exec $(printf '%q' "${real_scp}") -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR "\$@"
EOF
    chmod +x "${bindir}/ssh" "${bindir}/scp"
    E2E_SSH_WRAP_DIR="${bindir}"
    export PATH="${bindir}:${PATH}"
}

e2e_auto_flags() {
    local flags="--auto"
    if [[ "${TLAB_NO_TYPE}" -eq 1 ]]; then
        flags+=" --no-type"
    fi
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        flags+=" --dry-run"
    fi
    if [[ "${E2E_SKIP_EXPORT}" -eq 1 ]]; then
        flags+=" --skip-export"
    fi
    if [[ "${E2E_ALL_URLS}" -eq 1 ]]; then
        flags+=" --all-urls"
    fi
    echo "${flags}"
}

e2e_parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --auto) TLAB_AUTO=1; shift ;;
            --no-type) TLAB_NO_TYPE=1; shift ;;
            --dry-run|--say-only) E2E_DRY=1; shift ;;
            --short) E2E_SHORT=1; shift ;;
            --all-urls) E2E_ALL_URLS=1; shift ;;
            --part) E2E_PART="$2"; shift 2 ;;
            --skip-export) E2E_SKIP_EXPORT=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
        esac
    done
    lab_env_require
    e2e_install_quiet_ssh
}

# Interactive: print the switch-window talk track and wait.
# --auto: optionally run $2 (usually ssh … demo_e2e_rhel_*.sh --auto) instead of waiting.
e2e_handoff() {
    local msg="$1"
    local auto_cmd="${2:-}"
    echo
    echo -e "${TLAB_BOLD}${TLAB_YELLOW}>>> Switch windows${TLAB_NC}"
    echo -e "${TLAB_YELLOW}${msg}${TLAB_NC}"
    echo
    if [[ "${TLAB_AUTO}" -eq 1 && -n "${auto_cmd}" ]]; then
        present_cmd "${auto_cmd}"
        return 0
    fi
    tlab_pause
}

e2e_require_mac() {
    if [[ "$(uname -s)" != Darwin ]]; then
        echo "This script is the Mac talk track. On a RHEL VM use demo_e2e_rhel_qa.sh or demo_e2e_rhel_prod.sh." >&2
        exit 1
    fi
}

e2e_require_rhel() {
    local who="$1"
    if [[ "$(uname -s)" == Darwin ]]; then
        echo "This script runs ON ${who}, not on the Mac." >&2
        echo "On the Mac: ssh ${E2E_SSH_USER}@${DEV_HOST}   or   ssh ${E2E_SSH_USER}@${PROD_HOST}" >&2
        exit 1
    fi
    if ! command -v getenforce >/dev/null 2>&1; then
        echo "getenforce not found — this is not a SELinux host." >&2
        exit 1
    fi
}
