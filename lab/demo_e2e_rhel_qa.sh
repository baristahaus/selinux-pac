#!/usr/bin/env bash
#
# demo_e2e_rhel_qa.sh — Typewriter talk track for the QA VM ($QA_HOST).
#
# Run ON rhel-qa, not on the Mac. Demo app is Spring Boot shopapi.
# This is one window of the ~45 min three-host walkthrough (see demo_e2e_mac.sh).
# Single-host customer talk (~20 min): bash lab/demo_present.sh
#
#   bash lab/demo_e2e_rhel_qa.sh --part app
#   bash lab/demo_e2e_rhel_qa.sh --part generate
#   bash lab/demo_e2e_rhel_qa.sh --part generate --skip-export
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib/talk.sh" ]]; then
    # shellcheck source=lib/talk.sh
    source "${SCRIPT_DIR}/lib/talk.sh"
elif [[ -f "${HOME}/selinux-pac/lab/lib/talk.sh" ]]; then
    # shellcheck source=lib/talk.sh
    source "${HOME}/selinux-pac/lab/lib/talk.sh"
    SCRIPT_DIR="${HOME}/selinux-pac/lab"
else
    echo "Cannot find lab/lib/talk.sh. On this VM: cd ~/selinux-pac && git pull" >&2
    exit 1
fi

TLAB_PS1='[ansible@rhel-qa selinux-pac]$'
REPO_URL="${REPO_URL:-https://github.com/anurag-saran/selinux-pac.git}"
APP_ROOT="${APP_ROOT:-${HOME}/selinux-pac}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Presenter script for the QA VM (${DEV_HOST:-QA_HOST}). Do not run this on the Mac.
Demo application is shopapi (Spring Boot).

  --part app              prepare the host, then sepac status and sepac capture
  --part generate         sepac generate, check, load
  --part all              app, then pause, then generate
  --all-urls              With --part app: capture /feature-spool too (happy path)
  --skip-export           With --part generate: use policy_out/avc.log from prod

$(e2e_usage_common)
EOF
}

e2e_parse_args "$@"
e2e_require_rhel "the QA VM (${DEV_HOST})"

part_app() {
    e2e_banner "QA VM — collect the evidence (${DEV_HOST})"
    if [[ "${E2E_DRY}" -eq 0 ]]; then
        sudo timedatectl set-ntp true 2>/dev/null || true
        sudo chronyc makestep 2>/dev/null || true
    fi
    if [[ -d "${HOME}/selinux-demo" && ! -d "${HOME}/selinux-pac" ]]; then
        mv "${HOME}/selinux-demo" "${HOME}/selinux-pac" 2>/dev/null || true
    fi
    lab_quiet "Hostname rhel-qa" "sudo hostnamectl set-hostname rhel-qa"
    lab_quiet "Java, Maven and the SELinux tools" "sudo dnf install -y git java-17-openjdk-headless maven policycoreutils policycoreutils-python-utils setools-console audit selinux-policy-devel"
    if [[ ! -d "${HOME}/selinux-pac" ]]; then
        lab_quiet "Clone the tool repo" "git clone ${REPO_URL} ${HOME}/selinux-pac"
    fi
    [[ "${E2E_DRY}" -eq 1 ]] || cd "${HOME}/selinux-pac"
    lab_quiet "Install shopapi with the types-only seed, domain permissive" "sudo bash lab/demo_bootstrap.sh --shopapi-only"
    tlab_pause

    say "shopapi runs as shopapi_t; permissive, so SELinux logs and doesn't block"
    present_cmd "sepac status shopapi"
    tlab_pause

    if [[ "${E2E_ALL_URLS}" -eq 1 ]]; then
        say "Restart with full auditing; call every endpoint, /feature-spool too"
        present_cmd "sepac capture shopapi --full-audit --url /feature-spool"
    else
        say "Restart with full auditing; call the endpoints in the manifest"
        present_cmd "sepac capture shopapi --full-audit"
    fi
    tlab_checkpoint "Evidence collected under Enforcing. Go back to the Mac."
}

part_generate() {
    e2e_banner "QA VM — write the policy from the evidence"
    [[ "${E2E_DRY}" -eq 1 ]] || cd "${HOME}/selinux-pac"
    if [[ "${E2E_SKIP_EXPORT}" -eq 1 ]]; then
        lab_quiet "The prod denial export is in policy_out/avc.log" "test -s ${APP_ROOT}/policy_out/avc.log"
        say "Generate from the prod log"
        present_cmd "sepac generate shopapi --skip-export --apply --approve execmem"
    else
        say "Generate; execmem was reviewed, /etc/passwd stays refused"
        present_cmd "sepac generate shopapi --apply --approve execmem"
    fi
    say "The gate CI runs on the pull request"
    present_cmd "sepac check shopapi"
    say "Load it on QA: module, file labels, port"
    present_cmd "sepac load shopapi"
    tlab_checkpoint "selinux/shopapi/ now holds the reviewed policy. Go back to the Mac."
}

case "${E2E_PART}" in
    app) part_app ;;
    generate) part_generate ;;
    fail)
        echo "Fail/retest runs on rhel-prod, not here:" >&2
        echo "  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part fail" >&2
        exit 2
        ;;
    all)
        part_app
        e2e_handoff "Leave this window open. On the Mac, do not canary yet. Come back here for --part generate.
Press Enter when you are ready to generate."
        part_generate
        ;;
    *)
        echo "Unknown --part ${E2E_PART} (use app, generate, or all)" >&2
        exit 2
        ;;
esac

echo
echo -e "${TLAB_BOLD}End of this QA talk-track part.${TLAB_NC} Do not type exit until the Mac script asks you to."
echo
