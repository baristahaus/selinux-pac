#!/usr/bin/env bash
#
# demo_e2e_rhel_prod.sh — Typewriter talk track for the PROD VM ($PROD_HOST).
#
# Run ON rhel-prod, not on the Mac. Do not git clone this repo onto prod.
# Demo app is Spring Boot shopapi.
#
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part app
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part rpms
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak-avc
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak-clean
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part fail
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part restore
#   bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part retest
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib/talk.sh" ]]; then
    # shellcheck source=lib/talk.sh
    source "${SCRIPT_DIR}/lib/talk.sh"
elif [[ -f "${HOME}/e2e-demo/lib/talk.sh" ]]; then
    # shellcheck source=lib/talk.sh
    source "${HOME}/e2e-demo/lib/talk.sh"
    SCRIPT_DIR="${HOME}/e2e-demo"
else
    echo "Cannot find lib/talk.sh. From the Mac, finish the shopapi scp, then re-run." >&2
    exit 1
fi

TLAB_PS1='[ansible@rhel-prod ~]$'
APP_BUNDLE="${HOME}/e2e-demo"
AVC_EXPORT="/tmp/prod-feature-spool.avc"
SOAK_FAIL_AVC="/var/lib/selinux-policy-ops/shopapi/selinux_soak_last_fail.avc"
SOAK_FAIL_JSON="/var/lib/selinux-policy-ops/shopapi/selinux_soak_last_fail.json"
SHOP_PORT="${SHOPAPI_PORT:-8091}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Presenter script for the PROD VM (${PROD_HOST:-PROD_HOST}). Do not run this on the Mac.
Do not git clone onto this box — shopapi files from scp, policy from RPMs.
This is one window of the ~45 min three-host walkthrough (see demo_e2e_mac.sh).

  --part app        Prepare the host and install shopapi (no policy module, unconfined)
  --part rpms       The signed repo (policy arrives with sepac canary)
  --part soak       sepac capture with /feature-spool; the denial is logged
  --part soak-avc   The soak gate's fail file
  --part soak-clean After the fix: sepac capture, all 200, no new denials
  --part fail       Enforcing: sepac capture shows the 500 and the denial
  --part restore    After sepac rollback: sepac status
  --part retest     After the recanary: sepac capture and sepac status

$(e2e_usage_common)
EOF
}

e2e_parse_args "$@"
e2e_require_rhel "the PROD VM (${PROD_HOST})"

export_spool_avc() {
    lab_quiet "Export the spool denial for rhel-qa (${AVC_EXPORT})" "sudo grep 'avc:  denied' /var/log/audit/audit.log | grep shopapi_t | grep -E 'var_spool_t|/var/spool/shopapi' | tail -20 | sudo tee ${AVC_EXPORT} >/dev/null && sudo chmod a+r ${AVC_EXPORT} && test -s ${AVC_EXPORT}"
}

part_app() {
    e2e_banner "PROD VM — shopapi, no git clone, no policy module yet"
    if [[ "${E2E_DRY}" -eq 0 ]]; then
        sudo timedatectl set-ntp true 2>/dev/null || true
        sudo chronyc makestep 2>/dev/null || true
    fi
    if [[ ! -f "${APP_BUNDLE}/lab/demo_bootstrap.sh" && "${E2E_DRY}" -eq 0 ]]; then
        echo "Missing ${APP_BUNDLE}/lab/demo_bootstrap.sh. On the Mac, finish the scp, then re-run --part app." >&2
        exit 1
    fi
    lab_quiet "Hostname rhel-prod" "sudo hostnamectl set-hostname rhel-prod"
    lab_quiet "Java and the SELinux tools" "sudo dnf install -y java-17-openjdk-headless python3 python3-pyyaml policycoreutils policycoreutils-python-utils setools-console audit"
    lab_quiet "Install shopapi: JVM and unit, unconfined until the RPM arrives" "sudo bash ${APP_BUNDLE}/lab/demo_bootstrap.sh --shopapi-only --no-seed --unconfined"
    say "shopapi answers; no policy on this host yet"
    present_cmd "curl -sS -o /dev/null -w '/health %{http_code}\n' http://127.0.0.1:${SHOP_PORT}/health"
    tlab_checkpoint "shopapi is up. Policy is not installed yet. Go back to the Mac."
}

part_rpms() {
    e2e_banner "PROD VM — policy arrives from the canary, not by hand"
    say "The internal repo is configured with gpgcheck=1 and its key imported"
    present_cmd "sudo dnf repolist && rpm -q gpg-pubkey"
    tlab_checkpoint "The process is still unconfined. Go back to the Mac for sepac canary."
}

part_soak() {
    e2e_banner "PROD VM — soak: /feature-spool is not in this module"
    say "The canary installed sepac and the policy; call every endpoint and the new feature"
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool"
    say "The spool denial that will fail the soak gate"
    present_cmd "sepac denials shopapi --since boot --last 5"
    export_spool_avc
    tlab_checkpoint "A shopapi denial for /var/spool/shopapi is logged. Go back to the Mac."
}

part_soak_avc() {
    e2e_banner "PROD VM — the soak gate kept its evidence"
    say "sepac soak wrote the failing denials next to its verdict"
    present_cmd "sudo ls -l ${SOAK_FAIL_JSON} ${SOAK_FAIL_AVC}"
    tlab_checkpoint "The fail file is there. Go back to the Mac."
}

part_soak_clean() {
    e2e_banner "PROD VM — clean soak after the fix"
    say "Every endpoint and the spool feature, with the new module"
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool"
    tlab_checkpoint "HTTP 200 everywhere, no new denials. Go back to the Mac."
}

part_fail() {
    e2e_banner "PROD VM — the new feature is blocked once enforcing"
    say "/feature-spool writes /var/spool/shopapi, which the first module does not cover"
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool"
    export_spool_avc
    tlab_checkpoint "HTTP 500 and the denial. Go back to the Mac: rollback, then generate on rhel-qa."
}

part_restore() {
    e2e_banner "PROD VM — after the rollback"
    say "Host Enforcing, shopapi_t permissive again, the app answers"
    present_cmd "sepac status shopapi"
    tlab_checkpoint "Host is still Enforcing. App is up. Policy is not fixed yet."
}

part_retest() {
    e2e_banner "PROD VM — the fix arrived as a new RPM"
    say "Enforcing, and the spool feature works"
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool && sepac status shopapi"
    tlab_checkpoint "shopapi_t enforcing."
}

case "${E2E_PART}" in
    app) part_app ;;
    rpms|all) part_rpms ;;
    soak) part_soak ;;
    soak-avc) part_soak_avc ;;
    soak-clean) part_soak_clean ;;
    fail) part_fail ;;
    restore) part_restore ;;
    retest) part_retest ;;
    *)
        echo "Unknown --part ${E2E_PART} (use app, rpms, soak, soak-avc, soak-clean, fail, restore, retest)" >&2
        exit 2
        ;;
esac

echo
echo -e "${TLAB_BOLD}End of this PROD talk-track part.${TLAB_NC} Playbooks run on the Mac, not here."
echo
