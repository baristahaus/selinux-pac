#!/usr/bin/env bash
#
# demo_e2e_mac.sh — Typewriter talk track for the Mac (Ansible controller).
#
# shopapi (Spring Boot): generate → PR → prod canary/soak →
# talk-only enforce → /feature-spool 500 → rollback → generate on rhel-qa →
# second PR → recanary.
#
#   bash lab/demo_e2e_mac.sh
#   bash lab/demo_e2e_mac.sh --dry-run
#   bash lab/demo_e2e_mac.sh --auto --no-type
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/talk.sh
source "${SCRIPT_DIR}/lib/talk.sh"

TLAB_PS1='${USER}@mac selinux-pac %'
DEMO_PROD_FORCE_ENFORCE="${DEMO_PROD_FORCE_ENFORCE:-true}"
export DEMO_REHEARSAL=1

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Presenter script for THIS Mac. Demo application is shopapi (Spring Boot).
Three-host production walkthrough (~45 min): this window + rhel-qa + rhel-prod.
Happy-path only (~20 min): add --short.
Do not run this as the first customer conversation.
Single-host customer talk (~20 min): bash lab/demo_present.sh

$(e2e_usage_common)

Other windows (do not run those scripts here unless using --auto):
  ssh ${E2E_SSH_USER:-SSH_USER}@${DEV_HOST:-QA_HOST}   →  bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh
  ssh ${E2E_SSH_USER:-SSH_USER}@${PROD_HOST:-PROD_HOST}  →  bash ~/e2e-demo/demo_e2e_rhel_prod.sh
EOF
}

mac_copy_prod_bundle() {
    lab_quiet "Copy the prod talk track and shopapi over scp (prod never gets a git clone)" "ssh ${E2E_SSH_USER}@${PROD_HOST} 'mkdir -p ~/e2e-demo/lib ~/e2e-demo/lab/lib ~/e2e-demo/lab/apps/shopapi/target ~/e2e-demo/scripts/lib ~/e2e-demo/config' && scp lab/demo_e2e_rhel_prod.sh ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/ && scp lab/lib/talk.sh lab/lib/lab_env.sh ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/lib/ && scp lab/lab.env ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/lab.env && scp lab/demo_bootstrap.sh ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/lab/ && scp lab/lib/demo_estate.sh ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/lab/lib/ && scp scripts/lib/app_manifest.py scripts/lib/manifest_shell.sh ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/scripts/lib/ && scp config/shopapi.manifest.yml ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/config/ && scp -r lab/apps/shopapi/. ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/lab/apps/shopapi/"
}

mac_scp_generated_from_dev() {
    lab_quiet "Copy the generated policy from rhel-qa into this checkout" "mkdir -p policy_out selinux/shopapi && scp ${E2E_SSH_USER}@${DEV_HOST}:~/selinux-pac/selinux/shopapi/shopapi.te ${E2E_SSH_USER}@${DEV_HOST}:~/selinux-pac/selinux/shopapi/shopapi.fc ${E2E_SSH_USER}@${DEV_HOST}:~/selinux-pac/selinux/shopapi/policy_version.txt ${E2E_SSH_USER}@${DEV_HOST}:~/selinux-pac/selinux/shopapi/shopapi.pp selinux/shopapi/ && ls -l selinux/shopapi/shopapi.te selinux/shopapi/shopapi.pp && cat selinux/shopapi/policy_version.txt"
}

mac_open_policy_pr() {
    say "The CI gate on this laptop, then open the pull request"
    present_cmd "sepac check shopapi && bash lab/demo_open_generated_pr.sh || true"
    tlab_checkpoint "If gh is logged in, a PR URL printed."
    tlab_pause
}

mac_canary_enforce_dev() {
    say "Canary on QA — shopapi_t permissive, the rest enforcing"
    present_cmd "sepac canary --env dev"
    tlab_checkpoint "failed=0. shopapi_t events should be 0 raw / 0 net-new."
    tlab_pause

    tlab_lab_only_banner "Dev inventory waits 0 days so this talk can lock down. Never copy soak_min_days: 0 onto prod (inventory.production.yml stays at 7 days)."
    say "Enforce on QA (production inventory is 7 days plus a change ticket)"
    present_cmd "sepac enforce --env dev --ticket LAB"
    tlab_checkpoint "failed=0. shopapi_t is no longer permissive."
}

mac_serve_repo() {
    local repo_host="${REPO_HOST:-}"
    if [[ -z "${repo_host}" ]]; then
        repo_host="$(ifconfig bridge100 2>/dev/null | awk '/inet /{print $2}' || true)"
    fi
    if [[ -z "${repo_host}" && "${E2E_DRY}" -eq 1 ]]; then
        repo_host="REPO_HOST"
    fi
    if [[ -z "${repo_host}" ]]; then
        echo "Set REPO_HOST in lab/lab.env (the address both VMs can reach on this Mac)." >&2
        exit 1
    fi
    lab_quiet "Serve the signed repo from this Mac (UTM keeps the VMs apart; the private key stays on rhel-qa)" "mkdir -p dist/lab-repo && rsync -az --delete -e 'ssh -o BatchMode=yes -o ConnectTimeout=15' ${E2E_SSH_USER}@${DEV_HOST}:~/selinux-pac/dist/lab-repo/ dist/lab-repo/ && test -f dist/lab-repo/RPM-GPG-KEY && test -d dist/lab-repo/repodata && ls dist/lab-repo/*.rpm >/dev/null && test -z \"\$(find dist/lab-repo \\( -name '*private*' -o -name '*secring*' \\) -print -quit)\" && echo 'public key, signed RPMs, repodata; no private key' && pkill -f \"[h]ttp.server 8765\" || true && nohup python3 -m http.server 8765 --bind ${repo_host} --directory \"${PROJECT_ROOT}/dist/lab-repo\" >/tmp/selinux-pac-repo.log 2>&1 & sleep 2 && ssh ${E2E_SSH_USER}@${PROD_HOST} 'curl -sfI http://${repo_host}:8765/RPM-GPG-KEY | head -1'"
    tlab_checkpoint "prod prints HTTP/1.0 200 OK for http://${repo_host}:8765/RPM-GPG-KEY."
}

mac_ship_prod() {
    local mode="${1:-soak_demo}"
    lab_quiet "Packaging tools and the lab signing key on rhel-qa" "ssh ${E2E_SSH_USER}@${DEV_HOST} 'cd ~/selinux-pac && (rpm -q rpm-build rpm-sign createrepo_c >/dev/null 2>&1 || sudo dnf install -y rpm-build rpm-sign createrepo_c) && bash lab/lab_signing_setup.sh'"
    say "rhel-qa builds, signs and publishes the RPMs; the private key stays there"
    present_cmd "ssh ${E2E_SSH_USER}@${DEV_HOST} 'cd ~/selinux-pac && sepac build --allow-dirty && sepac publish --env-file dist/lab-signing.env'"
    mac_serve_repo
    tlab_pause

    say "The canary installs the signed RPM (gpgcheck=1) and sets only shopapi_t permissive"
    present_cmd "sepac canary --env production --limit canary"
    tlab_pause

    if [[ "${mode}" == "soak_demo" ]]; then
        e2e_handoff "On the PROD VM window run:
  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak
Press Enter here when the denial is on screen." \
            "ssh ${E2E_SSH_USER}@${PROD_HOST} 'bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak $(e2e_auto_flags)'"

        say "The soak gate must fail: /feature-spool is not in this module"
        present_cmd "sepac soak --env production --limit canary" fail
        tlab_pause

        e2e_handoff "On the PROD VM window run:
  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak-avc
/var/lib/selinux-policy-ops/shopapi/selinux_soak_last_fail.avc should exist.
Press Enter here when you have shown the fail file." \
            "ssh ${E2E_SSH_USER}@${PROD_HOST} 'bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak-avc $(e2e_auto_flags)'"

        say "Enforce with a ticket and no break-glass: the gate refuses"
        present_cmd "sepac enforce --env production --ticket DEMO" fail
        tlab_checkpoint "The gate refused. shopapi_t stays permissive."
        return 0
    fi

    e2e_handoff "On the PROD VM window run:
  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak-clean
Press Enter here when all four URLs return 200." \
        "ssh ${E2E_SSH_USER}@${PROD_HOST} 'bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part soak-clean $(e2e_auto_flags)'"
    say "The soak gate passes: net-new is 0"
    present_cmd "sepac soak --env production --limit canary"
    tlab_pause
    say "--skip-soak-days skips only the day count; the AVC gate still runs"
    present_cmd "sepac enforce --env production --ticket DEMO --skip-soak-days"
    tlab_checkpoint "AVC gate passed. shopapi_t is enforcing."
}

mac_copy_prod_avc_to_dev() {
    lab_quiet "Copy the prod denial export to rhel-qa (prod has no generator)" "ssh ${E2E_SSH_USER}@${DEV_HOST} 'mkdir -p ~/selinux-pac/policy_out' && scp -3 ${E2E_SSH_USER}@${PROD_HOST}:/tmp/prod-feature-spool.avc ${E2E_SSH_USER}@${DEV_HOST}:~/selinux-pac/policy_out/avc.log && ssh ${E2E_SSH_USER}@${DEV_HOST} 'wc -l ~/selinux-pac/policy_out/avc.log'"
}

e2e_parse_args "$@"
e2e_require_mac
cd "${PROJECT_ROOT}"
export PATH="${PROJECT_ROOT}/bin:${PATH}"

e2e_banner "MAC — the remote control (no SELinux on this laptop)"
if [[ "${E2E_SHORT}" -eq 1 ]]; then
    E2E_ALL_URLS=1
    say "short happy path: generate all URLs on QA → ship → clean soak → enforce"
else
    say "Generate on QA → ship → soak refuses → break-glass → rollback → fix → enforce"
fi
tlab_pause

e2e_banner "Lab setup"
lab_quiet "Write the Ansible inventories and check SSH to both VMs" "bash lab/setup_rhel_hosts.sh write --qa-host ${DEV_HOST} --prod-host ${PROD_HOST} --user ${E2E_SSH_USER} && bash lab/setup_rhel_hosts.sh ping"
lab_quiet "Both hosts Enforcing, with ausearch and sesearch" "bash lab/setup_rhel_hosts.sh doctor"
lab_quiet "rsync this checkout onto rhel-qa" "bash lab/sync_rhel_dev.sh"
mac_copy_prod_bundle
tlab_pause

if [[ "${E2E_SHORT}" -eq 1 ]]; then
    e2e_handoff "On the QA VM window run:
  bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part app --all-urls
Press Enter here when sepac capture has summarised the denials." \
        "ssh ${E2E_SSH_USER}@${DEV_HOST} 'bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part app $(e2e_auto_flags)'"
else
    e2e_handoff "On the QA VM window run:
  bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part app
Press Enter here when sepac capture has summarised the denials." \
        "ssh ${E2E_SSH_USER}@${DEV_HOST} 'bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part app $(e2e_auto_flags)'"
fi

lab_quiet "Copy the JAR rhel-qa built, so prod does not need Maven" "ssh ${E2E_SSH_USER}@${PROD_HOST} 'mkdir -p ~/e2e-demo/lab/apps/shopapi/target' && scp -3 ${E2E_SSH_USER}@${DEV_HOST}:/opt/shopapi/shopapi.jar ${E2E_SSH_USER}@${PROD_HOST}:~/e2e-demo/lab/apps/shopapi/target/shopapi.jar"

e2e_handoff "On the PROD VM window run:
  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part app
Press Enter here when curl /health returns 200." \
    "ssh ${E2E_SSH_USER}@${PROD_HOST} 'bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part app $(e2e_auto_flags)'"

e2e_handoff "On the QA VM window run:
  bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part generate
Press Enter here when sepac load has loaded the module." \
    "ssh ${E2E_SSH_USER}@${DEV_HOST} 'bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part generate $(e2e_auto_flags)'"

e2e_banner "Copy generated policy and open a PR"
mac_scp_generated_from_dev
tlab_pause
mac_open_policy_pr
tlab_pause

e2e_banner "Canary, then enforce on QA"
mac_canary_enforce_dev
tlab_pause

if [[ "${E2E_SHORT}" -eq 1 ]]; then
    e2e_banner "Build RPMs, ship prod, clean soak, enforce"
    mac_ship_prod recanary
    tlab_pause
    tlab_checkpoint "The demo ends with shopapi_t enforcing."
else
    e2e_banner "Prod soak refuses, then the outage and rollback"
    mac_ship_prod soak_demo
    tlab_pause

    say "Break-glass enforce of the first module — spool allow is not in it"
    present_cmd "sepac enforce --env production --ticket DEMO --break-glass 'show the enforcing denial before the fix'"
    tlab_pause

    e2e_handoff "On the PROD VM window run:
  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part fail
/feature-spool returns 500. The denial is shopapi_t and var_spool_t." \
        "ssh ${E2E_SSH_USER}@${PROD_HOST} 'bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part fail $(e2e_auto_flags)'"

    say "Rollback — shopapi_t back to permissive, host stays Enforcing"
    present_cmd "sepac rollback --env production"
    tlab_pause

    e2e_handoff "On the PROD VM window run:
  bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part restore
Press Enter here when the app is up." \
        "ssh ${E2E_SSH_USER}@${PROD_HOST} 'bash ~/e2e-demo/demo_e2e_rhel_prod.sh --part restore $(e2e_auto_flags)'"
    tlab_pause

    e2e_banner "Fix, recanary, clean soak, enforce"
    mac_copy_prod_avc_to_dev
    tlab_pause

    e2e_handoff "On the QA VM generate from the prod log:
  bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part generate --skip-export
Press Enter here when the second compile finishes." \
        "ssh ${E2E_SSH_USER}@${DEV_HOST} 'bash ~/selinux-pac/lab/demo_e2e_rhel_qa.sh --part generate --skip-export $(e2e_auto_flags)'"

    mac_scp_generated_from_dev
    tlab_pause
    mac_open_policy_pr
    tlab_pause

    mac_canary_enforce_dev
    tlab_pause
    mac_ship_prod recanary
    tlab_pause
    tlab_checkpoint "The demo ends with shopapi_t enforcing."
fi

echo
echo -e "${TLAB_BOLD}End of the Mac talk track.${TLAB_NC} Guide: docs/guides/302-TECHNICAL.md"
echo
