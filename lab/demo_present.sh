#!/usr/bin/env bash
#
# demo_present.sh — the customer demo of sepac on one RHEL host.
#
# Red Hat's policy first → tune what Red Hat ships → write policy only from
# evidence → enforce it → ship it. Every tool step is a sepac command.
#
# Each step prints one caption line, types the command, and waits for Enter
# before it runs. The presenter explains; the screen stays quiet.
#
#   bash lab/demo_present.sh --dry-run            # any laptop: commands + sample output
#   bash lab/demo_present.sh --preflight          # on the RHEL host, before the audience
#   bash lab/demo_present.sh                      # the talk
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
export PATH="${PROJECT_ROOT}/bin:${PATH}"
# shellcheck source=lib/talk.sh
source "${SCRIPT_DIR}/lib/talk.sh"
# shellcheck source=lib/demo_estate.sh
source "${SCRIPT_DIR}/lib/demo_estate.sh"

TLAB_PS1='demo# '
PROFILE="customer"
ACTS=""
PREFLIGHT=0
OPEN_PR=0
PREFLIGHT_FAIL=0
STEP=1
DEMO_DRY_VARIANT="distro"
DEMO_DRY_UNCONFINED=1

CUSTOMER_ACTS="1,2,3,4"
FULL_ACTS="1,2,3,4,5"
TECHNICAL_ACTS="1,3,5"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

The customer demo of sepac on one RHEL host (~20 min):
  1 Triage    sepac triage: Red Hat's policy first. Only shopapi needs new policy.
  2 Tune      Inherited Tomcat: sepac denials --why, sepac tune. No policy module.
  3 Write     shopapi: sepac capture → generate (stops for review) → check → load.
  4 Enforce   sepac load --enforcing, verify all endpoints pass under enforcement.
  5 Prod fail A new feature is blocked, rollback, fix from evidence, enforce again.

  Guide: docs/demo.md. Two hosts (Mac + rhel-qa + rhel-prod): bash lab/demo_e2e_mac.sh

Options:
  --profile customer|full|technical  customer = 1-4; full = 1-5 (with prod failure); technical = 1,3,5
  --acts LIST                    Comma-separated part numbers (overrides --profile)
  --preflight                    Check the host and exit (pass/fail table)
  --dry-run                      Type the commands and a sample result; execute nothing
  --variant distro|jws           Dry-run host: distro tomcat_t is unconfined; jws is confined
  --open-pr                      Part 5 opens the pull request (needs gh auth)
  --no-step                      Run each command as soon as it is typed
  --auto                         No Enter at all (CI)
  --no-type                      Instant command echo
  -h, --help

Laptop with no RHEL:  bash lab/demo_present.sh --dry-run
Unprepared VM:        make demo-bootstrap
Run it again:         bash lab/reset_demo_vms.sh --dev-only
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --acts) ACTS="$2"; shift 2 ;;
        --preflight) PREFLIGHT=1; shift ;;
        --dry-run|--say-only) E2E_DRY=1; shift ;;
        --variant)
            case "$2" in
                distro|jws) DEMO_DRY_VARIANT="$2"; shift 2 ;;
                *) echo "Unknown --variant ${2} (use distro|jws)" >&2; exit 2 ;;
            esac
            ;;
        --open-pr) OPEN_PR=1; shift ;;
        --no-step) STEP=0; shift ;;
        --auto) TLAB_AUTO=1; shift ;;
        --no-type) TLAB_NO_TYPE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ "${E2E_DRY}" -eq 1 ]]; then
    if [[ "${DEMO_DRY_VARIANT}" == "jws" ]]; then
        DEMO_TOMCAT_VARIANT="jws"
        DEMO_DRY_UNCONFINED=0
    else
        DEMO_TOMCAT_VARIANT="tomcat"
        DEMO_DRY_UNCONFINED=1
    fi
fi
export DEMO_TOMCAT_VARIANT

if [[ -z "${ACTS}" ]]; then
    case "${PROFILE}" in
        customer) ACTS="${CUSTOMER_ACTS}" ;;
        full) ACTS="${FULL_ACTS}" ;;
        technical) ACTS="${TECHNICAL_ACTS}" ;;
        *) echo "Unknown --profile ${PROFILE} (use customer|full|technical)" >&2; exit 2 ;;
    esac
fi

PRESENT_STEP=${STEP}

# ── Preflight (not shown to the audience) ────────────────────────────────────

pf_row() {
    local status="$1" name="$2" detail="$3" hint="${4:-}"
    printf '%-6s  %-22s  %s\n' "${status}" "${name}" "${detail}"
    if [[ "${status}" == "FAIL" ]]; then
        PREFLIGHT_FAIL=1
        [[ -z "${hint}" ]] || echo "        → ${hint}"
    elif [[ "${status}" == "WARN" && -n "${hint}" ]]; then
        echo "        → ${hint}"
    fi
}

# True if APP_B_PORT is in the local customizations (semanage -C). A labelled
# port means the second run of part 2 has nothing to show.
app_b_port_labelled() {
    command -v semanage >/dev/null 2>&1 || return 1
    semanage port -l -C 2>/dev/null | awk -v p="${APP_B_PORT}" '
        $2 == "tcp" {
            line = $0
            sub(/^[^ \t]+[ \t]+tcp[ \t]+/, "", line)
            n = split(line, parts, /,[ \t]*/)
            for (i = 1; i <= n; i++) {
                gsub(/[ \t]/, "", parts[i])
                if (parts[i] == p) exit 0
                if (parts[i] ~ /^[0-9]+-[0-9]+$/) {
                    split(parts[i], r, /-/)
                    if ((p + 0) >= (r[1] + 0) && (p + 0) <= (r[2] + 0)) exit 0
                }
            }
        }
        END { exit 1 }
    '
}

app_b_fcontext_custom() {
    command -v semanage >/dev/null 2>&1 || return 1
    semanage fcontext -l -C 2>/dev/null | grep -qF "${APP_B_DATA}"
}

# The first JWS connect boolean that is on. Distro Tomcat has none, and
# httpd_can_network_connect is never Tomcat's.
app_b_connect_boolean_on() {
    local b
    for b in jws6_can_network_connect jws_can_network_connect; do
        if getsebool "${b}" 2>/dev/null | grep -Fq -- '--> on'; then
            printf '%s' "${b}"
            return 0
        fi
    done
    return 1
}

reset_hint() {
    echo "bash lab/reset_demo_vms.sh --dev-only   (or make demo-bootstrap)"
}

run_preflight() {
    echo
    echo "Demo preflight"
    echo "=============="
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        echo "(dry-run — checks not executed)"
        pf_row "WOULD" "getenforce" "Enforcing"
        pf_row "WOULD" "sepac" "bin/sepac --version"
        pf_row "WOULD" "host role" "/etc/selinux-pac/role says qa"
        pf_row "WOULD" "tomcat unit" "$(demo_tomcat_service 2>/dev/null || echo tomcat.service)"
        pf_row "WOULD" "shopapi" "running as shopapi_t, on the permissive list"
        pf_row "WOULD" "App B port ${APP_B_PORT}" "not labelled yet (fix: semanage port -d -p tcp ${APP_B_PORT})"
        pf_row "WOULD" "App B fcontext" "none for ${APP_B_DATA} (fix: semanage fcontext -d '${APP_B_DATA}(/.*)?')"
        pf_row "WOULD" "App B boolean" "connect boolean off"
        echo
        echo "Missing apps: make demo-bootstrap. Already-run demo: $(reset_hint)"
        return 0
    fi

    if [[ "$(uname -s)" != "Linux" ]]; then
        pf_row "FAIL" "Linux/RHEL host" "$(uname -s)" "run make demo-bootstrap on a RHEL VM, or --dry-run here"
        echo
        echo "Preflight FAILED. Run make demo-bootstrap on a RHEL VM, or --dry-run here"
        return 1
    fi

    local ge
    ge="$(getenforce 2>/dev/null || echo missing)"
    if [[ "${ge}" == "Enforcing" ]]; then
        pf_row "PASS" "getenforce" "${ge}"
    else
        pf_row "FAIL" "getenforce" "${ge}" "setenforce 1 (the host stays Enforcing for the whole demo)"
    fi

    if sepac --version >/dev/null 2>&1; then
        pf_row "PASS" "sepac" "$(sepac --version 2>/dev/null)"
    else
        pf_row "FAIL" "sepac" "does not run" "python3 and python3-pyyaml are needed"
    fi

    local role
    role="$(cat /etc/selinux-pac/role 2>/dev/null || true)"
    if [[ "${role}" == "qa" || "${role}" == "dev" ]]; then
        pf_row "PASS" "host role" "${role}"
    else
        pf_row "FAIL" "host role" "${role:-missing}" "echo qa | sudo tee /etc/selinux-pac/role   (make demo-bootstrap writes it)"
    fi

    local svc
    svc="$(demo_tomcat_service)"
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        pf_row "PASS" "tomcat unit" "${svc} active"
    else
        pf_row "FAIL" "tomcat unit" "${svc} not active" "run make demo-bootstrap"
    fi

    local shop_label
    shop_label="$(ps -o label= -C java 2>/dev/null | grep -o 'shopapi_t' | head -n 1 || true)"
    if [[ -n "${shop_label}" ]] && sudo -n semanage permissive -l 2>/dev/null | grep -qw shopapi_t; then
        pf_row "PASS" "shopapi" "shopapi_t, permissive"
    elif [[ -n "${shop_label}" ]]; then
        pf_row "FAIL" "shopapi" "shopapi_t is not permissive (left over from a run)" "$(reset_hint)"
    else
        pf_row "FAIL" "shopapi" "not running as shopapi_t" "run make demo-bootstrap"
    fi

    if app_b_port_labelled; then
        pf_row "FAIL" "App B port ${APP_B_PORT}" "already labelled" "$(reset_hint)"
    else
        pf_row "PASS" "App B port ${APP_B_PORT}" "not labelled"
    fi
    if app_b_fcontext_custom; then
        pf_row "FAIL" "App B fcontext" "already set for ${APP_B_DATA}" "$(reset_hint)"
    else
        pf_row "PASS" "App B fcontext" "none for ${APP_B_DATA}"
    fi
    local b_on
    b_on="$(app_b_connect_boolean_on || true)"
    if [[ -n "${b_on}" ]]; then
        pf_row "FAIL" "App B boolean" "${b_on} is on" "$(reset_hint)"
    else
        pf_row "PASS" "App B boolean" "off (or absent)"
    fi

    if demo_selinux_type_unconfined "$(demo_tomcat_domain)"; then
        pf_row "WARN" "tomcat domain" "$(demo_tomcat_domain) is unconfined: part 2 shows no denials (JWS jws6_tomcat_t would)"
    fi

    if [[ "${OPEN_PR}" -eq 1 ]]; then
        if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
            pf_row "PASS" "gh auth" "ok"
        else
            pf_row "FAIL" "gh auth" "missing" "gh auth login (required with --open-pr)"
        fi
    fi

    echo
    if [[ "${PREFLIGHT_FAIL}" -ne 0 ]]; then
        echo "Preflight FAILED. Missing apps: make demo-bootstrap. Already-run demo: $(reset_hint)"
        return 1
    fi
    echo "Preflight PASSED. variant=$(demo_variant) domain=$(demo_tomcat_domain)"
    return 0
}

# ── The talk ─────────────────────────────────────────────────────────────────

# Distro tomcat_t is unconfined_domain_type. Dry-run uses the variant flag.
present_distro_unconfined() {
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        [[ "${DEMO_DRY_UNCONFINED}" -eq 1 ]]
        return
    fi
    demo_selinux_type_unconfined "$(demo_tomcat_domain)"
}

# True if a recent tomcat denial matches PATTERN. Dry-run: true (show the fix).
tomcat_avc() {
    [[ "${E2E_DRY}" -eq 1 ]] && return 0
    sudo ausearch -m avc -ts recent 2>/dev/null | grep tomcat_t | grep -Eq "$1"
}

# The connect boolean audit2why names for a recent tomcat denial, if this host
# has it. Never httpd_can_network_connect: that one is for httpd.
tomcat_connect_boolean() {
    local b
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        echo "<boolean audit2why names>"
        return 0
    fi
    tomcat_avc "name_connect|network_connect" || return 0
    b="$(sudo ausearch -m avc -ts recent 2>/dev/null | grep tomcat_t | audit2why 2>/dev/null \
        | grep -oE 'setsebool -P [^ ]+' | awk '{print $3}' | head -n 1 || true)"
    [[ -n "${b}" && "${b}" != "httpd_can_network_connect" ]] || return 0
    getsebool "${b}" >/dev/null 2>&1 || return 0
    printf '%s' "${b}"
}

part1_triage() {
    local svc unit_flag="" tomcat_sample
    svc="$(demo_tomcat_service)"
    [[ "${svc}" == "tomcat.service" ]] || unit_flag=" --unit ${svc}"
    if present_distro_unconfined; then
        tomcat_sample="TRIAGE situation=loaded_unconfined app=tomcat action=confine / Red Hat module loaded, but tomcat_t is unconfined."
    else
        tomcat_sample="TRIAGE situation=loaded app=tomcat module=jws6_tomcat action=tune / Red Hat policy confines tomcat. Tune it, do not write a module."
    fi
    e2e_banner "1 · Triage — does Red Hat already ship policy?"
    say "Standard Tomcat (App A) and the inherited Tomcat (App B) run in one domain"
    present_cmd "sepac triage tomcat${unit_flag}" run "${tomcat_sample}"
    say "shopapi, a Spring Boot app we built"
    present_cmd "sepac triage shopapi" run \
        "TRIAGE situation=none app=shopapi action=generate / No Red Hat policy for shopapi. Write one: sepac generate shopapi"
    if present_distro_unconfined; then
        tlab_checkpoint "Red Hat's policy first. Tomcat is Red Hat's to confine. Only shopapi gets new policy."
    else
        tlab_checkpoint "Tomcat is vendor-covered. Only shopapi gets new policy."
    fi
    tlab_pause
}

part2_tune() {
    local svc fctx b base fixed=0
    svc="$(demo_tomcat_service)"
    fctx="$(demo_tomcat_fcontext_type)"
    base="http://127.0.0.1:${APP_B_PORT}/inherited"
    e2e_banner "2 · Inherited Tomcat — tune it, don't write policy"
    say "Port ${APP_B_PORT}, data in ${APP_B_DATA}, a call to the payment gateway"
    present_cmd "for p in '' data.jsp gateway.jsp; do curl -s -o /dev/null -w \"%{http_code} /inherited/\$p\n\" ${base}/\$p; done" run \
        "200 /inherited/ · 200 /inherited/data.jsp · 200 /inherited/gateway.jsp"
    say "What did SELinux block, and why?"
    if present_distro_unconfined; then
        present_cmd "sepac denials tomcat --why" run "No denials for domains matching 'tomcat' since recent"
        tlab_checkpoint "Nothing blocked, nothing to fix, no policy written."
        tlab_pause
        return 0
    fi
    present_cmd "sepac denials tomcat --why" run \
        "name_bind on unreserved_port_t, read on user_home_t, name_connect: each with its cause"
    say "The fixes, without a policy module"
    present_cmd "sepac tune tomcat" run \
        "semanage port -a … · semanage fcontext -a … && restorecon … · setsebool -P …"
    if tomcat_avc "name_bind"; then
        say "Apply: label the port, restart Tomcat"
        present_cmd "sudo semanage port -a -t http_port_t -p tcp ${APP_B_PORT} && sudo systemctl restart ${svc}"
        fixed=1
    fi
    if tomcat_avc "appdata|user_home_t"; then
        say "Apply: label the data"
        present_cmd "sudo semanage fcontext -a -t ${fctx} '${APP_B_DATA}(/.*)?' && sudo restorecon -Rv ${APP_B_DATA}"
        fixed=1
    fi
    b="$(tomcat_connect_boolean)"
    if [[ -n "${b}" ]]; then
        say "Apply: the boolean audit2why named"
        present_cmd "sudo setsebool -P ${b} on"
        fixed=1
    fi
    if [[ "${fixed}" -eq 1 ]]; then
        say "Again"
        present_cmd "for p in '' data.jsp gateway.jsp; do curl -s -o /dev/null -w \"%{http_code} /inherited/\$p\n\" ${base}/\$p; done" run \
            "200 on all three"
    fi
    tlab_checkpoint "Host fixes from sepac tune, only where a denial was real. No policy module."
    tlab_pause
}

part3_write() {
    e2e_banner "3 · shopapi — write policy from evidence"
    say "shopapi has its own domain; permissive for now: SELinux logs, doesn't block"
    present_cmd "sepac status shopapi" run \
        "Host Enforcing · Module shopapi 1.0.0 (types only) · Domain shopapi_t permissive · Process shopapi_t"
    say "Collect the evidence: restart with full auditing, call every endpoint"
    present_cmd "sepac capture shopapi --full-audit" run \
        "GET /health 200 · /state 200 · /log 200 · shopapi_t: 82 denials (permissive: logged, not blocked) · Next: sepac generate shopapi"
    say "The old way: audit2allow turns every denial into an allow, unreviewed"
    present_cmd "sudo ausearch -m avc -ts boot | grep shopapi_t | audit2allow | grep -E 'passwd_file_t|execmem|bin_t'" run \
        "allow shopapi_t bin_t:file { execute … } · allow shopapi_t passwd_file_t:file { open read } · allow shopapi_t self:process execmem;"
    say "sepac writes policy from the same evidence"
    present_cmd "sepac generate shopapi" fail \
        "GENERATION BLOCKED: execmem needs review · Blocked for review: execmem. After review: sepac generate shopapi --approve execmem --apply"
    say "A reviewer approves execmem; /etc/passwd stays refused"
    present_cmd "sepac generate shopapi --approve execmem --apply" run \
        "REFUSED /etc/passwd · bin_t execute: reviewed exception in the manifest · Red Hat interfaces · AVC coverage OK"
    say "The same gate CI runs on the pull request"
    present_cmd "sepac check shopapi" run \
        "Forbidden-pattern checks passed · compiled · Semantic policy checks passed"
    say "Load it on QA; production only ever gets the signed RPM"
    present_cmd "sepac load shopapi" run "Loaded shopapi 1.0.1"
    tlab_checkpoint "Evidence in, reviewed policy out: execmem signed off, /etc/passwd refused, CI gate passed."
    tlab_pause
}

part4_enforce() {
    e2e_banner "4 · shopapi — enforce it"
    say "Turn enforcement on for shopapi"
    present_cmd "sepac load shopapi --enforcing" run \
        "shopapi 1.0.1 is already loaded · shopapi_t: enforcing (removed from the permissive list)"
    say "Every known endpoint, now under enforcement"
    present_cmd "sepac capture shopapi --no-restart" run \
        "/health 200 · /state 200 · /log 200 · shopapi_t: no denials"
    say "Where it stands"
    present_cmd "sepac status shopapi" run \
        "Host Enforcing · Module shopapi 1.0.1, matches the repo build · Domain shopapi_t enforcing · Labels ok"
    tlab_checkpoint "Enforcing. Every known endpoint passes. The host never left Enforcing."
    echo -e "${TLAB_DIM}# Next: sepac build, publish, canary, soak, enforce, rollback.${TLAB_NC}"
    echo -e "${TLAB_DIM}# The two-host demo (bash lab/demo_e2e_mac.sh) shows them live.${TLAB_NC}"
    tlab_pause
}

part5_prod_failure() {
    e2e_banner "5 · A new feature hits production"
    say "A developer deploys /feature-spool. It writes to /var/spool/shopapi."
    say "The policy has never seen that path."
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool" run \
        "/health 200 · /state 200 · /log 200 · /feature-spool 500 · new: { open } on var_spool_t file /var/spool/shopapi/feature.log"
    tlab_checkpoint "Confinement doing its job: the new code path is blocked."
    tlab_pause

    say "Rollback: shopapi_t back to permissive so the app runs. The host stays Enforcing."
    present_cmd "sepac load shopapi --permissive" run \
        "shopapi_t: permissive (added to the permissive list)"
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool" run \
        "/feature-spool 200 · shopapi_t: 1 denial (permissive: logged, not blocked)"
    tlab_checkpoint "The service is back, permissive. Now fix the policy from the evidence."
    tlab_pause

    say "Generate the fix from the evidence"
    present_cmd "sepac generate shopapi --apply" run \
        "LABELING FIXES: /var/spool/shopapi(/.*)? shopapi_var_lib_t (a label, not a wider rule)"
    say "Load and re-enforce"
    present_cmd "sepac load shopapi --enforcing" run \
        "Loaded shopapi 1.0.2 · Relabeled /var/spool/shopapi … to shopapi_var_lib_t · shopapi_t: already enforcing"
    say "Verify"
    present_cmd "sepac capture shopapi --no-restart --url /feature-spool" run \
        "/feature-spool 200 · shopapi_t: no denials"
    present_cmd "sepac status shopapi" run \
        "Host Enforcing · Module shopapi 1.0.2, matches the repo build · Domain shopapi_t enforcing · Labels ok"
    if [[ "${OPEN_PR}" -eq 1 ]]; then
        say "Open the updated PR; CI runs sepac check"
        present_cmd "bash lab/demo_open_generated_pr.sh"
    fi
    tlab_checkpoint "Blocked, rolled back, fixed from evidence, enforcing. The host never left Enforcing."
    tlab_pause
}

run_act() {
    case "$1" in
        1) part1_triage ;;
        2) part2_tune ;;
        3) part3_write ;;
        4) part4_enforce ;;
        5) part5_prod_failure ;;
        *) echo "Unknown part $1 (use 1-5)" >&2; exit 2 ;;
    esac
}

main() {
    cd "${PROJECT_ROOT}"
    if [[ "${PREFLIGHT}" -eq 1 ]]; then
        run_preflight
        exit $?
    fi
    if [[ "${E2E_DRY}" -eq 1 ]]; then
        echo "dry-run  profile=${PROFILE}  parts=${ACTS}  variant=${DEMO_DRY_VARIANT}"
        echo "Unprepared host: make demo-bootstrap.  Run it again: bash lab/reset_demo_vms.sh --dev-only"
    fi
    e2e_banner "sepac — SELinux policy as code for RHEL admins"
    tlab_pause
    local -a acts
    local act
    IFS=',' read -r -a acts <<<"${ACTS// /}"
    for act in "${acts[@]}"; do
        [[ -n "${act}" ]] || continue
        run_act "${act}"
    done
    tlab_checkpoint "Red Hat's policy first. New policy only from evidence, reviewed, and enforcing."
}

main
