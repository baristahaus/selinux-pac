#!/usr/bin/env bash
#
# reset_demo_vms.sh — Wipe leftover demo policy on rhel-qa and rhel-prod.
#
# Run on the Mac (Ansible controller) between rehearsals. Not part of the
# customer talk. Does not uninstall the JVM. Does not setenforce 0.
#
#   bash lab/reset_demo_vms.sh
#   bash lab/reset_demo_vms.sh --dry-run
#   bash lab/reset_demo_vms.sh --dev-only
#   bash lab/reset_demo_vms.sh --prod-only
#
# After this, start docs/guides/302-TECHNICAL.md at Part 1 (write / ping / rsync).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/lab_env.sh
source "${SCRIPT_DIR}/lib/lab_env.sh"
lab_env_load
SSH_USER="${SSH_USER:-}"
DEV_HOST="${DEV_HOST:-}"
PROD_HOST="${PROD_HOST:-}"
DO_DEV=1
DO_PROD=1
DRY=0
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR)

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Lab reset for a second run of the two-host shopapi talk. From the Mac:

  • Unload shopapi / shopapi_canary / shopapi_ports and the local port 8090 assignment
  • Clear semanage permissive on shopapi_t
  • Untune App B so a second customer Act 2 still produces denials:
      semanage port -d tcp 8090, fcontext -d /opt/appdata,
      chcon user_home_t on /opt/appdata
  • Write an ausearch timestamp. Do not stop auditd or rewrite /var/log/audit.
  • On prod: rpm -e shopapi-selinux selinux-policy-ops; delete soak/AVC files
  • Restore this laptop’s types-only selinux/shopapi/ seed from git
  • Leave /opt/shopapi and shopapi.service in place

Also clears leftover myapp policy from older rehearsals.

Not ansible/reset_host_state.yml (that only runs semodule -B and clears
permissive; the module stays). Not emergency_rollback.yml.

Options:
  --dev-only   Reset rhel-qa only (alias: --qa-only)
  --prod-only  Reset rhel-prod only
  --dry-run    Print targets and remote steps; do not SSH
  --qa-host H  Override (alias: --dev-host)
  --dev-host H Same as --qa-host
  --prod-host H Override
  --user NAME  SSH user
  -h, --help

Hosts come from QA_HOST, PROD_HOST, and SSH_USER, or from lab/lab.env.
Flags override those. There is no built-in address.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev-only|--qa-only) DO_PROD=0; shift ;;
        --prod-only) DO_DEV=0; shift ;;
        --dry-run) DRY=1; shift ;;
        --dev-host|--qa-host) DEV_HOST="$2"; shift 2 ;;
        --prod-host) PROD_HOST="$2"; shift 2 ;;
        --user) SSH_USER="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ "${DO_DEV}" -eq 0 && "${DO_PROD}" -eq 0 ]]; then
    echo "Nothing to do: both --dev-only and --prod-only cancel each other." >&2
    exit 2
fi

lab_env_load
lab_env_require

# Shared remote body. $1 is "dev" or "prod".
# Unload policy leftovers; keep the JVM. Host stays Enforcing.
REMOTE_RESET=$(cat <<'REMOTE'
set -u
role="$1"
echo "=== reset ${role} ($(hostname)) ==="

if ! command -v getenforce >/dev/null 2>&1; then
    echo "getenforce not found — this is not a SELinux host" >&2
    exit 1
fi

if command -v semanage >/dev/null 2>&1; then
    semanage port -d -t shopapi_port_t -p tcp 8091 2>/dev/null || true
    semanage port -d -t myapp_port_t -p tcp 8888 2>/dev/null || true
    semanage port -d -t myapp_backend_port_t -p tcp 8889 2>/dev/null || true
fi
for mod in shopapi_ports shopapi_canary shopapi permissive_shopapi_t \
           myapp_ports myapp_canary myapp permissive_myapp_t permissive_myapp_backend_t; do
    semodule -r "${mod}" 2>/dev/null || true
done
if command -v semanage >/dev/null 2>&1; then
    semanage port -d -t shopapi_port_t -p tcp 8091 2>/dev/null || true
    semanage port -d -t myapp_port_t -p tcp 8888 2>/dev/null || true
    semanage port -d -t myapp_backend_port_t -p tcp 8889 2>/dev/null || true
    semanage permissive -d shopapi_t 2>/dev/null || true
    semanage permissive -d myapp_t 2>/dev/null || true
    semanage permissive -d myapp_backend_t 2>/dev/null || true

    # App B (demo_present.sh Act 2). A second talk on the same host is silent
    # unless these three host tunings are undone and /opt/appdata is mislabeled.
    while read -r ptype proto rest; do
        [[ "${proto:-}" == tcp ]] || continue
        echo "${rest:-}" | grep -Eq '(^|[^0-9])8090([^0-9]|$)' || continue
        semanage port -d -t "${ptype}" -p tcp 8090 2>/dev/null || true
    done < <(semanage port -l -C 2>/dev/null | awk 'NF >= 3 && $1 != "SELinux" { print }')
    semanage port -d -t http_port_t -p tcp 8090 2>/dev/null || true
    while read -r spec; do
        [[ -n "${spec}" ]] || continue
        semanage fcontext -d "${spec}" 2>/dev/null || true
    done < <(semanage fcontext -l -C 2>/dev/null | awk 'index($1, "/opt/appdata") { print $1 }')
    semanage fcontext -d '/opt/appdata(/.*)?' 2>/dev/null || true
    semanage fcontext -d '/opt/appdata' 2>/dev/null || true
fi

if [[ -d /opt/appdata ]]; then
    chcon -R -t user_home_t /opt/appdata 2>/dev/null || true
fi
for svc in jws6-tomcat.service tomcat.service tomcat9.service; do
    if systemctl list-unit-files "${svc}" >/dev/null 2>&1 \
        && systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl restart "${svc}" 2>/dev/null || true
    fi
done

if [[ "${role}" == prod ]]; then
    if command -v rpm >/dev/null 2>&1; then
        rpm -q shopapi-selinux >/dev/null 2>&1 && rpm -e shopapi-selinux || true
        rpm -q myapp-selinux >/dev/null 2>&1 && rpm -e myapp-selinux || true
        rpm -q selinux-policy-ops >/dev/null 2>&1 && rpm -e selinux-policy-ops || true
    fi
    rm -f /root/shopapi-selinux-*.rpm /root/myapp-selinux-*.rpm /root/selinux-policy-ops-*.rpm 2>/dev/null || true
fi

semodule -B 2>/dev/null || true

# Do not stop auditd or rewrite /var/log/audit. The marker is an epoch.
# Later readers keep msg=audit records at or after this second.
mkdir -p /var/lib/selinux-pac-demo
date +%s >/var/lib/selinux-pac-demo/ausearch-since
chmod 0644 /var/lib/selinux-pac-demo/ausearch-since

rm -rf /var/lib/selinux-policy-ops/shopapi \
       /var/lib/selinux-policy-ops/myapp
rm -f /var/lib/shopapi/selinux_soak_last_fail.avc \
      /var/lib/shopapi/selinux_soak_last_fail.json \
      /var/lib/shopapi/selinux_canary_deployed_at \
      /var/lib/myapp/selinux_soak_last_fail.avc \
      /var/lib/myapp/selinux_soak_last_fail.json \
      /var/lib/myapp/selinux_canary_deployed_at \
      /tmp/prod-feature-spool.avc \
      /tmp/emergency_avc.log 2>/dev/null || true
rm -rf /var/lib/selinux-pac-demo/stamps 2>/dev/null || true

restorecon -Rv /opt/shopapi /var/lib/shopapi /var/log/shopapi /run/shopapi /var/spool/shopapi 2>/dev/null || true
if systemctl list-unit-files shopapi.service >/dev/null 2>&1; then
    systemctl restart shopapi.service 2>/dev/null || true
fi

echo "getenforce: $(getenforce)"
if semodule -l 2>/dev/null | grep -E '^shopapi($| )|^permissive_shopapi|^myapp($| )|^permissive_myapp'; then
    echo "NOTE: a leftover demo module is still listed"
else
    echo "Good: no shopapi (or leftover myapp) module loaded"
fi
if [[ "${role}" == prod ]] && command -v rpm >/dev/null 2>&1; then
    rpm -q shopapi-selinux myapp-selinux selinux-policy-ops 2>/dev/null || echo "Good: demo policy RPMs not installed"
fi
REMOTE
)

ssh_sudo() {
    local host="$1"
    local role="$2"
    echo "-> ${SSH_USER}@${host} (${role})"
    if [[ "${DRY}" -eq 1 ]]; then
        echo "(dry-run — not executing)"
        echo "  would also untune App B: semanage port -d -p tcp 8090; fcontext -d /opt/appdata; chcon user_home_t; write ausearch-since"
        return 0
    fi
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${host}" "sudo bash -s -- ${role}" <<<"${REMOTE_RESET}"
}

echo "Demo VM reset (policy leftovers + App B host tunings; shopapi JVM stays)."
echo "dev=${DEV_HOST} prod=${PROD_HOST} user=${SSH_USER}"
[[ "${DRY}" -eq 1 ]] && echo "dry-run: no SSH, no git checkout"

if [[ "${DO_DEV}" -eq 1 ]]; then
    if [[ "${DRY}" -eq 0 && -d "${PROJECT_ROOT}/.git" ]]; then
        git -C "${PROJECT_ROOT}" checkout -- \
            selinux/shopapi/shopapi.te selinux/shopapi/shopapi.fc selinux/shopapi/policy_version.txt
        rm -f "${PROJECT_ROOT}/selinux/shopapi/shopapi.pp"
        echo "Restored types-only selinux/shopapi/ seed from git on this laptop."
    elif [[ "${DRY}" -eq 1 ]]; then
        echo "Would restore types-only selinux/shopapi/ seed from git on this laptop."
    fi
    ssh_sudo "${DEV_HOST}" dev
    if [[ "${DRY}" -eq 0 ]]; then
        ssh "${SSH_OPTS[@]}" "${SSH_USER}@${DEV_HOST}" \
            'rm -f ~/shopapi-selinux-*.rpm ~/myapp-selinux-*.rpm ~/selinux-policy-ops-*.rpm
             if [[ -d ~/selinux-pac ]]; then
               sudo rm -f ~/selinux-pac/selinux/shopapi/shopapi.pp
               sudo rm -rf ~/selinux-pac/policy_out ~/selinux-pac/dist
               sudo chown -R "$(id -un):$(id -gn)" ~/selinux-pac 2>/dev/null || true
             fi'
        if ssh "${SSH_OPTS[@]}" "${SSH_USER}@${DEV_HOST}" 'test -d ~/selinux-pac/selinux/shopapi'; then
            scp "${SSH_OPTS[@]}" \
                "${PROJECT_ROOT}/selinux/shopapi/shopapi.te" \
                "${PROJECT_ROOT}/selinux/shopapi/shopapi.fc" \
                "${PROJECT_ROOT}/selinux/shopapi/policy_version.txt" \
                "${SSH_USER}@${DEV_HOST}:~/selinux-pac/selinux/shopapi/"
            echo "Copied git snapshot of types-only shopapi.te / .fc / policy_version.txt onto rhel-qa."
        fi
    fi
fi

if [[ "${DO_PROD}" -eq 1 ]]; then
    ssh_sudo "${PROD_HOST}" prod
    if [[ "${DRY}" -eq 0 ]]; then
        ssh "${SSH_OPTS[@]}" "${SSH_USER}@${PROD_HOST}" \
            'rm -f ~/shopapi-selinux-*.rpm ~/myapp-selinux-*.rpm ~/selinux-policy-ops-*.rpm /tmp/prod-feature-spool.avc'
    fi
fi

echo
echo "Next: customer talk → bash lab/demo_present.sh --preflight (202)."
echo "      three-host ship → docs/guides/302-TECHNICAL.md at Part 1 (write / ping / rsync / scp)."
echo "Do not canary until demo_bootstrap.sh --shopapi-only and generate --apply have run on rhel-qa."
