#!/usr/bin/env bash
#
# selinux_pac_adopt.sh — host prerequisite check behind `sepac doctor`.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $(basename "$0") doctor

  doctor   Check host prerequisites (SELinux, audit, tools). sepac doctor runs this.

Onboarding an app is sepac init APP (docs/sepac.md).
EOF
}

doctor() {
    echo "=== selinux-pac doctor ==="
    getenforce 2>/dev/null || echo "WARN: getenforce unavailable"
    command -v ausearch >/dev/null && echo "OK ausearch" || echo "WARN: ausearch missing"
    command -v sesearch >/dev/null && echo "OK sesearch" || { echo "FAIL: sesearch missing (dnf install setools-console)"; exit 1; }
    command -v ansible-playbook >/dev/null && echo "OK ansible-playbook" || echo "INFO: ansible-playbook on controller only"
    [[ -x "${SCRIPT_DIR}/monitor_avc.sh" ]] && echo "OK ops scripts in repo" || true
}


if [[ $# -lt 1 ]]; then
    usage
    exit 1
fi

SUB="$1"
shift

case "${SUB}" in
    doctor) doctor ;;
    init)
        echo "Onboarding moved to sepac: sepac init ${1:-APP}" >&2
        exit 2
        ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown subcommand: ${SUB}" >&2; usage; exit 1 ;;
esac
