#!/usr/bin/env bash
#
# check_soak_gate.sh — Fail when the AVC monitor crashed or net-new is unknown.
# A raw count of 0 is not a substitute for a failed monitor.
#
set -euo pipefail

FAIL_CLOSED=0
NET_NEW=0

usage() {
    echo "Usage: $(basename "$0") --fail-closed true|false --net-new N" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fail-closed)
            case "$2" in
                1|true|True|TRUE|yes) FAIL_CLOSED=1 ;;
                *) FAIL_CLOSED=0 ;;
            esac
            shift 2
            ;;
        --net-new) NET_NEW="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ "${FAIL_CLOSED}" -eq 1 || "${NET_NEW}" -lt 0 ]]; then
    echo "Soak AVC monitor failed closed (net_new=${NET_NEW}). Refusing to continue." >&2
    exit 1
fi
exit 0
