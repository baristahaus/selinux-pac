#!/usr/bin/env bash
#
# check_audit_health.sh — Fail closed unless auditd is recording.
# auditctl -s must show enabled, and lost must not have grown since the marker.
#
set -euo pipefail

marker="${1:-}"

if ! command -v systemctl >/dev/null 2>&1 || ! systemctl is-active --quiet auditd; then
    echo "auditd is not active" >&2
    exit 1
fi
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl is missing" >&2
    exit 1
fi

status="$(auditctl -s 2>/dev/null || true)"
enabled="$(awk '/^enabled / { print $2; exit }' <<<"${status}")"
lost="$(awk '/^lost / { print $2; exit }' <<<"${status}")"
if [[ "${enabled}" != "1" && "${enabled}" != "2" ]]; then
    echo "auditctl -s enabled is ${enabled:-missing}" >&2
    exit 1
fi
lost="${lost:-0}"
if [[ ! "${lost}" =~ ^[0-9]+$ ]]; then
    echo "auditctl -s lost is not a number" >&2
    exit 1
fi

base_file="${marker}.audit_lost"
if [[ -n "${marker}" && -f "${base_file}" ]]; then
    base="$(tr -d '[:space:]' < "${base_file}")"
    if [[ ! "${base}" =~ ^[0-9]+$ ]]; then
        echo "audit lost baseline at the marker is not a number" >&2
        exit 1
    fi
    if [[ "${lost}" -gt "${base}" ]]; then
        echo "lost records since the marker: ${lost} > ${base}" >&2
        exit 1
    fi
elif [[ "${lost}" -gt 0 ]]; then
    echo "lost records (${lost}) and no baseline at the marker" >&2
    exit 1
fi

exit 0
