#!/usr/bin/env bash
#
# verify_avc_coverage.sh — Wrapper for cli/verify_avc_coverage.py
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

APP_NAME=""
AVC_LOG=""
TE=""
MANIFEST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app|--app-name) APP_NAME="$2"; shift 2 ;;
        --avc-log)        AVC_LOG="$2"; shift 2 ;;
        --te)             TE="$2"; shift 2 ;;
        --manifest)       MANIFEST="$2"; shift 2 ;;
        *)
            # Positional args: avc_log, te, manifest (legacy)
            if [[ -z "${AVC_LOG}" ]]; then AVC_LOG="$1"
            elif [[ -z "${TE}" ]]; then TE="$1"
            elif [[ -z "${MANIFEST}" ]]; then MANIFEST="$1"
            fi
            shift
            ;;
    esac
done

[[ -n "${APP_NAME}" ]] || APP_NAME="myapp"
AVC_LOG="${AVC_LOG:-${PROJECT_ROOT}/policy_out/avc.log}"
TE="${TE:-${PROJECT_ROOT}/policy_out/${APP_NAME}.te}"
MANIFEST="${MANIFEST:-${PROJECT_ROOT}/config/${APP_NAME}.manifest.yml}"

exec python3 "${PROJECT_ROOT}/cli/verify_avc_coverage.py" \
    --avc-log "${AVC_LOG}" \
    --te "${TE}" \
    --manifest "${MANIFEST}"
