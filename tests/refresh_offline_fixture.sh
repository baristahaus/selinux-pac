#!/usr/bin/env bash
#
# refresh_offline_fixture.sh — Sync offline/generated/ with selinux/ after a policy bump.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

APP_NAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --app|--app-name) APP_NAME="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "${APP_NAME}" ]] || { echo "[ERROR] --app NAME is required" >&2; exit 1; }
DEST="${PROJECT_ROOT}/tests/fixtures/offline/generated"

# shellcheck source=../scripts/lib/app_identity.sh
source "${PROJECT_ROOT}/scripts/lib/app_identity.sh"
resolve_app_identity --app "${APP_NAME}"

mkdir -p "${DEST}"
cp "${MODULE_DIR}/${APP_NAME}.te" "${DEST}/${APP_NAME}.te"
cp "${MODULE_DIR}/${APP_NAME}.fc" "${DEST}/${APP_NAME}.fc"
echo "Updated ${DEST}/ from ${MODULE_DIR}/"
