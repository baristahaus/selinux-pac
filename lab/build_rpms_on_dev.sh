#!/usr/bin/env bash
#
# build_rpms_on_dev.sh — Build selinux-policy-ops + myapp-selinux (fixture)
# + shopapi-selinux (demo) on rhel-qa
# and copy the RPMs back to dist/ on this controller (macOS has no rpmbuild).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/lab_env.sh
source "${ROOT}/lab/lib/lab_env.sh"
lab_env_require
DEV_USER="${SSH_USER}"
TARGET="${DEV_USER}@${QA_HOST}"
REMOTE_DIR="${REMOTE_RPM_DIR:-/tmp/selinux-pac-rpm}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR)
DIST="${ROOT}/dist"

bash "${ROOT}/lab/sync_rhel_dev.sh" --dest "${REMOTE_DIR}" "${TARGET}"

ssh "${SSH_OPTS[@]}" "${TARGET}" \
    'rpm -q rpm-build >/dev/null 2>&1 || sudo dnf install -y rpm-build'
ssh "${SSH_OPTS[@]}" "${TARGET}" \
    "cd $(printf '%q' "${REMOTE_DIR}") && bash packaging/build_rpms.sh"

mkdir -p "${DIST}"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    --include '*.rpm' --exclude '*' \
    "${TARGET}:${REMOTE_DIR}/dist/" "${DIST}/"
echo "Copied RPMs to ${DIST}/"
ls -l "${DIST}"/*.rpm
