#!/usr/bin/env bash
#
# demo_open_generated_pr.sh — Open a GitHub PR on selinux-pac for selinux/shopapi/.
#
# Run on the Mac after scp of shopapi.te / shopapi.fc / policy_version.txt from rhel-qa.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="${POLICY_PR_ROOT:-${PROJECT_ROOT}}"
MODULE_DIR="${REPO_ROOT}/selinux/shopapi"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Open a GitHub PR on selinux-pac for live generated selinux/shopapi/ sources.

Options:
  -h, --help     Show this help
  --push-only    Commit and push the branch; do not run gh pr create
  --rehearsal    Draft PR. Title prefix "[rehearsal - do not merge] ".
                 Label do-not-merge instead of pending-admin-review.
                 Same as DEMO_REHEARSAL=1.
EOF
}

PUSH_ONLY=0
REHEARSAL=0
if [[ "${DEMO_REHEARSAL:-0}" == "1" ]]; then
    REHEARSAL=1
fi
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --push-only) PUSH_ONLY=1; shift ;;
        --rehearsal) REHEARSAL=1; shift ;;
        *) log_error "Unknown option $1"; usage; exit 2 ;;
    esac
done

if [[ ! -d "${REPO_ROOT}/.git" ]]; then
    log_error "Need a git clone at ${REPO_ROOT}"
    exit 1
fi

cd "${REPO_ROOT}"

VERSION="$(tr -d '[:space:]' < "${MODULE_DIR}/policy_version.txt" 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d%H%M%S)"
BRANCH="${DEMO_POLICY_BRANCH:-policy/shopapi-from-avc-${STAMP}}"
BASE_BRANCH="${DEMO_POLICY_BASE:-main}"
TITLE="${DEMO_POLICY_PR_TITLE:-security(selinux): shopapi ${VERSION} from rhel-qa AVCs}"
PR_BODY="${REPO_ROOT}/policy_out/pr_body.md"
if [[ "${REHEARSAL}" -eq 1 ]]; then
    case "${TITLE}" in
        "[rehearsal - do not merge] "*) ;;
        *) TITLE="[rehearsal - do not merge] ${TITLE}" ;;
    esac
    REVIEW_LABEL="do-not-merge"
else
    REVIEW_LABEL="pending-admin-review"
fi

if [[ ! -f "${MODULE_DIR}/shopapi.te" || ! -f "${MODULE_DIR}/shopapi.fc" || ! -f "${MODULE_DIR}/policy_version.txt" ]]; then
    log_error "Missing ${MODULE_DIR}/shopapi.te, shopapi.fc, or policy_version.txt — scp them from rhel-qa first"
    exit 1
fi

if [[ ! -f "${PR_BODY}" ]]; then
    mkdir -p "${REPO_ROOT}/policy_out"
    cat >"${PR_BODY}" <<EOF
## Summary

Generated \`shopapi\` SELinux policy on **rhel-qa** from AVC denials (types-only domain seed → deterministic generator).

- Module version: **${VERSION}**
- Sources: \`selinux/shopapi/shopapi.te\`, \`shopapi.fc\`, \`policy_version.txt\`
- Demo app: Spring Boot (\`lab/apps/shopapi/\`).

## Admin checklist

- [ ] CODEOWNERS review on \`selinux/\`
- [ ] CI \`offline-tests\`, \`forbidden-patterns\`, \`compiled-policy\`, and \`version-consistency\` (forbidden-patterns already ran at generate time)
- [ ] Canary on staging, then soak / enforce with a change ticket

Label: \`${REVIEW_LABEL}\`
EOF
    log_info "Wrote ${PR_BODY}"
fi

log_info "Creating branch ${BRANCH} in ${REPO_ROOT} (base ${BASE_BRANCH})"
git checkout -B "${BRANCH}"

git add selinux/shopapi/shopapi.te selinux/shopapi/shopapi.fc selinux/shopapi/policy_version.txt
if git diff --cached --quiet; then
    log_warn "No policy diff vs HEAD — nothing to commit."
    if command -v gh >/dev/null 2>&1; then
        gh pr list --head "${BRANCH}" --state open || true
    fi
    exit 0
fi

git commit -m "$(cat <<EOF
security(selinux): generate shopapi ${VERSION} from rhel-qa AVCs

Types-only domain seed plus ausearch → deterministic_gen --apply on rhel-qa.
EOF
)"

if [[ "${DEMO_POLICY_PUSH:-1}" != "1" ]]; then
    log_info "DEMO_POLICY_PUSH=0 — commit is local only"
    exit 0
fi

git push -u origin "HEAD:refs/heads/${BRANCH}"

if [[ "${PUSH_ONLY}" -eq 1 ]]; then
    log_info "Branch pushed."
    if [[ "${REHEARSAL}" -eq 1 ]]; then
        echo "  gh pr create --draft --base ${BASE_BRANCH} --head ${BRANCH} --title $(printf '%q' "${TITLE}") --body-file ${PR_BODY} --label ${REVIEW_LABEL}"
    else
        echo "  gh pr create --base ${BASE_BRANCH} --head ${BRANCH} --title $(printf '%q' "${TITLE}") --body-file ${PR_BODY} --label ${REVIEW_LABEL}"
    fi
    exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
    log_warn "GitHub CLI (gh) not found. Open a PR in the browser."
    exit 0
fi

EXISTING="$(gh pr list --head "${BRANCH}" --base "${BASE_BRANCH}" --state open --json number -q '.[0].number' 2>/dev/null || true)"
if [[ -n "${EXISTING}" && "${EXISTING}" != "null" ]]; then
    log_info "Open PR already exists: #${EXISTING}"
    gh pr view "${EXISTING}" || true
    exit 0
fi

if [[ "${REHEARSAL}" -eq 1 ]]; then
    gh pr create \
        --draft \
        --base "${BASE_BRANCH}" \
        --head "${BRANCH}" \
        --title "${TITLE}" \
        --body-file "${PR_BODY}" \
        --label security \
        --label selinux \
        --label "${REVIEW_LABEL}" \
        || gh pr create --draft --base "${BASE_BRANCH}" --head "${BRANCH}" --title "${TITLE}" --body-file "${PR_BODY}"
else
    gh pr create \
        --base "${BASE_BRANCH}" \
        --head "${BRANCH}" \
        --title "${TITLE}" \
        --body-file "${PR_BODY}" \
        --label security \
        --label selinux \
        --label "${REVIEW_LABEL}" \
        || gh pr create --base "${BASE_BRANCH}" --head "${BRANCH}" --title "${TITLE}" --body-file "${PR_BODY}"
fi
log_info "PR opened on selinux-pac (selinux/shopapi)"
