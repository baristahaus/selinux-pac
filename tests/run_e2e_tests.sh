#!/usr/bin/env bash
#
# run_e2e_tests.sh — Local end-to-end checks (macOS/Linux; compile needs selinux-policy-devel).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
fail=0

log_ok() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; fail=1; }

log_ok "smoke_test.py"
python3 tests/smoke_test.py || log_fail "smoke_test.py"

log_ok "validate_rpm_ops_parity"
bash scripts/validate_rpm_ops_parity.sh || log_fail "rpm parity"

log_ok "stage_offline_fixture"
bash scripts/lib/stage_offline_fixture.sh || log_fail "offline fixture"

mkdir -p policy_out
cp tests/fixtures/offline/avc.log policy_out/avc.log

log_ok "dev_generate_policy (--skip-export)"
if bash scripts/dev_generate_policy.sh --skip-export; then
    log_ok "dev_generate deterministic pipeline"
else
    log_fail "dev_generate_policy deterministic"
fi

if [[ -f policy_out/myapp.pp ]]; then
    log_ok "policy_out/myapp.pp built"
else
    log_fail "compile did not produce policy_out/myapp.pp (needs selinux-policy-devel on RHEL 9)"
fi

if bash scripts/validate_forbidden_patterns.sh selinux/myapp --app myapp; then
    log_ok "selinux forbidden patterns"
else
    log_fail "selinux forbidden patterns"
fi

echo ""
if [[ "${fail}" -eq 0 ]]; then
    echo -e "${GREEN}All local E2E checks passed.${NC}"
    exit 0
fi
echo -e "${RED}One or more E2E checks failed.${NC}"
exit 1
