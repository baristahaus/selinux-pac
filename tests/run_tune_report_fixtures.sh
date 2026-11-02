#!/usr/bin/env bash
#
# run_tune_report_fixtures.sh — Assert vendor-domain --tune-report golden output (offline).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"
export PYTHONPATH="${PROJECT_ROOT}/cli:${PROJECT_ROOT}/scripts${PYTHONPATH:+:${PYTHONPATH}}"

python3 - <<'PY'
import sys

sys.path.insert(0, "tests")
from smoke_test import test_tune_report, test_tune_report_skip_no_selinux, test_force_reason_recorded

test_tune_report()
test_tune_report_skip_no_selinux()
test_force_reason_recorded()
print("Tune-report fixtures passed")
PY
