#!/usr/bin/env bash
#
# run_deterministic_fixtures.sh — Assert golden AVC → verdict fixtures (offline).
#
# Cases under tests/fixtures/deterministic/ (every classification verdict
# has at least one golden row). Same checks as smoke_test deterministic tests.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_ROOT="${PROJECT_ROOT}/tests/fixtures/deterministic"

cd "${PROJECT_ROOT}"
export PYTHONPATH="${PROJECT_ROOT}/cli:${PROJECT_ROOT}/scripts${PYTHONPATH:+:${PYTHONPATH}}"

if [[ ! -d "${FIXTURE_ROOT}" ]]; then
    echo "Missing fixture root: ${FIXTURE_ROOT}" >&2
    exit 1
fi

python3 - <<'PY'
import sys

sys.path.insert(0, "tests")
from smoke_test import (
    test_deterministic_fixture_classify,
    test_deterministic_verdict_fixture_coverage,
)

test_deterministic_verdict_fixture_coverage()
test_deterministic_fixture_classify()
print("All deterministic fixtures passed")
PY
