#!/usr/bin/env bash
#
# validate_app_manifest.sh — Validate config/*.manifest.yml for onboarding/CI.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${1:?Usage: validate_app_manifest.sh MANIFEST_PATH}"

python3 "${SCRIPT_DIR}/lib/app_manifest.py" validate "${MANIFEST}"
