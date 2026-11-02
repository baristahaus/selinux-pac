#!/usr/bin/env bash
#
# assemble_pr_body.sh — Merge PR template + pr_summary + AVC excerpt into pr_body.md
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE="${PROJECT_ROOT}/.github/PULL_REQUEST_TEMPLATE/selinux_policy_review.md"
PR_SUMMARY="${PROJECT_ROOT}/policy_out/pr_summary.md"
AVC_LOG="${PROJECT_ROOT}/policy_out/avc.log"
OUTPUT="${PROJECT_ROOT}/policy_out/pr_body.md"
APP_NAME=""
CAND_DIR="${PROJECT_ROOT}/selinux"
POLICY_DIFF_FILE=""
SKIP_POLICY_DIFF=0
STAGING_HOST="${STAGING_HOST:-<!-- fill in staging host -->}"
TEST_SUITE="${TEST_SUITE:-Integration tests (curl endpoints)}"
AVC_SAMPLE_LINES="${AVC_SAMPLE_LINES:-8}"
VERSION_FILE="${PROJECT_ROOT}/selinux/myapp/policy_version.txt"
DOMAINS=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Assemble policy_out/pr_body.md from PR template, pr_summary.md, and avc.log.

Options:
  --app-name NAME       Module name (default: myapp)
  --candidate-dir PATH  Candidate selinux sources (default: selinux/)
  --policy-diff-file PATH  Use precomputed diff (skips sesearch diff)
  --skip-policy-diff    Omit policy diff section (smoke tests only)
  --template PATH       PR template file
  --pr-summary PATH     PR summary file
  --avc-log PATH        AVC export file
  --output PATH         Output file
  --staging-host TEXT   Staging environment label
  --test-suite TEXT     Test suite description
  -h, --help            Show help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app|--app-name) APP_NAME="$2"; shift 2 ;;
        --candidate-dir) CAND_DIR="$2"; shift 2 ;;
        --policy-diff-file) POLICY_DIFF_FILE="$2"; shift 2 ;;
        --skip-policy-diff) SKIP_POLICY_DIFF=1; shift ;;
        --template) TEMPLATE="$2"; shift 2 ;;
        --pr-summary) PR_SUMMARY="$2"; shift 2 ;;
        --avc-log) AVC_LOG="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --staging-host) STAGING_HOST="$2"; shift 2 ;;
        --test-suite) TEST_SUITE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -n "${APP_NAME}" ]] || { echo "assemble_pr_body: --app-name is required" >&2; exit 1; }

[[ -f "${CAND_DIR}/policy_version.txt" ]] && VERSION_FILE="${CAND_DIR}/policy_version.txt"

[[ -f "${TEMPLATE}" ]] || { echo "Missing template: ${TEMPLATE}" >&2; exit 1; }
[[ -f "${PR_SUMMARY}" ]] || { echo "Missing pr_summary: ${PR_SUMMARY}" >&2; exit 1; }

if [[ -z "${DOMAINS}" && -f "${PROJECT_ROOT}/config/${APP_NAME}.manifest.yml" ]]; then
    DOMAINS="$(python3 - "${PROJECT_ROOT}/config/${APP_NAME}.manifest.yml" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
doms = {m["domain"]}
for svc in (m.get("services") or {}).values():
    if isinstance(svc, dict) and svc.get("domain"):
        doms.add(svc["domain"])
print(",".join(sorted(doms)))
PY
)"
fi
DOMAINS="${DOMAINS:-${APP_NAME}_t}"

policy_version="unknown"
if [[ -f "${VERSION_FILE}" ]]; then
    policy_version="$(tr -d '[:space:]' < "${VERSION_FILE}")"
fi

avc_line_count=0
avc_excerpt="(no AVC log found — run export before assemble)"
if [[ -f "${AVC_LOG}" ]] && [[ -s "${AVC_LOG}" ]]; then
    avc_line_count="$(wc -l < "${AVC_LOG}" | tr -d ' ')"
    avc_excerpt="$(grep -E '^type=AVC|avc: denied' "${AVC_LOG}" | head -n "${AVC_SAMPLE_LINES}" || true)"
    [[ -n "${avc_excerpt}" ]] || avc_excerpt="(AVC log present but no matching lines)"
fi

sediff_file="$(mktemp)"
trap 'rm -f "${sediff_file}" "${tmp:-}"' EXIT

if [[ "${SKIP_POLICY_DIFF}" -eq 1 ]]; then
    printf '%s\n' "### Policy access delta (sesearch)" "" "_Policy diff skipped (smoke test)._" > "${sediff_file}"
elif [[ -n "${POLICY_DIFF_FILE}" ]]; then
    cp "${POLICY_DIFF_FILE}" "${sediff_file}"
else
    diff_args=(
        --app-name "${APP_NAME}"
        --cand-dir "${CAND_DIR}"
        --from-merge-base
        --domains "${DOMAINS}"
        --output "${sediff_file}"
        --format markdown
    )
    if ! bash "${SCRIPT_DIR}/lib/policy_module_diff.sh" "${diff_args[@]}" 2>/dev/null; then
        printf '%s\n' "### Policy access delta (sesearch)" "" "_Policy access diff unavailable (sesearch requires RHEL tooling)._" > "${sediff_file}"
    fi
fi

tmp="$(mktemp)"
# Strip YAML frontmatter (--- ... ---) for body-file usage
awk 'BEGIN {delim=0} /^---$/ { delim++; next } delim >= 2' "${TEMPLATE}" > "${tmp}"

python3 - "${tmp}" "${OUTPUT}" "${policy_version}" "${STAGING_HOST}" "${TEST_SUITE}" "${avc_line_count}" "${PR_SUMMARY}" "${AVC_LOG}" "${sediff_file}" "${PROJECT_ROOT}" <<'PY'
import json
import pathlib
import sys

template_path, output_path, policy_version, staging_host, test_suite, avc_count, pr_summary_path, avc_log_path, sediff_path, project_root = sys.argv[1:11]
sys.path.insert(0, str(pathlib.Path(project_root) / "cli"))
from pr_summary_common import format_vendor_override_pr_banner

sediff_section = pathlib.Path(sediff_path).read_text(encoding="utf-8", errors="replace").strip()
body = pathlib.Path(template_path).read_text(encoding="utf-8")
pr_summary = pathlib.Path(pr_summary_path).read_text(encoding="utf-8").strip()
avc_log = pathlib.Path(avc_log_path)
if avc_log.is_file() and avc_log.stat().st_size:
    lines = [
        ln for ln in avc_log.read_text(encoding="utf-8", errors="replace").splitlines()
        if ln.startswith("type=AVC") or "avc: denied" in ln
    ]
    avc_excerpt = "\n".join(lines[:8]) or "(AVC log present but no matching lines)"
else:
    avc_excerpt = "(no AVC log found — run export before assemble)"

override_block = ""
findings_path = pathlib.Path(pr_summary_path).with_name("findings.json")
if findings_path.is_file():
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        override = data.get("vendor_override")
        if isinstance(override, dict) and override.get("reason"):
            override_block = format_vendor_override_pr_banner(override)
    except (json.JSONDecodeError, OSError):
        override_block = ""

replacements = {
    "<!-- AUTO:POLICY_VERSION -->": policy_version,
    "<!-- AUTO:STAGING_HOST -->": staging_host,
    "<!-- AUTO:TEST_SUITE -->": test_suite,
    "<!-- AUTO:AVC_LINE_COUNT -->": str(avc_count),
    "<!-- AUTO:PR_SUMMARY -->": pr_summary + "\n",
    "<!-- AUTO:AVC_EXCERPT -->": avc_excerpt,
    "<!-- AUTO:SEDIFF -->": sediff_section + "\n",
    "<!-- AUTO:VENDOR_OVERRIDE -->": override_block,
}
for marker, value in replacements.items():
    body = body.replace(marker, value)

pathlib.Path(output_path).write_text(body.rstrip() + "\n", encoding="utf-8")
PY

echo "Wrote ${OUTPUT}"
