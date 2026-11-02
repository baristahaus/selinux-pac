#!/usr/bin/env bash
#
# test_avc_epoch_window.sh — Real ausearch on a sample audit log.
# Stream 9 CI sets AVC_REQUIRE_AUSEARCH=1. Without ausearch this skips.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v ausearch >/dev/null 2>&1; then
    if [[ "${AVC_REQUIRE_AUSEARCH:-}" == 1 ]]; then
        echo "ausearch is required (install audit)" >&2
        exit 1
    fi
    echo "skip: ausearch not installed"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
log="${work}/audit.log"
marker_epoch=1700000000
printf 'type=AVC msg=audit(1600000000.000:1): avc:  denied  { write } for  pid=1 comm="java" path="/var/log/shopapi/old.log" dev="sda1" ino=1 scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_log_t:s0 tclass=file permissive=1\n' >"${log}"
printf 'type=AVC msg=audit(1700000001.000:2): avc:  denied  { write } for  pid=1 comm="java" path="/var/log/shopapi/new.log" dev="sda1" ino=2 scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_log_t:s0 tclass=file permissive=1\n' >>"${log}"
printf '%s\n' "${marker_epoch}" >"${work}/marker"

export AUDIT_LOG="${log}"
set +e
json="$(bash "${PROJECT_ROOT}/scripts/monitor_avc.sh" \
    --domain shopapi_t \
    --paths /var/log/shopapi \
    --manifest "${work}/no-manifest.yml" \
    --marker-file "${work}/marker" \
    --max-avc 0 \
    --format json)"
mon_rc=$?
set -e
[[ "${mon_rc}" -ne 0 ]]
python3 - "${json}" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
reason = str(payload.get("fail_closed_reason") or "")
# shopapi_t is not in the base policy, so soak_net_new fail-closed is expected.
# An ausearch error is a different reason and must still fail this test.
if "ausearch" in reason.lower():
    raise SystemExit(f"ausearch failed closed on the sample log: {payload}")
if payload["count"] < 1 or payload["status"] != "fail":
    raise SystemExit(f"sample denial after the marker was not counted: {payload}")
if payload["count"] != 1:
    raise SystemExit(f"denial before the marker was counted: {payload}")
PY

# shellcheck source=../scripts/lib/avc_query.sh
source "${PROJECT_ROOT}/scripts/lib/avc_query.sh"
export DEMO_STATE_DIR="${work}/demo"
mkdir -p "${DEMO_STATE_DIR}"
printf '%s\n' "${marker_epoch}" >"${DEMO_STATE_DIR}/ausearch-since"
export_app_avcs_to_file "${work}/avc.log" boot shopapi_t "" /var/log/shopapi
if grep -q 'old.log' "${work}/avc.log"; then
    echo "generate export included a denial from before the reset marker" >&2
    exit 1
fi
if ! grep -q 'new.log' "${work}/avc.log"; then
    echo "generate export missed the denial after the reset marker" >&2
    cat "${work}/avc.log" >&2 || true
    exit 1
fi

echo "avc epoch window passed"
