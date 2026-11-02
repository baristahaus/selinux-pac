#!/usr/bin/env bash
#
# test_avc_query_epoch.sh — Epoch filter and ausearch fail-closed, no real auditd.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=../scripts/lib/avc_query.sh
source "${PROJECT_ROOT}/scripts/lib/avc_query.sh"

filtered="$(printf '%s\n' \
    'type=AVC msg=audit(1000.100:1): old path="/var/log/shopapi/old.log"' \
    'type=AVC msg=audit(5000.100:2): new path="/var/log/shopapi/new.log"' \
    | avc_filter_since_epoch 2000)"
[[ "${filtered}" == *new.log* ]]
[[ "${filtered}" != *old.log* ]]

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cat >"${work}/ausearch" <<'EOF'
#!/bin/bash
echo "<no matches>" >&2
exit 1
EOF
chmod +x "${work}/ausearch"
if ! PATH="${work}:${PATH}" fetch_domain_avc_raw shopapi_t recent >/dev/null; then
    echo "ausearch <no matches> must not fail closed" >&2
    exit 1
fi

cat >"${work}/ausearch" <<'EOF'
#!/bin/bash
echo "Invalid start time" >&2
exit 1
EOF
if PATH="${work}:${PATH}" fetch_domain_avc_raw shopapi_t recent >/dev/null; then
    echo "ausearch errors other than <no matches> must fail closed" >&2
    exit 1
fi

cat >"${work}/ausearch" <<'EOF'
#!/bin/bash
printf '%s\n' "$@" >"${AUSEARCH_ARGS}"
printf '%s\n' 'type=AVC msg=audit(1700000001.000:1): kept'
exit 0
EOF
export AUSEARCH_ARGS="${work}/args"
PATH="${work}:${PATH}" fetch_domain_avc_raw shopapi_t "10/08/2026 10:00:00" >/dev/null
if grep -q -- '-ts' "${work}/args"; then
    echo "a formatted date was passed to ausearch -ts" >&2
    exit 1
fi
: >"${work}/args"
PATH="${work}:${PATH}" fetch_domain_avc_raw shopapi_t 1700000000 >/dev/null
if grep -q -- '-ts' "${work}/args"; then
    echo "an epoch was passed to ausearch -ts" >&2
    exit 1
fi

if grep -n 'avc_epoch_to_ts' \
    "${PROJECT_ROOT}/scripts/lib/avc_query.sh" \
    "${PROJECT_ROOT}/scripts/monitor_avc.sh" \
    "${PROJECT_ROOT}/scripts/check_soak_ready.sh" >/dev/null; then
    echo "avc_epoch_to_ts is still used" >&2
    exit 1
fi
if ! grep -q 'date +%s' "${PROJECT_ROOT}/lab/reset_demo_vms.sh"; then
    echo "reset marker must be stored with date +%s" >&2
    exit 1
fi
if grep -q "date '+%m" "${PROJECT_ROOT}/lab/reset_demo_vms.sh"; then
    echo "reset marker still writes a formatted ausearch date" >&2
    exit 1
fi

marker="${work}/marker"
printf '2000\n' >"${marker}"
cat >"${work}/ausearch" <<'EOF'
#!/bin/bash
printf '%s\n' \
    'type=AVC msg=audit(1000.000:1): avc: denied { write } for path="/var/log/shopapi/old.log" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_log_t:s0 tclass=file permissive=1' \
    'type=AVC msg=audit(5000.000:2): avc: denied { write } for path="/var/log/shopapi/new.log" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_log_t:s0 tclass=file permissive=1'
exit 0
EOF
export PATH="${work}:${PATH}"
set +e
json="$(bash "${PROJECT_ROOT}/scripts/monitor_avc.sh" \
    --domain shopapi_t \
    --paths /var/log/shopapi \
    --manifest "${work}/no-manifest.yml" \
    --marker-file "${marker}" \
    --max-avc 0 \
    --format json)"
mon_rc=$?
set -e
[[ "${mon_rc}" -ne 0 ]]
python3 - "${json}" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
if payload["count"] < 1 or payload["status"] != "fail":
    raise SystemExit(f"monitor did not fail closed on the post-marker denial: {payload}")
if payload["count"] != 1:
    raise SystemExit(f"pre-marker denial was counted: {payload}")
PY

export DEMO_STATE_DIR="${work}/demo"
mkdir -p "${DEMO_STATE_DIR}"
printf '2000\n' >"${DEMO_STATE_DIR}/ausearch-since"
export_app_avcs_to_file "${work}/avc.log" boot shopapi_t "" /var/log/shopapi
if grep -q 'old.log' "${work}/avc.log"; then
    echo "generate export included a denial from before the reset marker" >&2
    exit 1
fi
if ! grep -q 'new.log' "${work}/avc.log"; then
    echo "generate export missed the denial after the reset marker" >&2
    exit 1
fi

echo "avc epoch query tests passed"
