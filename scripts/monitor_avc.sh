#!/usr/bin/env bash
#
# monitor_avc.sh — Daily AVC report for permissive soak monitoring
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/avc_query.sh
source "${SCRIPT_DIR}/lib/avc_query.sh"
# shellcheck source=lib/manifest_shell.sh
source "${SCRIPT_DIR}/lib/manifest_shell.sh"

# Ansible become shells often omit /usr/sbin. Append those dirs so a caller
# PATH (a test fake for systemctl or auditctl) is still found first.
export PATH="${PATH:-}:/usr/sbin:/usr/bin:/sbin:/bin"

DOMAIN=""
PATHS="${MONITOR_PATHS:-}"
SINCE="${MONITOR_SINCE:-recent}"
MAX_AVC="${MONITOR_MAX_AVC:--1}"
MAX_NET_NEW="${MONITOR_MAX_NET_NEW:--1}"
SHOW_LINES="${MONITOR_SHOW_LINES:-10}"
MARKER_FILE="${SOAK_MARKER_FILE:-}"
MANIFEST=""
POLICY_KERN="${POLICY_KERN:-/sys/fs/selinux/policy}"
DOMAIN_CLI=0
PATHS_CLI=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Report SELinux events for a domain during permissive soak. Exit non-zero if count exceeds --max-avc or --max-net-new.

Options:
  --domain NAME         SELinux domain (or use --manifest)
  --paths CSV           Path filter substring list (or use --manifest)
  --manifest PATH       Load domain and paths from app manifest
  --since TS            ausearch keyword (recent, boot) or an epoch (default: recent)
  --marker-file PATH    Keep records whose msg=audit epoch is >= this file (overrides --since)
  --max-avc N           Fail if raw count > N (-1 = report only, default)
  --max-net-new N       Fail if net-new access needs > N (-1 = report only, default)
  --policy-kern PATH    Kernel policy for sesearch net-new (-1 default)
  --show-lines N        Print last N matching lines (default: 10)
  --format FORMAT       Output format: text (default) or json
  --fail-dir DIR        On fail, write selinux_soak_last_fail.json + .avc here
  --notify-webhook URL  POST JSON summary to webhook on failure
  --skip-if-unavailable Exit 0 when audit tools unavailable (CI smoke)
  -h, --help            Show help
EOF
}

SKIP_IF_UNAVAILABLE=0
OUTPUT_FORMAT="text"
NOTIFY_WEBHOOK=""
FAIL_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; DOMAIN_CLI=1; shift 2 ;;
        --paths) PATHS="$2"; PATHS_CLI=1; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --since) SINCE="$2"; shift 2 ;;
        --marker-file) MARKER_FILE="$2"; shift 2 ;;
        --max-avc) MAX_AVC="$2"; shift 2 ;;
        --max-net-new) MAX_NET_NEW="$2"; shift 2 ;;
        --policy-kern) POLICY_KERN="$2"; shift 2 ;;
        --show-lines) SHOW_LINES="$2"; shift 2 ;;
        --format) OUTPUT_FORMAT="$2"; shift 2 ;;
        --fail-dir) FAIL_DIR="$2"; shift 2 ;;
        --notify-webhook) NOTIFY_WEBHOOK="$2"; shift 2 ;;
        --skip-if-unavailable) SKIP_IF_UNAVAILABLE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [[ -z "${MANIFEST}" ]]; then
    MANIFEST="$(resolve_app_manifest_path "" 2>/dev/null || true)"
fi
if [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]]; then
    source_app_manifest_exports "${MANIFEST}"
    [[ "${DOMAIN_CLI}" -eq 0 ]] && DOMAIN="${PRIMARY_DOMAIN}"
    [[ "${PATHS_CLI}" -eq 0 ]] && PATHS="${PATHS_CSV}"
fi

if [[ -z "${DOMAIN}" ]]; then
    log_error "SELinux domain required (--domain or --manifest)"
    exit 1
fi
if [[ -z "${PATHS}" ]]; then
    log_error "Path filters required (--paths or --manifest with paths.*)"
    exit 1
fi

audit_unhealthy=0
if [[ -n "${MARKER_FILE}" && -f "${MARKER_FILE}" ]]; then
    deploy_epoch="$(tr -d '[:space:]' < "${MARKER_FILE}")"
    if [[ "${deploy_epoch}" =~ ^[0-9]+$ ]]; then
        SINCE="${deploy_epoch}"
    fi
    audit_err="$(mktemp)"
    if ! bash "${SCRIPT_DIR}/check_audit_health.sh" "${MARKER_FILE}" >"${audit_err}" 2>&1; then
        audit_unhealthy=1
        fail_closed_reason="$(tr '\n' ' ' <"${audit_err}")"
        fail_closed_reason="${fail_closed_reason:-auditd is not recording}"
    fi
    rm -f "${audit_err}"
fi

DOMAINS_CSV="${DOMAIN}"
if [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]]; then
    DOMAINS_CSV="$(python3 "${SCRIPT_DIR}/lib/app_manifest.py" domains-csv "${MANIFEST}" 2>/dev/null || echo "${DOMAIN}")"
fi

raw=""
avc_fail_closed=0
if [[ "${audit_unhealthy}" -eq 0 ]]; then
    fail_closed_reason=""
fi
fetch_err="$(mktemp)"
IFS=',' read -r -a domain_list <<< "${DOMAINS_CSV}"
for d in "${domain_list[@]}"; do
    d="${d// /}"
    [[ -z "${d}" ]] && continue
    set +e
    chunk="$(fetch_domain_avc_raw "${d}" "${SINCE}" 2>"${fetch_err}")"
    fetch_rc=$?
    set -e
    if [[ "${fetch_rc}" -ne 0 ]]; then
        avc_fail_closed=1
        fail_closed_reason="$(tr '\n' ' ' <"${fetch_err}")"
        fail_closed_reason="${fail_closed_reason:-ausearch failed}"
    elif [[ -n "${chunk}" ]]; then
        raw+="${chunk}"$'\n'
    fi
done
rm -f "${fetch_err}"

if [[ -z "${raw}" ]] && ! command -v ausearch >/dev/null 2>&1 && [[ ! -f /var/log/audit/audit.log ]]; then
    if [[ "${SKIP_IF_UNAVAILABLE}" -eq 1 ]]; then
        log_info "No audit sources available — skipping AVC monitor"
        exit 0
    fi
    log_error "No ausearch or /var/log/audit/audit.log available"
    exit 1
fi

ignored_log="$(mktemp)"
: > "${ignored_log}"
matches=()
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    matches+=("${line}")
done < <(printf '%s\n' "${raw}" | avc_filter_lines_by_paths "${PATHS}" "${DOMAINS_CSV}" "${SOAK_IGNORE_CSV:-}" "${ignored_log}")

count="${#matches[@]}"
ignored_count="$(wc -l < "${ignored_log}" | tr -d '[:space:]')"
ignored_json="$(python3 - "${ignored_log}" <<'PY'
import collections, json, sys

counts = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8"):
    parts = line.split()
    if len(parts) == 2:
        counts[tuple(parts)] += 1
rows = [
    {"tclass": tclass, "target_type": target, "count": count}
    for (tclass, target), count in sorted(counts.items())
]
print(json.dumps(rows))
PY
)"

net_new_json="$(mktemp)"
net_new_count=0
if [[ ${#matches[@]} -gt 0 ]]; then
    soak_py=""
    if [[ -f "${PROJECT_ROOT}/cli/soak_net_new.py" ]]; then
        soak_py="${PROJECT_ROOT}/cli/soak_net_new.py"
    elif [[ -f "${SCRIPT_DIR}/lib/soak_net_new.py" ]]; then
        soak_py="${SCRIPT_DIR}/lib/soak_net_new.py"
    fi
    if [[ -z "${soak_py}" ]]; then
        net_new_count=-1
        avc_fail_closed=1
        fail_closed_reason="soak_net_new.py missing on this host"
    else
        soak_cmd=(python3 "${soak_py}" --policy-kern "${POLICY_KERN}" --json-out "${net_new_json}")
        if [[ -n "${MANIFEST}" && -f "${MANIFEST}" ]]; then
            soak_cmd+=(--manifest "${MANIFEST}")
        fi
        soak_err="$(mktemp)"
        if printf '%s\n' "${matches[@]}" | "${soak_cmd[@]}" >/dev/null 2>"${soak_err}"; then
            net_new_count="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("net_new_count",-1))' "${net_new_json}")"
            if [[ "$(python3 -c 'import json,sys; print(1 if json.load(open(sys.argv[1])).get("fail_closed") else 0)' "${net_new_json}")" -eq 1 ]]; then
                avc_fail_closed=1
                fail_closed_reason="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("fail_closed_reason",""))' "${net_new_json}")"
            fi
        else
            net_new_count=-1
            avc_fail_closed=1
            fail_closed_reason="$(tr '\n' ' ' <"${soak_err}")"
            fail_closed_reason="${fail_closed_reason:-soak_net_new.py failed}"
        fi
        rm -f "${soak_err}"
    fi
fi

if [[ "${audit_unhealthy}" -eq 1 ]]; then
    avc_fail_closed=1
fi

fail=0
if [[ "${avc_fail_closed}" -eq 1 ]]; then
    fail=1
fi
if [[ "${MAX_AVC}" -ge 0 && "${count}" -gt "${MAX_AVC}" ]]; then
    fail=1
fi
if [[ "${MAX_NET_NEW}" -ge 0 && "${net_new_count}" -ge 0 && "${avc_fail_closed}" -eq 0 && "${net_new_count}" -gt "${MAX_NET_NEW}" ]]; then
    fail=1
fi

ignored_stale_daily='[]'
ignored_stale_fail='[]'
if [[ -n "${MARKER_FILE}" && -f "${MARKER_FILE}" && -n "${FAIL_DIR}" && -d "${FAIL_DIR}" ]]; then
    stale_out="$(python3 - "${MARKER_FILE}" "${FAIL_DIR}" <<'PY'
import json
import sys
from pathlib import Path

marker_path, fail_dir = Path(sys.argv[1]), Path(sys.argv[2])
raw = marker_path.read_text(encoding="utf-8").strip()
if not raw.isdigit():
    print(json.dumps({"daily": [], "fail": []}))
    raise SystemExit(0)
marker = int(raw)


def record_epoch(path: Path, record: dict) -> int:
    for key in ("marker_epoch", "since"):
        value = record.get(key)
        if isinstance(value, int) or (isinstance(value, str) and str(value).isdigit()):
            return int(value)
    return int(path.stat().st_mtime)


daily = []
daily_dir = fail_dir / "daily"
if daily_dir.is_dir():
    for path in sorted(daily_dir.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                record = {}
        except (json.JSONDecodeError, OSError):
            record = {}
        if record_epoch(path, record) < marker:
            daily.append(path.name)

fail_names = []
fail_json = fail_dir / "selinux_soak_last_fail.json"
fail_avc = fail_dir / "selinux_soak_last_fail.avc"
if fail_json.is_file():
    try:
        record = json.loads(fail_json.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            record = {}
    except (json.JSONDecodeError, OSError):
        record = {}
    if record_epoch(fail_json, record) < marker:
        fail_names.append(fail_json.name)
        if fail_avc.is_file():
            fail_names.append(fail_avc.name)
elif fail_avc.is_file() and int(fail_avc.stat().st_mtime) < marker:
    fail_names.append(fail_avc.name)
print(json.dumps({"daily": daily, "fail": fail_names}))
PY
)"
    ignored_stale_daily="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["daily"]))' "${stale_out}")"
    ignored_stale_fail="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["fail"]))' "${stale_out}")"
fi

NEXT_STEP=""
if [[ "${fail}" -eq 1 ]]; then
    fail_dir_shown="${FAIL_DIR:-/var/lib/selinux-policy-ops/<app>}"
    NEXT_STEP="Copy ${fail_dir_shown}/selinux_soak_last_fail.json and selinux_soak_last_fail.avc to rhel-qa. Run bash scripts/dev_generate_policy.sh. Open a PR, recanary, reset soak. Do not semodule -i or audit2allow on this host. See docs/shipping.md#a-denial-after-ship."
fi

if [[ "${fail}" -eq 1 && -n "${FAIL_DIR}" ]]; then
    mkdir -p "${FAIL_DIR}"
    avc_excerpt="${FAIL_DIR}/selinux_soak_last_fail.avc"
    if [[ "${count}" -gt 0 ]]; then
        start=$(( count > SHOW_LINES ? count - SHOW_LINES : 0 ))
        printf '%s\n' "${matches[@]:${start}}" > "${avc_excerpt}"
    else
        : > "${avc_excerpt}"
    fi
    MON_DOMAIN="${DOMAIN}" MON_SINCE="${SINCE}" MON_COUNT="${count}" \
        MON_MAX_AVC="${MAX_AVC}" MON_MAX_NET_NEW="${MAX_NET_NEW}" \
        MON_NET_NEW="${net_new_count}" MON_FAIL_CLOSED="${avc_fail_closed}" \
        MON_FAIL_REASON="${fail_closed_reason}" \
        MON_IGNORED_COUNT="${ignored_count}" MON_IGNORED_JSON="${ignored_json}" \
        MON_STALE_DAILY="${ignored_stale_daily}" MON_STALE_FAIL="${ignored_stale_fail}" \
        MON_NEXT_STEP="${NEXT_STEP}" MON_FAIL_DIR="${FAIL_DIR}" \
        python3 - "${net_new_json}" "${FAIL_DIR}/selinux_soak_last_fail.json" "${avc_excerpt}" <<'PY'
import json, os, sys

net_path, out_path, avc_path = sys.argv[1], sys.argv[2], sys.argv[3]
extra = {}
if os.path.isfile(net_path) and os.path.getsize(net_path) > 0:
    extra = json.load(open(net_path, encoding="utf-8"))
payload = {
    "domain": os.environ["MON_DOMAIN"],
    "since": os.environ["MON_SINCE"],
    "count": int(os.environ["MON_COUNT"]),
    "max_avc": int(os.environ["MON_MAX_AVC"]),
    "max_net_new": int(os.environ["MON_MAX_NET_NEW"]),
    "net_new_count": int(os.environ.get("MON_NET_NEW", "-1")),
    "avc_fail_closed": os.environ.get("MON_FAIL_CLOSED", "0") == "1",
    "fail_closed_reason": os.environ.get("MON_FAIL_REASON", extra.get("fail_closed_reason", "")),
    "ignored_count": int(os.environ.get("MON_IGNORED_COUNT", "0")),
    "ignored": json.loads(os.environ.get("MON_IGNORED_JSON", "[]")),
    "ignored_stale_daily": json.loads(os.environ.get("MON_STALE_DAILY", "[]")),
    "ignored_stale_fail": json.loads(os.environ.get("MON_STALE_FAIL", "[]")),
    "exceptions": extra.get("exceptions", [])[:20],
    "status": "fail",
    "next_step": os.environ.get("MON_NEXT_STEP", ""),
    "avc_excerpt": avc_path,
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY
fi

if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
    MON_DOMAIN="${DOMAIN}" MON_SINCE="${SINCE}" MON_COUNT="${count}" \
        MON_MAX_AVC="${MAX_AVC}" MON_MAX_NET_NEW="${MAX_NET_NEW}" \
        MON_NET_NEW="${net_new_count}" MON_FAIL_CLOSED="${avc_fail_closed}" \
        MON_FAIL_REASON="${fail_closed_reason}" \
        MON_IGNORED_COUNT="${ignored_count}" MON_IGNORED_JSON="${ignored_json}" \
        MON_STALE_DAILY="${ignored_stale_daily}" MON_STALE_FAIL="${ignored_stale_fail}" \
        MON_STATUS="$([[ "${fail}" -eq 1 ]] && echo fail || echo pass)" \
        MON_NEXT_STEP="${NEXT_STEP}" \
        python3 - "${net_new_json}" <<'PY'
import json, sys, os

net_path = sys.argv[1]
extra = {}
if os.path.isfile(net_path) and os.path.getsize(net_path) > 0:
    extra = json.load(open(net_path, encoding="utf-8"))

out = {
    "domain": os.environ["MON_DOMAIN"],
    "since": os.environ["MON_SINCE"],
    "count": int(os.environ["MON_COUNT"]),
    "max_avc": int(os.environ["MON_MAX_AVC"]),
    "max_net_new": int(os.environ["MON_MAX_NET_NEW"]),
    "net_new_count": int(os.environ.get("MON_NET_NEW", "-1")),
    "avc_fail_closed": os.environ.get("MON_FAIL_CLOSED", "0") == "1",
    "fail_closed_reason": os.environ.get("MON_FAIL_REASON", extra.get("fail_closed_reason", "")),
    "ignored_count": int(os.environ.get("MON_IGNORED_COUNT", "0")),
    "ignored": json.loads(os.environ.get("MON_IGNORED_JSON", "[]")),
    "ignored_stale_daily": json.loads(os.environ.get("MON_STALE_DAILY", "[]")),
    "ignored_stale_fail": json.loads(os.environ.get("MON_STALE_FAIL", "[]")),
    "exceptions": extra.get("exceptions", [])[:20],
    "status": os.environ.get("MON_STATUS", "pass"),
}
next_step = os.environ.get("MON_NEXT_STEP", "")
if next_step:
    out["next_step"] = next_step
print(json.dumps(out, indent=2))
PY
else
    log_info "AVC report: domain=${DOMAIN} since=${SINCE} count=${count} net_new=${net_new_count}"
fi

rm -f "${net_new_json}" "${ignored_log}"

if [[ "${OUTPUT_FORMAT}" != "json" && "${SHOW_LINES}" -gt 0 && "${count}" -gt 0 ]]; then
    echo "--- recent matching event lines ---"
    start=$(( count > SHOW_LINES ? count - SHOW_LINES : 0 ))
    for ((i=start; i<count; i++)); do
        echo "${matches[$i]}"
    done
fi

if [[ "${fail}" -eq 1 ]]; then
    if [[ "${MAX_AVC}" -ge 0 && "${count}" -gt "${MAX_AVC}" ]]; then
        log_error "Event count ${count} exceeds threshold ${MAX_AVC}"
    fi
    if [[ "${MAX_NET_NEW}" -ge 0 && "${net_new_count}" -ge 0 && "${avc_fail_closed}" -eq 0 && "${net_new_count}" -gt "${MAX_NET_NEW}" ]]; then
        log_error "Net-new access needs ${net_new_count} exceed threshold ${MAX_NET_NEW}"
    fi
    if [[ -n "${NEXT_STEP}" ]]; then
        log_error "${NEXT_STEP}"
    fi
    if [[ -n "${NOTIFY_WEBHOOK}" ]]; then
        curl -sf -X POST -H "Content-Type: application/json" \
            -d "{\"text\":\"SELinux AVC alert: domain=${DOMAIN} count=${count} net_new=${net_new_count}\"}" \
            "${NOTIFY_WEBHOOK}" >/dev/null 2>&1 || true
    fi
    exit 1
fi

if [[ "${OUTPUT_FORMAT}" != "json" ]]; then
    log_info "AVC monitoring check complete"
fi
