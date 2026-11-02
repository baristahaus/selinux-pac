#!/usr/bin/env bash
#
# avc_query.sh — Shared AVC counting for soak/monitor scripts.
#
set -euo pipefail

# ausearch -ts rejects "MM/DD/YYYY HH:MM:SS" as one argument ("Invalid start
# time"). Callers pass a keyword (recent, boot) or an integer epoch. An epoch
# is not given to -ts; records are kept when msg=audit(EPOCH. is >= that epoch.
avc_since_epoch() {
    local since="$1"
    if [[ "${since}" =~ ^[0-9]+$ ]]; then
        printf '%s' "${since}"
        return 0
    fi
    if [[ "${since}" == */* ]]; then
        python3 - "${since}" <<'PY'
import datetime, sys
text = sys.argv[1].strip()
stamp = datetime.datetime.strptime(text, "%m/%d/%Y %H:%M:%S")
print(int(stamp.timestamp()))
PY
        return 0
    fi
    return 1
}

avc_filter_since_epoch() {
    local min_epoch="$1"
    local line record_epoch
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        if [[ "${line}" =~ msg=audit\(([0-9]+) ]]; then
            record_epoch="${BASH_REMATCH[1]}"
            if [[ "${record_epoch}" -ge "${min_epoch}" ]]; then
                printf '%s\n' "${line}"
            fi
        fi
    done
}

count_domain_events_since() {
    local domain="$1"
    local since_ts="$2"
    local raw count

    if ! command -v ausearch >/dev/null 2>&1 && [[ ! -f "${AUDIT_LOG:-/var/log/audit/audit.log}" ]]; then
        echo "-1"
        return 0
    fi
    if ! raw="$(fetch_domain_avc_raw "${domain}" "${since_ts}")"; then
        echo "-1"
        return 0
    fi
    count="$(printf '%s\n' "${raw}" | grep -c '^type=AVC' || true)"
    echo "${count:-0}"
}

# Keep every AVC whose scontext type is one of the domains.
# A path= outside the manifest paths is still a denial and still counts.
# Optional ignore list is tclass:target_type pairs (comma-separated).
# Optional 4th arg is a file that receives one "tclass target_type" line per ignored AVC.
avc_filter_lines_by_paths() {
    local _paths_csv="$1"
    local domains_csv="${2:-}"
    local ignore_csv="${3:-}"
    local ignored_log="${4:-}"
    local -a domains=() ignores=()
    local line sctx stype tctx ttype tclass rule iclass itype ignored
    if [[ -n "${domains_csv}" ]]; then
        IFS=',' read -r -a domains <<< "${domains_csv}"
    fi
    if [[ -n "${ignore_csv}" ]]; then
        IFS=',' read -r -a ignores <<< "${ignore_csv}"
    fi
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        [[ "${line}" != type=AVC* ]] && continue
        sctx="${line##* scontext=}"
        sctx="${sctx%% *}"
        stype="$(printf '%s' "${sctx}" | cut -d: -f3)"
        if [[ ${#domains[@]} -gt 0 ]]; then
            local keep=0 d
            for d in "${domains[@]}"; do
                d="${d// /}"
                if [[ -n "${d}" && "${stype}" == "${d}" ]]; then
                    keep=1
                    break
                fi
            done
            [[ "${keep}" -eq 1 ]] || continue
        fi
        tctx="${line##* tcontext=}"
        tctx="${tctx%% *}"
        ttype="$(printf '%s' "${tctx}" | cut -d: -f3)"
        tclass="${line##* tclass=}"
        tclass="${tclass%% *}"
        ignored=0
        if [[ ${#ignores[@]} -gt 0 ]]; then
            for rule in "${ignores[@]}"; do
                rule="${rule// /}"
                [[ -z "${rule}" ]] && continue
                iclass="${rule%%:*}"
                itype="${rule#*:}"
                if [[ "${tclass}" == "${iclass}" && "${ttype}" == "${itype}" ]]; then
                    ignored=1
                    break
                fi
            done
        fi
        if [[ "${ignored}" -eq 1 ]]; then
            if [[ -n "${ignored_log}" ]]; then
                printf '%s %s\n' "${tclass}" "${ttype}" >> "${ignored_log}"
            fi
            continue
        fi
        printf '%s\n' "${line}"
    done
}

# Demo reset writes this instead of truncating /var/log/audit.
demo_ausearch_since_file() {
    printf '%s\n' "${DEMO_STATE_DIR:-/var/lib/selinux-pac-demo}/ausearch-since"
}

resolve_ausearch_since() {
    local since_ts="$1"
    local marker
    marker="$(demo_ausearch_since_file)"
    if [[ "${since_ts}" == "boot" && -f "${marker}" ]]; then
        tr -d '\n' <"${marker}"
        return 0
    fi
    printf '%s' "${since_ts}"
}

# Read AVC records for one domain. since_ts is an ausearch keyword or an epoch.
# A formatted date is converted to an epoch and is not passed to -ts.
# Exit 1 when ausearch fails for any reason other than "<no matches>".
fetch_domain_avc_raw() {
    local domain="$1"
    local since_ts="$2"
    local epoch="" raw="" err rc log_file
    local -a args=()

    if avc_since_epoch "${since_ts}" >/dev/null 2>&1; then
        epoch="$(avc_since_epoch "${since_ts}")"
    fi

    if command -v ausearch >/dev/null 2>&1; then
        if [[ -n "${AUDIT_LOG:-}" ]]; then
            args+=(-if "${AUDIT_LOG}")
        else
            args+=(--input-logs)
        fi
        args+=(-m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR --subject "${domain}" --format raw)
        if [[ -z "${epoch}" && -n "${since_ts}" ]]; then
            args+=(-ts "${since_ts}")
        fi
        err="$(mktemp)"
        set +e
        raw="$(ausearch "${args[@]}" 2>"${err}")"
        rc=$?
        set -e
        if [[ "${rc}" -ne 0 ]]; then
            if grep -q '<no matches>' "${err}" || grep -q '<no matches>' <<<"${raw}"; then
                rm -f "${err}"
                return 0
            fi
            echo "ausearch failed: $(tr '\n' ' ' <"${err}")" >&2
            rm -f "${err}"
            return 1
        fi
        rm -f "${err}"
        if [[ -n "${epoch}" ]]; then
            printf '%s\n' "${raw}" | avc_filter_since_epoch "${epoch}"
        else
            printf '%s\n' "${raw}"
        fi
        return 0
    fi

    log_file="${AUDIT_LOG:-/var/log/audit/audit.log}"
    if [[ -f "${log_file}" ]]; then
        raw="$(grep -E '^(type=AVC|type=SELINUX_ERR|type=USER_AVC|type=USER_SELINUX_ERR)' "${log_file}" \
            | grep "${domain}" || true)"
        if [[ -n "${epoch}" ]]; then
            printf '%s\n' "${raw}" | avc_filter_since_epoch "${epoch}"
        else
            printf '%s\n' "${raw}"
        fi
    fi
}

# Export app-related AVC lines (same message types / --subject as monitor_avc.sh).
export_app_avcs_to_file() {
    local outfile="$1"
    local since_ts="${2:-boot}"
    local primary_domain="$3"
    local marker_bounds=0
    local backend_domain="${4:-}"
    local paths_csv="$5"

    if [[ -z "${primary_domain}" ]]; then
        echo "[ERROR] export_app_avcs_to_file: primary_domain required (manifest PRIMARY_DOMAIN)" >&2
        return 1
    fi
    if [[ -z "${paths_csv}" ]]; then
        echo "[ERROR] export_app_avcs_to_file: paths_csv required (manifest PATHS_CSV via app_manifest.py)" >&2
        return 1
    fi

    since_ts="$(resolve_ausearch_since "${since_ts}")"
    if [[ -f "$(demo_ausearch_since_file)" ]]; then
        marker_bounds=1
    fi

    mkdir -p "$(dirname "${outfile}")"
    : > "${outfile}"

    local raw="" chunk=""
    if ! chunk="$(fetch_domain_avc_raw "${primary_domain}" "${since_ts}")"; then
        echo "[ERROR] ausearch failed; refusing an empty AVC export" >&2
        return 1
    fi
    raw="${chunk}"
    if [[ -n "${backend_domain}" && "${backend_domain}" != "${primary_domain}" ]]; then
        if ! chunk="$(fetch_domain_avc_raw "${backend_domain}" "${since_ts}")"; then
            echo "[ERROR] ausearch failed; refusing an empty AVC export" >&2
            return 1
        fi
        raw+=$'\n'
        raw+="${chunk}"
    fi

    local tmp
    tmp="$(mktemp)"
    if [[ -n "${raw}" ]]; then
        printf '%s\n' "${raw}" | avc_filter_lines_by_paths "${paths_csv}" "${primary_domain}" >> "${tmp}" || true
    fi

    # Also read audit.log when no demo marker is set. A reset marker is an
    # epoch; fetch_domain_avc_raw already dropped older msg=audit records.
    # Do not pull those lines back out of audit.log.
    if [[ "${marker_bounds}" -eq 0 && -f /var/log/audit/audit.log ]]; then
        grep -E '^(type=AVC|type=SELINUX_ERR|type=USER_AVC|type=USER_SELINUX_ERR)' /var/log/audit/audit.log \
            | grep "${primary_domain}" \
            | avc_filter_lines_by_paths "${paths_csv}" "${primary_domain}" >> "${tmp}" || true
        if [[ -n "${backend_domain}" && "${backend_domain}" != "${primary_domain}" ]]; then
            grep -E '^(type=AVC|type=SELINUX_ERR|type=USER_AVC|type=USER_SELINUX_ERR)' /var/log/audit/audit.log \
                | grep "${backend_domain}" \
                | avc_filter_lines_by_paths "${paths_csv}" "${backend_domain}" >> "${tmp}" || true
        fi
    fi
    sort -u "${tmp}" > "${outfile}"
    rm -f "${tmp}"
}

# Domain-only AVC export for vendor tune-report (no path filter — binds/connects included).
export_vendor_domain_avcs_to_file() {
    local outfile="$1"
    local domain="$2"
    local since_ts="${3:-boot}"
    since_ts="$(resolve_ausearch_since "${since_ts}")"

    if [[ -z "${domain}" ]]; then
        echo "[ERROR] export_vendor_domain_avcs_to_file: domain required" >&2
        return 1
    fi

    mkdir -p "$(dirname "${outfile}")"
    : > "${outfile}"

    local tmp chunk
    tmp="$(mktemp)"
    if ! chunk="$(fetch_domain_avc_raw "${domain}" "${since_ts}")"; then
        rm -f "${tmp}"
        echo "[ERROR] ausearch failed; refusing an empty AVC export" >&2
        return 1
    fi
    printf '%s\n' "${chunk}" >> "${tmp}"
    if [[ ! -f "$(demo_ausearch_since_file)" && -f /var/log/audit/audit.log ]]; then
        grep -E '^(type=AVC|type=SELINUX_ERR|type=USER_AVC|type=USER_SELINUX_ERR)' /var/log/audit/audit.log \
            | grep "${domain}" >> "${tmp}" || true
    fi
    sort -u "${tmp}" > "${outfile}"
    rm -f "${tmp}"
}
