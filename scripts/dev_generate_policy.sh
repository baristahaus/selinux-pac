#!/usr/bin/env bash
#
# dev_generate_policy.sh — One-command developer self-service policy generation
#
# Exports AVC logs, runs cli/deterministic_gen.py, diffs against selinux/
# promotes generated policy into selinux/ for PR commit.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DETERMINISTIC="${PROJECT_ROOT}/cli/deterministic_gen.py"
VERIFY_AVC="${PROJECT_ROOT}/cli/verify_avc_coverage.py"
APP_NAME=""
DOMAIN=""
APPLY=0
ENFORCE_CHECK=0
SKIP_EXPORT=0
OPEN_PR=0
FORCE=0
FORCE_REASON=""
TUNE_REPORT=0
ALLOW_NEEDS_REVIEW=0
ALLOW_NEEDS_REVIEW_PERMS=()
PRIMARY_SERVICE="${PRIMARY_SERVICE:-}"
OUT_DIR_ARG=""
AVC_LOG_ARG=""
STAGING_HOST="${STAGING_HOST:-rhel-qa}"
TEST_SUITE="${TEST_SUITE:-Integration tests (curl endpoints)}"
ASSEMBLE="${SCRIPT_DIR}/assemble_pr_body.sh"
# shellcheck source=lib/version.sh
source "${SCRIPT_DIR}/lib/version.sh"
# shellcheck source=lib/manifest_shell.sh
source "${SCRIPT_DIR}/lib/manifest_shell.sh"
# shellcheck source=lib/policy_generation.sh
source "${SCRIPT_DIR}/lib/policy_generation.sh"
# shellcheck source=lib/vendor_policy_check.sh
source "${SCRIPT_DIR}/lib/vendor_policy_check.sh"

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

Developer self-service: export AVCs → generate policy → diff → optional promote to selinux/

Options:
  --apply          Copy policy_out/{app}.te/.fc into selinux/ after generation
  --enforce-check  Load candidate policy enforcing and run endpoint + domain checks
  --open-pr        Run gh pr create with assembled pr_body.md (requires gh CLI + git branch)
  --skip-export    Use existing policy_out/avc.log (must be non-empty for generate)
  --tune-report    Read-only vendor-domain analysis (commands only; no policy module)
  --force REASON   Bypass vendor-policy pre-flight; REASON is required and recorded
  --allow-needs-review  Write domain-weakening allows (execmem, dac_override, …) after review
  --app-name NAME  Module name (default: myapp)
  --unit NAME      systemd unit for vendor triage / --tune-report (e.g. tomcat.service)
  --app-root DIR   Application tree (selinux/ + config/). Default: sibling/~/myapp
  --out-dir DIR    Artifact directory (default: APP_ROOT/policy_out)
  --avc-log PATH   AVC log for --skip-export / --tune-report (default: OUT_DIR/avc.log)
  --staging-host   Staging environment label for PR body
  --test-suite     Test suite description for PR body
  -h, --help       Show this help

Environment:
  POLICY_ALLOW_DEGRADED  Pass --allow-degraded to deterministic_gen when sepolgen missing
  POLICY_ALLOW_NEEDS_REVIEW  Pass --allow-needs-review (domain-weakening allows)

Example:
  sudo bash scripts/dev_generate_policy.sh --apply
  bash scripts/dev_generate_policy.sh --skip-export
  bash scripts/dev_generate_policy.sh --tune-report --app-name tomcat --unit tomcat.service
  bash scripts/dev_generate_policy.sh --force "non-standard layout vs jws6_tomcat" --apply
  git checkout -b policy/update && git add selinux/ && gh pr create --body-file policy_out/pr_body.md
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply) APPLY=1; shift ;;
        --enforce-check) ENFORCE_CHECK=1; shift ;;
        --open-pr) OPEN_PR=1; APPLY=1; shift ;;
        --skip-export) SKIP_EXPORT=1; shift ;;
        --tune-report) TUNE_REPORT=1; shift ;;
        --force)
            if [[ $# -lt 2 || -z "${2:-}" || "${2}" == -* ]]; then
                log_error "bare --force is rejected. A generated module that overrides vendor policy needs a recorded reason for reviewers."
                log_error "Usage: --force \"why this app genuinely differs from the vendor module\""
                exit 2
            fi
            FORCE=1
            FORCE_REASON="$2"
            shift 2
            ;;
        --allow-needs-review) ALLOW_NEEDS_REVIEW=1; shift ;;
        --allow-needs-review-perm)
            ALLOW_NEEDS_REVIEW_PERMS+=("$2")
            shift 2
            ;;
        --app-name|--app) APP_NAME="$2"; shift 2 ;;
        --unit) PRIMARY_SERVICE="$2"; shift 2 ;;
        --app-root) APP_ROOT="$2"; shift 2 ;;
        --out-dir) OUT_DIR_ARG="$2"; shift 2 ;;
        --avc-log) AVC_LOG_ARG="$2"; shift 2 ;;
        --staging-host) STAGING_HOST="$2"; shift 2 ;;
        --test-suite) TEST_SUITE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# shellcheck source=lib/app_root.sh
source "${SCRIPT_DIR}/lib/app_root.sh"
bind_app_tree "${PROJECT_ROOT}"
SELINUX_DIR="${APP_ROOT}/selinux"
POLICY_OUT="${OUT_DIR_ARG:-${APP_ROOT}/policy_out}"
AVC_LOG="${AVC_LOG_ARG:-${POLICY_OUT}/avc.log}"
if [[ -z "${APP_NAME}" ]]; then
    log_error "--app-name NAME is required"
    exit 2
fi
MANIFEST="${APP_ROOT}/config/${APP_NAME}.manifest.yml"
if [[ "${TUNE_REPORT}" -eq 0 ]]; then
    [[ -f "${MANIFEST}" ]] || { log_error "No manifest for ${APP_NAME}: ${MANIFEST}"; exit 1; }
fi
log_info "App tree ${APP_ROOT} (tool ${PROJECT_ROOT})"

sync_identity_from_manifest() {
    [[ -f "${MANIFEST}" ]] || {
        log_error "App manifest not found: ${MANIFEST}"
        exit 1
    }
    source_app_manifest_exports "${MANIFEST}"
    APP_NAME="${APP_NAME}"
    DOMAIN="${PRIMARY_DOMAIN}"
}

# Fail closed when vendor/base policy already covers this app (JWS, EAP, httpd, …).
# Missing semodule+rpm: one skip line and continue (laptop / fixture hosts).
check_vendor_policy() {
    local args=(--app-name "${APP_NAME}")
    mkdir -p "${POLICY_OUT}"
    export VENDOR_OVERRIDE_OUT="${POLICY_OUT}/vendor_override.json"
    rm -f "${VENDOR_OVERRIDE_OUT}"
    if [[ "${FORCE}" -eq 1 ]]; then
        args+=(--force "${FORCE_REASON}")
    fi
    if [[ -n "${PRIMARY_SERVICE:-}" ]]; then
        args+=(--unit "${PRIMARY_SERVICE}")
    fi
    vendor_policy_preflight "${args[@]}"
}

triage_field() {
    local line="$1"
    local key="$2"
    local value=""
    value="$(printf '%s\n' "${line}" | grep -oE "${key}=[^ ]*" | head -n 1 | cut -d= -f2- || true)"
    printf '%s\n' "${value}"
}

run_tune_report() {
    local triage="" situation="" action="" module="" package="" cls="" domain="" fc_type="" port_type=""
    local report_args=(--report --app-name "${APP_NAME}")
    local skip_notice="tune-report skipped: no SELinux tooling (ausearch/audit.log) and no AVC log to classify"

    if [[ "${APPLY}" -eq 1 ]]; then
        log_error "--tune-report does not write policy; do not combine it with --apply"
        exit 2
    fi

    mkdir -p "${POLICY_OUT}"
    if [[ -n "${PRIMARY_SERVICE:-}" ]]; then
        report_args+=(--unit "${PRIMARY_SERVICE}")
    fi
    triage="$(vendor_policy_preflight "${report_args[@]}" 2>&1 || true)"
    printf '%s\n' "${triage}"
    situation="$(triage_field "${triage}" situation)"
    action="$(triage_field "${triage}" action)"
    module="$(triage_field "${triage}" module)"
    package="$(triage_field "${triage}" package)"
    cls="$(triage_field "${triage}" class)"
    domain="$(triage_field "${triage}" domain)"
    fc_type="$(triage_field "${triage}" fc_type)"
    port_type="$(triage_field "${triage}" port_type)"
    domain="${domain:-${APP_NAME}_t}"
    fc_type="${fc_type:-${APP_NAME}_var_lib_t}"
    port_type="${port_type:-http_port_t}"
    cls="${cls:-none}"
    situation="${situation:-skipped}"

    if [[ "${action}" != "tune" && "${situation}" != "skipped" && "${situation}" != "loaded" && "${situation}" != "base_policy" ]]; then
        case "${situation}" in
            none)
                log_info "situation=none — this app is a generate candidate, not a vendor tune. No module written."
                ;;
            package_installed|package_available|unconfined)
                log_info "situation=${situation} — install or enable the vendor RPM first. --tune-report is for loaded/base_policy."
                ;;
            loaded_unconfined)
                log_info "situation=loaded_unconfined — the loaded domain is unconfined. Install the vendor's confining package, or generate with --force \"reason\". No module written."
                ;;
            *)
                log_info "situation=${situation:-unknown} — not a tune case. No module written."
                ;;
        esac
        printf '%s\n' "# Vendor policy tune report" "" \
            "Not a tune situation (\`${situation}\` / \`${action}\`). No policy module written." \
            > "${POLICY_OUT}/tune_report.md"
        cat "${POLICY_OUT}/tune_report.md"
        return 0
    fi

    if [[ "${SKIP_EXPORT}" -eq 0 && -z "${AVC_LOG_ARG:-}" ]]; then
        # shellcheck source=lib/avc_query.sh
        source "${SCRIPT_DIR}/lib/avc_query.sh"
        audit_log="${AUDIT_LOG:-/var/log/audit/audit.log}"
        if command -v ausearch >/dev/null 2>&1 || [[ -f "${audit_log}" ]]; then
            log_info "Collecting denials for vendor domain ${domain} (read-only)..."
            export_vendor_domain_avcs_to_file "${AVC_LOG}" "${domain}" boot || true
        elif [[ ! -s "${AVC_LOG}" ]]; then
            log_info "${skip_notice}"
            printf '%s\n' "# Vendor policy tune report" "" "${skip_notice}." \
                > "${POLICY_OUT}/tune_report.md"
            cat "${POLICY_OUT}/tune_report.md"
            return 0
        fi
    elif [[ ! -s "${AVC_LOG}" ]]; then
        audit_log="${AUDIT_LOG:-/var/log/audit/audit.log}"
        if command -v ausearch >/dev/null 2>&1 || [[ -f "${audit_log}" ]]; then
            :
        else
            log_info "${skip_notice}"
            printf '%s\n' "# Vendor policy tune report" "" "${skip_notice}." \
                > "${POLICY_OUT}/tune_report.md"
            cat "${POLICY_OUT}/tune_report.md"
            return 0
        fi
    fi

    if [[ ! -s "${AVC_LOG}" ]]; then
        log_info "No vendor-domain denials found for ${domain}. Writing an empty tune report."
    fi

    python3 "${PROJECT_ROOT}/cli/tune_report.py" \
        --avc-log "${AVC_LOG}" \
        --out-dir "${POLICY_OUT}" \
        --app-name "${APP_NAME}" \
        --domain "${domain}" \
        --module "${module}" \
        --package "${package}" \
        --vendor-class "${cls}" \
        --situation "${situation}" \
        --fc-type "${fc_type}" \
        --port-type "${port_type}"
}

resolve_manifest_policy_paths() {
    python3 - "${MANIFEST}" "${APP_ROOT}" "${PROJECT_ROOT}" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[3]) / "scripts" / "lib"))
from app_manifest import load_manifest, policy_source_paths

root = Path(sys.argv[2])
manifest = load_manifest(Path(sys.argv[1]))
paths = policy_source_paths(root, manifest)
print(paths["te"])
print(paths["fc"])
print(paths["version_file"])
print(paths["module_dir"])
PY
}

load_policy_paths_from_manifest() {
    local idx=0
    while IFS= read -r line; do
        case "${idx}" in
            0) POLICY_TE="${line}" ;;
            1) POLICY_FC="${line}" ;;
            2) POLICY_VERSION_FILE="${line}" ;;
            3) POLICY_MODULE_DIR="${line}" ;;
        esac
        idx=$((idx + 1))
    done < <(resolve_manifest_policy_paths)
}

require_existing_policy() {
    load_policy_paths_from_manifest
    [[ -f "${POLICY_TE}" ]] || {
        log_error "Missing ${POLICY_TE}"
        exit 1
    }
    [[ -f "${POLICY_FC}" ]] || {
        log_error "Missing ${POLICY_FC}"
        exit 1
    }
}

require_local_export_privileges() {
    [[ "$(id -u)" -eq 0 ]] && return 0
    local need_sudo=0
    if [[ -e "${POLICY_OUT}" && ! -w "${POLICY_OUT}" ]]; then
        need_sudo=1
    elif [[ -e "${AVC_LOG}" && ! -w "${AVC_LOG}" ]]; then
        need_sudo=1
    fi
    if [[ ! -r /var/log/audit/audit.log ]]; then
        need_sudo=1
    fi
    [[ "${need_sudo}" -eq 0 ]] && return 0
    log_error "This step must run with sudo."
    log_error "It reads the audit log and writes policy_out/ (that folder is often owned by root after generate)."
    echo "  cd ~/selinux-pac"
    echo "  sudo bash scripts/dev_generate_policy.sh --apply --app-name shopapi --app-root ~/selinux-pac"
    exit 1
}

restore_repo_ownership() {
    [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]] || return 0
    local grp
    grp="$(id -gn "${SUDO_USER}" 2>/dev/null || echo "${SUDO_USER}")"
    chown -R "${SUDO_USER}:${grp}" "${POLICY_OUT}" 2>/dev/null || true
    if [[ -n "${POLICY_MODULE_DIR:-}" ]]; then
        chown -R "${SUDO_USER}:${grp}" "${POLICY_MODULE_DIR}" 2>/dev/null || true
    fi
}

export_avcs() {
    sync_identity_from_manifest
    require_local_export_privileges
    mkdir -p "${POLICY_OUT}"
    # shellcheck source=lib/avc_query.sh
    source "${SCRIPT_DIR}/lib/avc_query.sh"
    if ! command -v ausearch >/dev/null 2>&1 && [[ ! -f /var/log/audit/audit.log ]]; then
        log_error "No ausearch on host; run this on a SELinux Linux host (rhel-qa)"
        exit 1
    fi
    log_info "Exporting AVCs from local audit log (avc_query pipeline)..."
    export_app_avcs_to_file "${AVC_LOG}" boot "${PRIMARY_DOMAIN}" "${BACKEND_DOMAIN:-}" "${PATHS_CSV}"
    [[ -s "${AVC_LOG}" ]] || {
        log_error "No AVC lines in ${AVC_LOG}. Exercise the app first (shopapi: curl /health /state /log)."
        echo "  sudo bash lab/demo_bootstrap.sh --shopapi-only"
        echo "  curl http://127.0.0.1:8091/health"
        exit 1
    }
    log_info "Exported $(wc -l < "${AVC_LOG}" | tr -d ' ') AVC lines to ${AVC_LOG}"
}

generate_policy() {
    log_info "Running cli/deterministic_gen.py (policy)..."
    if [[ "${ALLOW_NEEDS_REVIEW}" -eq 1 ]]; then
        export POLICY_ALLOW_NEEDS_REVIEW=1
    fi
    run_deterministic_policy_gen \
        "${AVC_LOG}" \
        "${MANIFEST}" \
        "${POLICY_TE}" \
        "${POLICY_FC}" \
        "${POLICY_VERSION_FILE}" \
        "${POLICY_OUT}" \
        "${APP_NAME}"
}

show_diff() {
    load_policy_paths_from_manifest
    log_info "Diff: ${POLICY_MODULE_DIR}/ vs policy_out/"
    if command -v git >/dev/null 2>&1 && git -C "${PROJECT_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "${PROJECT_ROOT}" diff --no-index \
            "${POLICY_TE}" "${POLICY_OUT}/${APP_NAME}.te" 2>/dev/null || true
        git -C "${PROJECT_ROOT}" diff --no-index \
            "${POLICY_FC}" "${POLICY_OUT}/${APP_NAME}.fc" 2>/dev/null || true
    else
        diff -u "${POLICY_TE}" "${POLICY_OUT}/${APP_NAME}.te" 2>/dev/null || true
        diff -u "${POLICY_FC}" "${POLICY_OUT}/${APP_NAME}.fc" 2>/dev/null || true
    fi
}

promote_to_selinux() {
    load_policy_paths_from_manifest
    log_info "Promoting policy_out → ${POLICY_MODULE_DIR}/"
    cp "${POLICY_OUT}/${APP_NAME}.te" "${POLICY_TE}"
    cp "${POLICY_OUT}/${APP_NAME}.fc" "${POLICY_FC}"
    if [[ -f "${POLICY_OUT}/policy_version.txt" ]]; then
        cp "${POLICY_OUT}/policy_version.txt" "${POLICY_VERSION_FILE}"
    else
        match="$(policy_module_version_from_te "${POLICY_OUT}/${APP_NAME}.te" "${APP_NAME}")" || {
            log_error "promote_to_selinux: cannot extract SemVer from policy_module() in ${POLICY_OUT}/${APP_NAME}.te"
            exit 1
        }
        echo "${match}" > "${POLICY_VERSION_FILE}"
    fi
    log_info "Updated ${POLICY_TE}, ${POLICY_FC}, and ${POLICY_VERSION_FILE}"
}

verify_avc_coverage() {
    log_info "Verifying AVC log coverage in policy_out/${APP_NAME}.te..."
    python3 "${VERIFY_AVC}" \
        --avc-log "${AVC_LOG}" \
        --te "${POLICY_OUT}/${APP_NAME}.te" \
        --manifest "${MANIFEST}"
}

assemble_pr_body() {
    log_info "Assembling PR body..."
    local common_args=(
        --app-name "${APP_NAME}"
        --staging-host "${STAGING_HOST}"
        --test-suite "${TEST_SUITE}"
        --output "${POLICY_OUT}/pr_body.md"
    )
    if [[ "${ASSEMBLE_SKIP_POLICY_DIFF:-0}" == "1" ]]; then
        bash "${ASSEMBLE}" "${common_args[@]}" --skip-policy-diff
        return
    fi
    if ! bash "${ASSEMBLE}" "${common_args[@]}"; then
        log_warn "Policy access diff failed (sesearch) — PR body without delta section"
        bash "${ASSEMBLE}" "${common_args[@]}" --skip-policy-diff
    fi
}

open_pr() {
    if ! command -v gh >/dev/null 2>&1; then
        log_error "gh CLI not found; install GitHub CLI or open PR manually"
        return 1
    fi
    local branch="policy/${APP_NAME}-update"
    log_info "Creating branch ${branch}, committing, pushing, and opening PR..."
    git -C "${APP_ROOT}" checkout -b "${branch}" 2>/dev/null || \
        git -C "${APP_ROOT}" checkout "${branch}"
    git -C "${APP_ROOT}" add \
        "selinux/${APP_NAME}.te" \
        "selinux/${APP_NAME}.fc" \
        "selinux/myapp/policy_version.txt"
    if git -C "${APP_ROOT}" diff --cached --quiet; then
        log_error "Nothing to commit — run with --apply after generation"
        return 1
    fi
    git -C "${APP_ROOT}" commit -m "$(cat <<EOF
security(selinux): Update policy module for ${APP_NAME}

Generated via dev_generate_policy.sh
EOF
)"
    git -C "${APP_ROOT}" push -u origin "${branch}"
    (
        cd "${APP_ROOT}"
        gh pr create \
            --title "security(selinux): Update policy module for ${APP_NAME}" \
            --body-file "${POLICY_OUT}/pr_body.md" \
            --label security \
            --label selinux \
            --label pending-admin-review
    )
}

run_enforce_check() {
    local te_src fc_src pp_path
    te_src="${POLICY_OUT}/${APP_NAME}.te"
    fc_src="${POLICY_OUT}/${APP_NAME}.fc"

    pp_path="${POLICY_OUT}/${APP_NAME}.pp"
    log_info "Compiling candidate policy for enforce-check..."
    # shellcheck source=lib/compile_policy.sh
    source "${SCRIPT_DIR}/lib/compile_policy.sh"
    compile_policy_module "$(dirname "${te_src}")" "${APP_NAME}" "${pp_path}"

    if [[ "${EUID}" -ne 0 ]]; then
        log_error "enforce-check requires root on the SELinux host"
        return 1
    fi

    semodule -i "${pp_path}"
    semanage permissive -d "${DOMAIN}" 2>/dev/null || true
    if [[ -z "${PATHS_CSV:-}" || -z "${PRIMARY_SERVICE:-}" ]]; then
        log_error "enforce-check needs the manifest paths and primary unit"
        return 1
    fi
    local -a restore_paths=()
    local -a units=()
    IFS=',' read -r -a restore_paths <<< "${PATHS_CSV}"
    restorecon -Rv "${restore_paths[@]}" 2>/dev/null || true
    if [[ "${HAS_BACKEND:-0}" == "1" && -n "${BACKEND_SERVICE:-}" ]]; then
        units+=("${BACKEND_SERVICE}")
    fi
    units+=("${PRIMARY_SERVICE}")
    systemctl restart "${units[@]}"
    if bash "${SCRIPT_DIR}/wait_for_endpoints.sh" --host 127.0.0.1 --retries 10 --delay 2; then
        log_info "enforce-check passed under enforcing ${DOMAIN}"
        return 0
    fi

    log_error "enforce-check failed — recent AVCs:"
    bash "${SCRIPT_DIR}/monitor_avc.sh" --domain "${DOMAIN}" --manifest "${MANIFEST}" --since recent --max-avc -1 --show-lines 5 || true
    semanage permissive -a "${DOMAIN}" 2>/dev/null || true
    return 1
}

print_pr_steps() {
    local mod_dir_rel=""
    mod_dir_rel="$(python3 -c "
import sys, yaml
m = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
print(m.get('policy', {}).get('module_dir', 'selinux'))
" "${MANIFEST}" 2>/dev/null || echo "selinux")"
    cat <<EOF

--- Next steps (Git PR handoff) ---

1. Review assembled PR body:
   cat policy_out/pr_body.md

2. Validate locally (matches CI):
   sepac check ${APP_NAME}

3. Commit, push, and open PR:
   git checkout -b policy/${APP_NAME}-update
   git add ${mod_dir_rel}/${APP_NAME}.te ${mod_dir_rel}/${APP_NAME}.fc ${mod_dir_rel}/policy_version.txt
   git commit -m "security(selinux): Update policy module for ${APP_NAME}"
   git push -u origin policy/${APP_NAME}-update
   gh pr create \\
     --title "security(selinux): Update policy module for ${APP_NAME}" \\
     --body-file policy_out/pr_body.md \\
     --label security --label selinux --label pending-admin-review

Admin team: review PR table + summary; merge triggers staging canary; enforce via deploy workflow.

EOF
}

main() {
    if [[ "${TUNE_REPORT}" -eq 1 ]]; then
        run_tune_report
        restore_repo_ownership
        return 0
    fi

    sync_identity_from_manifest
    check_vendor_policy
    require_existing_policy

    # shellcheck source=lib/compile_policy.sh
    source "${SCRIPT_DIR}/lib/compile_policy.sh"

    if [[ "${SKIP_EXPORT}" -eq 0 ]]; then
        export_avcs
    else
        [[ -s "${AVC_LOG}" ]] || { log_error "--skip-export but ${AVC_LOG} is empty"; exit 1; }
    fi

    generate_policy
    show_diff
    verify_avc_coverage || exit 1

    if [[ "${ENFORCE_CHECK}" -eq 1 ]]; then
        run_enforce_check || exit 1
    fi

    if [[ "${APPLY}" -eq 1 ]]; then
        promote_to_selinux
    else
        log_warn "Generated files in policy_out/ only. Re-run with --apply to copy into selinux/"
    fi

    assemble_pr_body

    if [[ "${OPEN_PR}" -eq 1 ]]; then
        open_pr
    else
        print_pr_steps
    fi

    restore_repo_ownership
}

main "$@"
