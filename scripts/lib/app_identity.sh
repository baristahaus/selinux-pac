#!/usr/bin/env bash
#
# app_identity.sh — Resolve app identity from --app NAME or --manifest PATH.
#
# Source from scripts after parsing their own flags:
#   source "${SCRIPT_DIR}/lib/app_identity.sh"
#   resolve_app_identity --app shopapi          # loads config/shopapi.manifest.yml
#   resolve_app_identity --manifest /path/to.yml
#
# After resolve_app_identity, these variables are set:
#   APP_NAME, APP_DOMAIN, PRIMARY_DOMAIN, MODULE_NAME, MODULE_DIR,
#   POLICY_TE, POLICY_FC, POLICY_PP, POLICY_VERSION_FILE,
#   DOMAINS_CSV, SELINUX_PORTS_CSV, PATHS_CSV, SOAK_IGNORE_CSV,
#   PRIMARY_SERVICE, HTTP_HOST, HTTP_PORT, ENDPOINT_PATHS,
#   BACKEND_DOMAIN, BACKEND_SERVICE, HAS_BACKEND, etc.
#
# Errors:
#   Neither --app nor --manifest given → "--app NAME or --manifest PATH is required"
#   Manifest file missing → "No manifest for APP: config/APP.manifest.yml"
#
set -euo pipefail

_APP_IDENTITY_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_APP_IDENTITY_PROJECT_ROOT="$(cd "${_APP_IDENTITY_LIB}/../.." && pwd)"

# Guard: fail loudly if any old identity variable is set.
_guard_old_identity_vars() {
    local var msg
    for var in POLICY_MODULE SELINUX_DOMAIN POLICY_APP SELINUX_APP_DOMAIN SELINUX_BACKEND_DOMAIN APP_MANIFEST; do
        if [[ -n "${!var:-}" ]]; then
            case "${var}" in
                POLICY_MODULE)    msg="POLICY_MODULE is no longer read. Pass --app ${!var}." ;;
                SELINUX_DOMAIN)   msg="SELINUX_DOMAIN is no longer read. Pass --app NAME (domain comes from the manifest)." ;;
                POLICY_APP)       msg="POLICY_APP is no longer read. Pass --app ${!var}." ;;
                SELINUX_APP_DOMAIN) msg="SELINUX_APP_DOMAIN is no longer read. Domain comes from the manifest." ;;
                SELINUX_BACKEND_DOMAIN) msg="SELINUX_BACKEND_DOMAIN is no longer read. Domain comes from the manifest." ;;
                APP_MANIFEST)     msg="APP_MANIFEST is no longer read. Pass --manifest ${!var}." ;;
            esac
            echo "[ERROR] ${msg}" >&2
            return 1
        fi
    done
    return 0
}

resolve_app_identity() {
    local app_name="" manifest_path="" project_root="${_APP_IDENTITY_PROJECT_ROOT}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --app|--app-name)
                app_name="$2"
                shift 2
                ;;
            --manifest)
                manifest_path="$2"
                shift 2
                ;;
            --project-root)
                project_root="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    _guard_old_identity_vars

    if [[ -z "${app_name}" && -z "${manifest_path}" ]]; then
        echo "[ERROR] --app NAME or --manifest PATH is required" >&2
        return 1
    fi

    if [[ -z "${manifest_path}" ]]; then
        manifest_path="${project_root}/config/${app_name}.manifest.yml"
    fi

    if [[ ! -f "${manifest_path}" ]]; then
        if [[ -n "${app_name}" ]]; then
            echo "[ERROR] No manifest for ${app_name}: config/${app_name}.manifest.yml" >&2
        else
            echo "[ERROR] Manifest not found: ${manifest_path}" >&2
        fi
        return 1
    fi

    # shellcheck disable=SC1090
    eval "$(python3 "${_APP_IDENTITY_LIB}/app_manifest.py" shell-export "${manifest_path}")"
}
