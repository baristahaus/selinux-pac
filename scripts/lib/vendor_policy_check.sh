#!/usr/bin/env bash
#
# vendor_policy_check.sh — Refuse to generate a module that duplicates
# vendor or base policy. RHEL 9 base module names (c9s): apache, bind.
# There is no policy/modules/contrib/jboss.te on c9s. EAP ships its own package.
#
# JWS and EAP ship SELinux in a separate RPM that is not installed by default
# (jws6-tomcat-selinux, eap7-selinux / eap8-selinux). Until that RPM is
# installed the process runs unconfined_service_t — "no module loaded" does not
# mean "no policy exists". unconfined_java_t is not declared on RHEL 9.
# Distro Tomcat is tomcat_t and unconfined.
#
# Source from other scripts:
#   source "${SCRIPT_DIR}/lib/vendor_policy_check.sh"
#   vendor_policy_preflight --app-name NAME [--unit UNIT] [--pid PID] [--force "reason"] [--report]
#
# When executed: same argv, exit status of the check.
#
# Mock env (smoke tests only; no live tools):
#   VENDOR_CHECK_MOCK=1
#   VENDOR_CHECK_SEMODULE_L   semodule -l text
#   VENDOR_CHECK_RPM_QA       rpm -qa text (vendor selinux NEVRAs)
#   VENDOR_CHECK_DNF_AVAILABLE  newline-separated available package names
#   VENDOR_CHECK_PS_EZ        ps -eZ / ps -o label=,comm= text
#   VENDOR_CHECK_DOMAIN_UNCONFINED  1 = treat resolved domain as files_unconfined_type
#
set -euo pipefail

_vpc_info() {
    if declare -F log_info >/dev/null 2>&1; then
        log_info "$@"
    else
        echo "[INFO] $*"
    fi
}

_vpc_warn() {
    if declare -F log_warn >/dev/null 2>&1; then
        log_warn "$@"
    else
        echo "[WARN] $*"
    fi
}

_vpc_error() {
    if declare -F log_error >/dev/null 2>&1; then
        log_error "$@"
    else
        echo "[ERROR] $*" >&2
    fi
}

vendor_policy_classify() {
    local blob
    blob="$(printf '%s' "$*" | tr '[:upper:]' '[:lower:]')"
    case "${blob}" in
        *tomcat*|*jws*|*catalina*) echo tomcat ;;
        *jboss*|*eap*|*wildfly*) echo eap ;;
        *httpd*|*apache*) echo httpd ;;
        *named*|*bind9*|*bind*) echo named ;;
        *postgres*) echo postgresql ;;
        *python*|*gunicorn*|*uwsgi*) echo python ;;
        *) echo none ;;
    esac
}

vendor_pkgs_for_class() {
    case "$1" in
        tomcat)
            printf '%s\n' jws5-tomcat-selinux jws6-tomcat-selinux tomcat-selinux
            ;;
        eap)
            printf '%s\n' eap7-selinux eap8-selinux
            ;;
        postgresql)
            printf '%s\n' postgresql-selinux
            ;;
        *)
            ;;
    esac
}

vendor_module_grep_for_class() {
    case "$1" in
        tomcat) echo '^(tomcat|jws[0-9]*_tomcat|jws[0-9]+)$' ;;
        # jboss is not a base-policy module. Keep the name for an EAP package that loads one.
        eap) echo '^(jboss|eap[0-9]+|eap|wildfly)$' ;;
        # policy_module(apache) in policy/modules/contrib/apache.te; the domain is httpd_t.
        httpd) echo '^apache$' ;;
        # policy_module(bind) in policy/modules/contrib/bind.te; the domain is named_t.
        named) echo '^bind$' ;;
        postgresql) echo '^(postgresql|postgres)$' ;;
        python) echo '^(python|python3)$' ;;
        *) echo '^$' ;;
    esac
}

vendor_check_tools_missing() {
    if [[ "${VENDOR_CHECK_MOCK:-}" == "1" ]]; then
        return 1
    fi
    if command -v semodule >/dev/null 2>&1; then
        return 1
    fi
    if command -v rpm >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# semodule -l needs the module store; unprivileged users get Permission denied.
# Commands here are used in `cmd || true` / `if cmd` contexts so set -e is safe.
vendor_check_run_privileged() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
        return $?
    fi
    if command -v sudo >/dev/null 2>&1 && sudo -n "$@"; then
        return 0
    fi
    "$@"
    return $?
}

vendor_check_semodule_l() {
    if [[ "${VENDOR_CHECK_MOCK:-}" == "1" ]]; then
        printf '%s\n' "${VENDOR_CHECK_SEMODULE_L:-}"
        return 0
    fi
    if command -v semodule >/dev/null 2>&1; then
        vendor_check_run_privileged semodule -l 2>/dev/null || true
    fi
}

# True when the type is files_unconfined_type / unconfined_domain_type.
# RHEL distro tomcat_t is that way even with module "tomcat" loaded.
vendor_domain_is_effectively_unconfined() {
    local domain="${1:-}" out=""
    [[ -n "${domain}" ]] || return 1
    if [[ "${VENDOR_CHECK_MOCK:-}" == "1" ]]; then
        [[ "${VENDOR_CHECK_DOMAIN_UNCONFINED:-}" == "1" ]]
        return $?
    fi
    if ! command -v seinfo >/dev/null 2>&1; then
        return 1
    fi
    out="$(seinfo -t "${domain}" -x 2>/dev/null || true)"
    if [[ -z "${out}" ]]; then
        out="$(vendor_check_run_privileged seinfo -t "${domain}" -x 2>/dev/null || true)"
    fi
    printf '%s\n' "${out}" | grep -Eq 'files_unconfined_type|unconfined_domain_type'
}

vendor_domain_confined_flag() {
    local domain="${1:-}"
    if [[ -z "${domain}" ]]; then
        echo unknown
        return 0
    fi
    if vendor_domain_is_effectively_unconfined "${domain}"; then
        echo no
    else
        echo yes
    fi
}

vendor_check_rpm_qa() {
    if [[ "${VENDOR_CHECK_MOCK:-}" == "1" ]]; then
        printf '%s\n' "${VENDOR_CHECK_RPM_QA:-}"
        return 0
    fi
    if ! command -v rpm >/dev/null 2>&1; then
        return 0
    fi
    # Local NEVRA query only — no network. Globs keep this cheaper than rpm -qa.
    rpm -qa \
        'jws*-tomcat-selinux' \
        'eap*-selinux' \
        'tomcat-selinux' \
        'postgresql-selinux' \
        'selinux-policy-targeted' \
        2>/dev/null || true
}

vendor_rpm_has_pkg() {
    local pkg="$1"
    local qa="$2"
    printf '%s\n' "${qa}" | grep -E "^${pkg}(-|$)" >/dev/null 2>&1
}

vendor_check_pkg_available() {
    local pkg="$1"
    local out=""
    if [[ "${VENDOR_CHECK_MOCK:-}" == "1" ]]; then
        if printf '%s\n' "${VENDOR_CHECK_DNF_AVAILABLE:-}" | grep -E "^${pkg}(\.|$)" >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    if command -v dnf >/dev/null 2>&1; then
        out="$(dnf --cacheonly --quiet list available "${pkg}" 2>/dev/null || true)"
        if [[ "${out}" == *"${pkg}"* ]]; then
            return 0
        fi
        return 1
    fi
    if command -v yum >/dev/null 2>&1; then
        out="$(yum -C --quiet list available "${pkg}" 2>/dev/null || true)"
        if [[ "${out}" == *"${pkg}"* ]]; then
            return 0
        fi
        return 1
    fi
    return 1
}

vendor_check_ps_context() {
    local pid="${1:-}"
    local unit="${2:-}"
    local mpid=""

    if [[ "${VENDOR_CHECK_MOCK:-}" == "1" ]]; then
        printf '%s\n' "${VENDOR_CHECK_PS_EZ:-}"
        return 0
    fi

    if [[ -n "${pid}" ]] && command -v ps >/dev/null 2>&1; then
        ps -o label=,comm= -p "${pid}" 2>/dev/null || true
        return 0
    fi
    if [[ -n "${unit}" ]] && command -v systemctl >/dev/null 2>&1 && command -v ps >/dev/null 2>&1; then
        mpid="$(systemctl show -p MainPID --value "${unit}" 2>/dev/null || true)"
        if [[ -n "${mpid}" && "${mpid}" != "0" ]]; then
            ps -o label=,comm= -p "${mpid}" 2>/dev/null || true
        fi
    fi
}

vendor_match_loaded_modules() {
    local class="$1"
    local listing="$2"
    local pattern names
    pattern="$(vendor_module_grep_for_class "${class}")"
    [[ -n "${listing}" ]] || return 0
    names="$(printf '%s\n' "${listing}" | awk '{print $1}')"
    printf '%s\n' "${names}" | grep -E "${pattern}" || true
}

_vpc_domain() {
    local class="$1"
    local module="$2"
    case "${module}" in
        jws6_tomcat) echo jws6_tomcat_t; return ;;
        tomcat) echo tomcat_t; return ;;
        httpd|apache) echo httpd_t; return ;;
        named|bind) echo named_t; return ;;
        postgresql) echo postgresql_t; return ;;
        jboss|eap7|eap8) echo jboss_t; return ;;
    esac
    case "${class}" in
        tomcat) echo tomcat_t ;;
        eap) echo jboss_t ;;
        httpd) echo httpd_t ;;
        named) echo named_t ;;
        postgresql) echo postgresql_t ;;
        *)
            if [[ -n "${module}" ]]; then
                echo "${module}_t"
            else
                echo ""
            fi
            ;;
    esac
}

_vpc_fc_type() {
    local domain="$1"
    case "${domain}" in
        jws6_tomcat_t) echo jws6_tomcat_var_lib_t ;;
        tomcat_t) echo tomcat_var_lib_t ;;
        httpd_t) echo httpd_sys_content_t ;;
        postgresql_t) echo postgresql_db_t ;;
        named_t) echo named_zone_t ;;
        jboss_t) echo jboss_var_lib_t ;;
        "") echo "" ;;
        *) echo "${domain%_t}_var_lib_t" ;;
    esac
}

_vpc_port_type() {
    local class="$1"
    local manifest="${2:-}"
    if [[ -n "${manifest}" && -f "${manifest}" ]]; then
        local mpt
        mpt="$(python3 -c "
import yaml, sys
m = yaml.safe_load(open(sys.argv[1]))
ports = m.get('selinux_ports') or []
types = sorted(set(p['type'] for p in ports if p.get('type')))
print(','.join(types) if types else '')
" "${manifest}" 2>/dev/null || true)"
        if [[ -n "${mpt}" ]]; then
            echo "${mpt}"
            return 0
        fi
    fi
    case "${class}" in
        postgresql) echo postgresql_port_t ;;
        named) echo dns_port_t ;;
        *) echo "" ;;
    esac
}

_vpc_emit_triage() {
    local situation="$1" app="$2" module="$3" pkg="$4" cls="$5" action="$6" domain="${7:-}" manifest="${8:-}"
    local fc_type port_type confined
    if [[ -z "${domain}" ]]; then
        domain="$(_vpc_domain "${cls}" "${module}")"
    fi
    fc_type="$(_vpc_fc_type "${domain}")"
    port_type="$(_vpc_port_type "${cls}" "${manifest}")"
    confined="$(vendor_domain_confined_flag "${domain}")"
    local triage_line="TRIAGE situation=${situation} app=${app} module=${module} package=${pkg} class=${cls} action=${action} domain=${domain} fc_type=${fc_type}"
    [[ -n "${port_type}" ]] && triage_line+=" port_type=${port_type}"
    triage_line+=" domain_confined=${confined}"
    _vpc_info "${triage_line}"
    if [[ "${confined}" == "no" ]]; then
        _vpc_warn "domain ${domain} is files_unconfined_type / unconfined_domain_type — a loaded vendor module does not mean file or port denials will fire"
    fi
}

_vpc_write_override() {
    local situation="$1" module="$2" pkg="$3" cls="$4" reason="$5"
    [[ -n "${VENDOR_OVERRIDE_OUT:-}" ]] || return 0
    mkdir -p "$(dirname "${VENDOR_OVERRIDE_OUT}")"
    FORCE_REASON="${reason}" python3 - "${situation}" "${module}" "${pkg}" "${cls}" <<'PY'
import json
import os
import sys

situation, module, pkg, cls = sys.argv[1:5]
path = os.environ["VENDOR_OVERRIDE_OUT"]
payload = {
    "reason": os.environ.get("FORCE_REASON", ""),
    "situation": situation,
    "module": module,
    "package": pkg,
    "class": cls,
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

_vpc_refuse_loaded() {
    local module="$1"
    local class="$2"
    _vpc_error "vendor policy already loaded: module '${module}' covers this app (class ${class})."
    _vpc_error "Tune booleans and file contexts for the vendor domain; do not generate a duplicate module."
    _vpc_error "Re-run with --tune-report for concrete host commands (fcontext, setsebool, semanage port). That mode does not write a policy module."
    _vpc_error "Escape hatch: re-run with --force \"reason\" if this app genuinely differs from the vendor policy."
    return 1
}

_vpc_refuse_loaded_unconfined() {
    local module="$1"
    local domain="$2"
    _vpc_error "vendor module '${module}' is loaded, but ${domain} is unconfined (situation=loaded_unconfined, action=confine)."
    _vpc_error "Next step: install the vendor's confining package, or generate with --force \"reason\"."
    _vpc_error "Do not tune file or port denials this domain will not produce."
    return 1
}

_vpc_refuse_package() {
    local pkg="$1"
    local detail="$2"
    _vpc_error "vendor SELinux package ${detail}: ${pkg}"
    _vpc_error "Install or enable the vendor package; do not generate a duplicate module."
    _vpc_error "Until that RPM is installed, Tomcat/EAP on RHEL 9 runs as unconfined_service_t — that is not confinement. Distro Tomcat is tomcat_t and unconfined."
    _vpc_error "Escape hatch: re-run with --force \"reason\" if this app genuinely differs from the vendor policy."
    return 1
}

_vpc_refuse_unconfined() {
    local domain="$1"
    _vpc_error "process domain is ${domain} (looks like Tomcat/EAP); vendor policy exists but is not enabled."
    _vpc_error "Install jws6-tomcat-selinux or eap7-selinux/eap8-selinux, then confirm the process runs in jws*_tomcat_t / jboss_t."
    _vpc_error "Do not generate a duplicate module."
    _vpc_error "Escape hatch: re-run with --force \"reason\" if this app genuinely differs from the vendor policy."
    return 1
}

_vpc_refuse_base() {
    local class="$1"
    _vpc_error "vendor/base policy already covers this app class (${class} via selinux-policy-targeted)."
    _vpc_error "Tune booleans and file contexts for the vendor domain; do not generate a duplicate module."
    _vpc_error "Re-run with --tune-report for concrete host commands (fcontext, setsebool, semanage port). That mode does not write a policy module."
    _vpc_error "Escape hatch: re-run with --force \"reason\" if this app genuinely differs from the vendor policy."
    return 1
}

vendor_policy_preflight() {
    local app_name="" unit="" pid="" force=0 report=0 force_reason=""
    local class="none" listing="" rpm_qa="" loaded="" pkg="" installed="" available=""
    local ctx="" domain="" situation="none" action="generate" module="" package=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --app-name)
                app_name="$2"
                shift 2
                ;;
            --unit)
                unit="$2"
                shift 2
                ;;
            --pid)
                pid="$2"
                shift 2
                ;;
            --force)
                if [[ $# -lt 2 || -z "${2:-}" || "${2}" == -* ]]; then
                    _vpc_error "bare --force is rejected. Pass --force \"reason\" so reviewers can see why a vendor policy was overridden."
                    return 2
                fi
                force=1
                force_reason="$2"
                shift 2
                ;;
            --report)
                report=1
                shift
                ;;
            *)
                _vpc_error "vendor_policy_check: unknown option $1"
                return 1
                ;;
        esac
    done

    if [[ -z "${app_name}" ]]; then
        _vpc_error "vendor_policy_check: --app-name is required"
        return 1
    fi

    if vendor_check_tools_missing; then
        _vpc_warn "vendor policy check skipped: semodule and rpm not found; continuing"
        _vpc_emit_triage "skipped" "${app_name}" "" "" "none" "skip"
        return 0
    fi

    class="$(vendor_policy_classify "${app_name} ${unit}")"

    if [[ "${class}" == "none" ]]; then
        situation="none"
        action="generate"
    else
        listing="$(vendor_check_semodule_l)"
        loaded="$(vendor_match_loaded_modules "${class}" "${listing}")"
        if [[ -n "${loaded}" ]]; then
            loaded="$(printf '%s\n' "${loaded}" | head -n 1)"
            module="${loaded}"
            domain="$(_vpc_domain "${class}" "${module}")"
            if [[ "$(vendor_domain_confined_flag "${domain}")" == "no" ]]; then
                situation="loaded_unconfined"
                action="confine"
            else
                situation="loaded"
                action="tune"
            fi
        else
            rpm_qa="$(vendor_check_rpm_qa)"
            while IFS= read -r pkg; do
                [[ -n "${pkg}" ]] || continue
                if vendor_rpm_has_pkg "${pkg}" "${rpm_qa}"; then
                    installed="${pkg}"
                    break
                fi
            done < <(vendor_pkgs_for_class "${class}")

            if [[ -n "${installed}" ]]; then
                situation="package_installed"
                action="enable"
                package="${installed}"
            else
                while IFS= read -r pkg; do
                    [[ -n "${pkg}" ]] || continue
                    if vendor_check_pkg_available "${pkg}"; then
                        available="${pkg}"
                        break
                    fi
                done < <(vendor_pkgs_for_class "${class}")

                if [[ -n "${available}" ]]; then
                    situation="package_available"
                    action="install"
                    package="${available}"
                elif [[ "${class}" == "tomcat" || "${class}" == "eap" ]]; then
                    ctx="$(vendor_check_ps_context "${pid}" "${unit}")"
                    if printf '%s\n' "${ctx}" | grep -Eq 'unconfined_java_t|unconfined_service_t'; then
                        domain="$(printf '%s\n' "${ctx}" | grep -Eo 'unconfined_java_t|unconfined_service_t' | head -n 1 || true)"
                        situation="unconfined"
                        action="install"
                    elif [[ "${class}" == "httpd" || "${class}" == "named" || "${class}" == "postgresql" ]] \
                        && vendor_rpm_has_pkg "selinux-policy-targeted" "${rpm_qa}"; then
                        situation="base_policy"
                        action="tune"
                    else
                        situation="none"
                        action="generate"
                    fi
                elif [[ "${class}" == "httpd" || "${class}" == "named" || "${class}" == "postgresql" ]]; then
                    if vendor_rpm_has_pkg "selinux-policy-targeted" "${rpm_qa}"; then
                        situation="base_policy"
                        action="tune"
                    else
                        situation="none"
                        action="generate"
                    fi
                else
                    situation="none"
                    action="generate"
                fi
            fi
        fi
    fi

    local _vpc_manifest="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}/config/${app_name}.manifest.yml"
    [[ -f "${_vpc_manifest}" ]] || _vpc_manifest=""
    _vpc_emit_triage "${situation}" "${app_name}" "${module}" "${package}" "${class}" "${action}" "${domain}" "${_vpc_manifest}"

    if [[ "${force}" -eq 1 ]]; then
        if [[ "${situation}" == "none" || "${situation}" == "skipped" ]]; then
            _vpc_warn "vendor policy check: --force given but nothing to override (situation=${situation})"
            return 0
        fi
        _vpc_warn "vendor policy check bypassed (--force): ${force_reason}"
        echo "FORCE_REASON ${force_reason}"
        _vpc_write_override "${situation}" "${module}" "${package}" "${class}" "${force_reason}"
        return 0
    fi

    if [[ "${report}" -eq 1 ]]; then
        return 0
    fi

    case "${situation}" in
        none)
            _vpc_info "vendor policy check: no vendor or base module covers '${app_name}'; continuing"
            return 0
            ;;
        loaded)
            _vpc_refuse_loaded "${module}" "${class}"
            return 1
            ;;
        loaded_unconfined)
            _vpc_refuse_loaded_unconfined "${module}" "${domain}"
            return 1
            ;;
        package_installed)
            _vpc_refuse_package "${package}" "installed but module not loaded"
            return 1
            ;;
        package_available)
            _vpc_refuse_package "${package}" "available but not installed"
            return 1
            ;;
        unconfined)
            _vpc_refuse_unconfined "${domain}"
            return 1
            ;;
        base_policy)
            _vpc_refuse_base "${class}"
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    vendor_policy_preflight "$@"
    exit $?
fi
