#!/usr/bin/env bash
#
# demo_bootstrap.sh — Idempotent three-app estate (App A, App B, shopapi).
#
# Run on RHEL / CentOS Stream as root. Re-run after interrupt is safe.
# JWS repo missing → upstream Tomcat + tomcat_t (same narrative).
#
# Usage:
#   sudo bash lab/demo_bootstrap.sh
#   sudo bash lab/demo_bootstrap.sh --shopapi-only --no-seed --unconfined
#   make demo-bootstrap
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/demo_estate.sh
source "${SCRIPT_DIR}/lib/demo_estate.sh"

SHOPAPI_ONLY=0
LOAD_SEED=1
DEMO_SHOPAPI_CONFINED="${DEMO_SHOPAPI_CONFINED:-1}"

log() { echo "[bootstrap] $*"; }
die() { echo "[bootstrap] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --shopapi-only) SHOPAPI_ONLY=1; shift ;;
        --no-seed) LOAD_SEED=0; shift ;;
        --unconfined) DEMO_SHOPAPI_CONFINED=0; shift ;;
        -h|--help)
            echo "Usage: $(basename "$0") [--shopapi-only] [--no-seed] [--unconfined]"
            exit 0
            ;;
        *) die "unknown option $1" ;;
    esac
done
export DEMO_SHOPAPI_CONFINED

require_linux_root() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "make demo-bootstrap must run on RHEL or CentOS Stream (dnf, systemd, SELinux)."
        echo "On this laptop: bash lab/demo_present.sh --dry-run --profile customer"
        exit 2
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        die "run as root (sudo bash lab/demo_bootstrap.sh)"
    fi
}

# Stamp only after the step returns 0. A Ctrl-C mid-dnf leaves no stamp; re-run
# picks up. Steps themselves are idempotent (dnf, cp, useradd).
run_step() {
    local name="$1"
    shift
    if demo_stamp_exists "${name}"; then
        log "skip ${name} (stamp present)"
        return 0
    fi
    log "step ${name}"
    "$@"
    demo_stamp_done "${name}"
}

detect_and_persist_variant() {
    if [[ -f "${DEMO_VARIANT_FILE}" ]]; then
        log "variant already $(demo_variant)"
        return 0
    fi
    if demo_jws_repo_reachable; then
        log "JWS repository reachable — installing JWS (domain jws6_tomcat_t)"
        demo_write_variant jws
    else
        log "JWS repository NOT reachable — falling back to upstream Tomcat from distro repos"
        log "Vendor domain will be tomcat_t, not jws6_tomcat_t. Distro tomcat_t is unconfined_domain_type — Act 1/2 denials will not fire. JWS is the confined vendor domain. Act 3 shopapi is still the generate path."
        demo_write_variant tomcat
    fi
}

install_tomcat_stack() {
    local variant
    variant="$(demo_variant)"
    dnf install -y policycoreutils policycoreutils-python-utils setools-console \
        audit python3 curl
    dnf install -y java-17-openjdk-headless \
        || dnf install -y java-17-openjdk \
        || dnf install -y java-11-openjdk-headless
    if [[ "${variant}" == "jws" ]]; then
        if ! dnf install -y jws6-tomcat jws6-tomcat-selinux; then
            log "jws6 packages failed — falling back to distro Tomcat (tomcat_t)"
            demo_write_variant tomcat
            variant=tomcat
        fi
    fi
    if [[ "${variant}" == "tomcat" ]]; then
        dnf install -y tomcat tomcat-webapps tomcat-admin-webapps || dnf install -y tomcat
        dnf install -y tomcat-selinux 2>/dev/null || true
        log "Using distro Tomcat. Process domain: tomcat_t (not jws6_tomcat_t)."
    else
        log "Using JWS. Process domain: jws6_tomcat_t."
    fi
}

install_build_tools() {
    dnf install -y maven java-17-openjdk-devel python3 python3-pyyaml selinux-policy-devel \
        || dnf install -y maven java-17-openjdk-devel python3 \
        || dnf install -y maven python3
}

install_app_a_forbidden_file() {
    mkdir -p "${DEMO_STATE_DIR}"
    echo "out-of-scope" >"${APP_A_FORBIDDEN_PATH}"
    chmod 0644 "${APP_A_FORBIDDEN_PATH}"
    # DAC-readable, SELinux-denied for tomcat_t / jws6_tomcat_t.
    chcon -t user_home_t "${APP_A_FORBIDDEN_PATH}" 2>/dev/null \
        || chcon -t admin_home_t "${APP_A_FORBIDDEN_PATH}" 2>/dev/null \
        || log "WARN: could not chcon ${APP_A_FORBIDDEN_PATH}; Act 1 may lack an AVC"
}

deploy_app_a() {
    local webapps dest
    webapps="$(demo_tomcat_webapps)"
    mkdir -p "${webapps}"
    dest="${webapps}/standard"
    rm -rf "${dest}"
    mkdir -p "${dest}"
    cp -a "${PROJECT_ROOT}/lab/apps/tomcat/app-a/." "${dest}/"
    restorecon -Rv "${dest}" 2>/dev/null || true
    install_app_a_forbidden_file
    log "App A exploded at ${dest} (port ${APP_A_PORT})"
}

configure_app_b() {
    mkdir -p "${APP_B_DATA}"
    cp -a "${PROJECT_ROOT}/lab/apps/tomcat/app-b/." "${APP_B_DATA}/"
    echo "inherited-secret" >"${APP_B_DATA}/secret.dat"
    # Wrong label on purpose. Do NOT restorecon. Act 2 retunes with semanage fcontext.
    chcon -R -t user_home_t "${APP_B_DATA}" 2>/dev/null \
        || log "WARN: chcon user_home_t on ${APP_B_DATA} failed — Act 2 label probe may be silent"
    local ctxdir xml
    ctxdir="$(demo_tomcat_catalina_localhost)"
    mkdir -p "${ctxdir}"
    cp "${PROJECT_ROOT}/lab/apps/tomcat/inherited.xml" "${ctxdir}/inherited.xml"
    xml="$(demo_tomcat_server_xml)"
    APP_B_PORT="${APP_B_PORT}" python3 "${PROJECT_ROOT}/lab/apps/tomcat/insert_connector.py" "${xml}"
    demo_write_tomcat_dropin "${PROJECT_ROOT}"
    log "App B data ${APP_B_DATA} connector :${APP_B_PORT} (labels unrestored)"
}

deploy_shopapi() {
    local install_root var_dir log_dir runtime_dir port unit domain
    local parsed
    parsed="$(demo_write_shopapi_runtime_files "${PROJECT_ROOT}")"
    mapfile -t lines <<<"${parsed}"
    install_root="${lines[0]}"
    var_dir="${lines[1]}"
    log_dir="${lines[2]}"
    runtime_dir="${lines[3]}"
    port="${lines[4]}"
    unit="${lines[5]}"
    domain="${lines[6]}"
    [[ -n "${install_root}" && -n "${unit}" ]] || die "could not parse shopapi manifest paths"

    getent group shopapi >/dev/null || groupadd --system shopapi
    getent passwd shopapi >/dev/null || useradd --system --gid shopapi --home-dir "${install_root}" --shell /sbin/nologin shopapi
    mkdir -p "${install_root}" "${var_dir}" "${log_dir}" "${runtime_dir}" /var/spool/shopapi
    if [[ -f "${PROJECT_ROOT}/lab/apps/shopapi/target/shopapi.jar" ]]; then
        log "using prebuilt ${PROJECT_ROOT}/lab/apps/shopapi/target/shopapi.jar"
    else
        (cd "${PROJECT_ROOT}/lab/apps/shopapi" && mvn -q -DskipTests package)
    fi
    cp -f "${PROJECT_ROOT}/lab/apps/shopapi/target/shopapi.jar" "${install_root}/shopapi.jar"
    chown -R shopapi:shopapi "${install_root}" "${var_dir}" "${log_dir}" /var/spool/shopapi
    log "shopapi jar at ${install_root}/shopapi.jar port ${port} domain ${domain} unit ${unit}"
}

load_shopapi_seed() {
    local pp parsed install_root var_dir log_dir runtime_dir
    parsed="$(python3 - "${PROJECT_ROOT}/config/shopapi.manifest.yml" <<'PY'
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parents[1] / "scripts" / "lib"))
from app_manifest import load_manifest
m = load_manifest(pathlib.Path(sys.argv[1]))
print(m["paths"]["install_root"])
print(m["paths"]["var_dir"])
print(m["paths"]["log_dir"])
print(m["paths"]["runtime_dir"])
PY
)"
    mapfile -t lines <<<"${parsed}"
    install_root="${lines[0]}"
    var_dir="${lines[1]}"
    log_dir="${lines[2]}"
    runtime_dir="${lines[3]}"

    if [[ -f /usr/share/selinux/devel/Makefile ]]; then
        bash "${PROJECT_ROOT}/scripts/compile_and_validate.sh" "${PROJECT_ROOT}/selinux/shopapi" --app shopapi
        pp="${PROJECT_ROOT}/selinux/shopapi/shopapi.pp"
        if [[ -f "${pp}" ]]; then
            semodule -i "${pp}"
        fi
    else
        log "selinux-policy-devel missing — skip compile; load a prebuilt .pp if present"
        pp="${PROJECT_ROOT}/selinux/shopapi/shopapi.pp"
        [[ -f "${pp}" ]] && semodule -i "${pp}" || true
    fi
    restorecon -Rv "${install_root}" "${var_dir}" "${log_dir}" "${runtime_dir}" 2>/dev/null || true
    demo_register_shopapi_port "$(demo_manifest_http_port "${PROJECT_ROOT}/config/shopapi.manifest.yml")"
    # Permissive domain so Act 3 can collect observed AVCs. Do not guess allows here.
    semanage permissive -a shopapi_t 2>/dev/null || true
}

start_services() {
    systemctl daemon-reload
    if [[ "${SHOPAPI_ONLY}" -eq 0 ]]; then
        local svc
        svc="$(demo_tomcat_service)"
        systemctl enable --now "${svc}"
        systemctl restart "${svc}" || true
    fi
    # Reset restarts shopapi before this module exists, so that process is
    # unconfined_service_t. enable --now does not recycle an active unit.
    systemctl enable shopapi.service
    systemctl restart shopapi.service
}

wait_shopapi() {
    local port i
    port="$(demo_manifest_http_port "${PROJECT_ROOT}/config/shopapi.manifest.yml")"
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
            log "shopapi responding on :${port}"
            return 0
        fi
        sleep 2
    done
    die "shopapi did not respond on :${port}. Check shopapi.service and journalctl."
}

verify_shopapi_label() {
    if [[ "${LOAD_SEED}" -eq 0 ]]; then
        return 0
    fi
    local pid label wrapper
    pid="$(systemctl show -p MainPID --value shopapi.service 2>/dev/null || true)"
    if [[ -z "${pid}" || "${pid}" == "0" ]]; then
        log "WARN: shopapi.service MainPID not available; skipping label check"
        return 0
    fi
    label="$(ps -o label= -p "${pid}" 2>/dev/null || true)"
    if [[ "${label}" != *":shopapi_t:"* ]]; then
        die "shopapi MainPID ${pid} label is '${label}', expected :shopapi_t:. The seed module may not be loaded."
    fi
    log "shopapi MainPID ${pid} label: ${label}"
    wrapper="$(readlink -f /proc/"${pid}"/exe 2>/dev/null || true)"
    if [[ -n "${wrapper}" ]]; then
        ls -Z "$(dirname "${wrapper}")" 2>/dev/null || true
    fi
}

wait_app_a() {
    local i
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${APP_A_PORT}/standard/" >/dev/null 2>&1 \
            || curl -sf "http://127.0.0.1:${APP_A_PORT}/standard/index.jsp" >/dev/null 2>&1; then
            log "App A responding on :${APP_A_PORT}"
            return 0
        fi
        sleep 2
    done
    die "App A did not respond on :${APP_A_PORT}. Check $(demo_tomcat_service) and journalctl."
}

main() {
    require_linux_root
    mkdir -p "${DEMO_STATE_DIR}" "${DEMO_STAMP_DIR}"
    if [[ "${SHOPAPI_ONLY}" -eq 1 ]]; then
        run_step install_build install_build_tools
        run_step deploy_shopapi deploy_shopapi
        # Unit file depends on DEMO_SHOPAPI_CONFINED; never skip after --unconfined → confined.
        demo_write_shopapi_runtime_files "${PROJECT_ROOT}" >/dev/null
        if [[ "${LOAD_SEED}" -eq 1 ]]; then
            run_step load_shopapi_seed load_shopapi_seed
        fi
        start_services
        wait_shopapi
        verify_shopapi_label
        echo
        echo "=== shopapi-only bootstrap complete (confined=${DEMO_SHOPAPI_CONFINED} seed=${LOAD_SEED}) ==="
        log "Installing sepac CLI"
        make -C "${PROJECT_ROOT}" install-cli
        mkdir -p /etc/selinux-pac
        echo qa > /etc/selinux-pac/role
        chmod 0644 /etc/selinux-pac/role
        return 0
    fi
    run_step detect_variant detect_and_persist_variant
    run_step install_tomcat install_tomcat_stack
    run_step install_build install_build_tools
    run_step deploy_app_a deploy_app_a
    run_step configure_app_b configure_app_b
    run_step deploy_shopapi deploy_shopapi
    demo_write_shopapi_runtime_files "${PROJECT_ROOT}" >/dev/null
    if [[ "${LOAD_SEED}" -eq 1 ]]; then
        run_step load_shopapi_seed load_shopapi_seed
    fi
    # Always (re)start: stamped skip here would leave a half-booted host stopped.
    start_services
    wait_app_a
    wait_shopapi || true
    verify_shopapi_label
    echo
    echo "=== bootstrap complete ==="
    log "Installing sepac CLI"
    make -C "${PROJECT_ROOT}" install-cli
    mkdir -p /etc/selinux-pac
    echo qa > /etc/selinux-pac/role
    chmod 0644 /etc/selinux-pac/role
    echo "variant:  $(demo_variant) (process domain $(demo_tomcat_domain))"
    if [[ "$(demo_variant)" == "tomcat" ]]; then
        echo "note:     distro Tomcat fallback — tomcat_t, not jws6_tomcat_t; distro tomcat_t is unconfined (Act 1/2 denials will not fire)"
    fi
    echo "App A:    http://127.0.0.1:${APP_A_PORT}/standard/   (already confined; do not retune)"
    echo "App B:    http://127.0.0.1:${APP_B_PORT}/inherited/  (wrong label/port/boolean on purpose)"
    echo "shopapi:  see config/shopapi.manifest.yml http.port (wrapper shopapi_exec_t, permissive seed)"
    echo "Re-running this script skips completed steps and exits 0."
}

main "$@"
