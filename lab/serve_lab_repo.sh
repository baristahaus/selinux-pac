#!/usr/bin/env bash
#
# serve_lab_repo.sh — Serve the signed lab repo over HTTP from this host.
# The private key stays in GNUPGHOME and is not in the repo directory.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/dist/lab-signing.env"
if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "${ENV_FILE}"
    set +a
fi

REPO="${SELINUX_RPM_REPO:-}"
PORT="${SELINUX_REPO_PORT:-8765}"
if [[ -z "${REPO}" || ! -d "${REPO}" ]]; then
    echo "Set SELINUX_RPM_REPO to the published repo directory." >&2
    exit 2
fi
if [[ -n "${LAB_GNUPGHOME:-}" && "${REPO}" == "${LAB_GNUPGHOME}"* ]]; then
    echo "Refusing to serve the private key directory." >&2
    exit 1
fi

BACKGROUND=0
for arg in "$@"; do
    case "${arg}" in
        --background) BACKGROUND=1 ;;
        *)
            echo "Unknown option: ${arg}" >&2
            exit 2
            ;;
    esac
done

print_urls() {
    echo "Serving ${REPO} on port ${PORT}"
    echo "baseurl=http://$(hostname -f 2>/dev/null || hostname):${PORT}"
    echo "gpgkey=http://$(hostname -f 2>/dev/null || hostname):${PORT}/RPM-GPG-KEY"
    echo "Alternative: rsync -a ${REPO}/ user@prod:/var/www/selinux-pac/"
}

repo_is_up() {
    command -v curl >/dev/null 2>&1 || return 1
    curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:${PORT}/"
}

if repo_is_up; then
    echo "Already serving on port ${PORT}"
    print_urls
    exit 0
fi

if [[ "${BACKGROUND}" -eq 1 ]]; then
    nohup python3 -m http.server "${PORT}" --bind 0.0.0.0 --directory "${REPO}" \
        >/var/tmp/selinux-repo-http.log 2>&1 &
    disown || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if repo_is_up; then
            print_urls
            exit 0
        fi
        sleep 0.2
    done
    echo "Repo server did not start on port ${PORT}. See /var/tmp/selinux-repo-http.log" >&2
    exit 1
fi

print_urls
exec python3 -m http.server "${PORT}" --bind 0.0.0.0 --directory "${REPO}"
