#!/usr/bin/env bash
# Sign selinux-pac RPMs and publish them to an internal file repo.
#
#   cp packaging/internal.env.example packaging/internal.env   # edit
#   bash packaging/build_rpms.sh
#   bash packaging/publish_internal.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${SELINUX_INTERNAL_ENV:-${ROOT}/packaging/internal.env}"

if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "${ENV_FILE}"
    set +a
fi

REPO_DIR="${SELINUX_RPM_REPO:-}"
if [[ -z "${REPO_DIR}" ]]; then
    echo "Set SELINUX_RPM_REPO (see packaging/internal.env.example)" >&2
    exit 2
fi

DIST="${ROOT}/dist"
if ! compgen -G "${DIST}/*.rpm" >/dev/null; then
    echo "No RPMs in ${DIST}/ — run bash packaging/build_rpms.sh first" >&2
    exit 1
fi

if [[ "${SELINUX_ALLOW_UNSIGNED:-}" == "1" ]]; then
    echo "WARNING: SELINUX_ALLOW_UNSIGNED=1 — publishing UNSIGNED RPMs." >&2
    echo "WARNING: labs only. Do not point a production host at this repository." >&2
elif [[ -z "${SELINUX_GPG_NAME:-}" ]] || ! command -v rpmsign >/dev/null 2>&1; then
    echo "Refusing to publish: RPM signing is not configured." >&2
    echo "Set SELINUX_GPG_NAME and install rpm-sign, or set SELINUX_ALLOW_UNSIGNED=1 for a lab only." >&2
    exit 1
else
    echo "Signing RPMs with GPG name ${SELINUX_GPG_NAME}"
    sign_args=(--addsign)
    if [[ -n "${LAB_GNUPGHOME:-}" ]]; then
        sign_args+=(--define "_gpg_path ${LAB_GNUPGHOME}")
    fi
    sign_args+=(--define "_gpg_name ${SELINUX_GPG_NAME}")
    # RHEL 9 rpm dropped --key-id. Older rpm still accepts it.
    if rpmsign --help 2>&1 | grep -q -- '--key-id'; then
        sign_args+=(--key-id "${SELINUX_GPG_NAME}")
    fi
    rpmsign "${sign_args[@]}" "${DIST}"/*.rpm
fi

sudo mkdir -p "${REPO_DIR}"
sudo cp -f "${DIST}"/*.rpm "${REPO_DIR}/"
if command -v createrepo_c >/dev/null 2>&1; then
    sudo createrepo_c "${REPO_DIR}"
elif command -v createrepo >/dev/null 2>&1; then
    sudo createrepo "${REPO_DIR}"
else
    echo "WARN: createrepo_c not installed — repo metadata not refreshed" >&2
fi

cat <<EOF
Published ${REPO_DIR}

On RHEL targets, install a .repo (adjust baseurl) and import the GPG key:

  [selinux-pac]
  name=SELinux Policy-as-Code
  baseurl=https://yum.example.internal/selinux-pac
  enabled=1
  gpgcheck=1
  gpgkey=https://yum.example.internal/selinux-pac/RPM-GPG-KEY

Compile policy on RHEL with selinux-policy-devel (dnf install selinux-policy-devel).
EOF
