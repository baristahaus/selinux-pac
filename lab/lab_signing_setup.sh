#!/usr/bin/env bash
#
# lab_signing_setup.sh — Lab GPG key and a local dnf repo so 302 installs
# with gpgcheck=1. Prints the public key path and the two variable names.
# Never prints the private key. Do not commit the key or the repo.
#
set -euo pipefail

if [[ "${1:-}" == "--print-secret" ]]; then
    echo "Refusing to print the private key." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${SELINUX_GPG_NAME:-selinux-pac-lab}"
REPO="${SELINUX_RPM_REPO:-${ROOT}/dist/lab-repo}"
GNUPGHOME="${LAB_GNUPGHOME:-${ROOT}/dist/lab-gnupg}"

if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is not installed. Install it, then re-run." >&2
    exit 1
fi

mkdir -p "${GNUPGHOME}" "${REPO}"
chmod 700 "${GNUPGHOME}"

if ! gpg --homedir "${GNUPGHOME}" --list-keys "${NAME}" >/dev/null 2>&1; then
    gpg --homedir "${GNUPGHOME}" --batch --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "${NAME}" default default never
fi

gpg --homedir "${GNUPGHOME}" --armor --export "${NAME}" >"${REPO}/RPM-GPG-KEY"
cat >"${REPO}/selinux-pac.repo" <<EOF
[selinux-pac]
name=SELinux Policy-as-Code lab
baseurl=file://${REPO}
enabled=1
gpgcheck=1
gpgkey=file://${REPO}/RPM-GPG-KEY
EOF
cat >"${ROOT}/dist/lab-rpmmacros" <<EOF
%_signature gpg
%_gpg_name ${NAME}
%_gpg_path ${GNUPGHOME}
EOF

cat >"${ROOT}/dist/lab-signing.env" <<EOF
SELINUX_GPG_NAME=${NAME}
SELINUX_RPM_REPO=${REPO}
LAB_GNUPGHOME=${GNUPGHOME}
EOF
chmod 0644 "${ROOT}/dist/lab-signing.env"

echo "SELINUX_GPG_NAME=${NAME}"
echo "SELINUX_RPM_REPO=${REPO}"
echo "GNUPGHOME=${GNUPGHOME}"
echo "Public key: ${REPO}/RPM-GPG-KEY"
echo "Repo file: ${REPO}/selinux-pac.repo (gpgcheck=1)"
echo "RPM macros: ${ROOT}/dist/lab-rpmmacros"
echo "Do not commit ${GNUPGHOME} or the private key."
