#!/usr/bin/env bash
# Build selinux-policy-ops, myapp-selinux (test fixture), and shopapi-selinux (demo).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
RPMBUILD="${ROOT}/packaging/rpmbuild"

stamp_spec_commit() {
    local spec="$1"
    local sha="$2"
    python3 - "${spec}" "${sha}" <<'PY'
import pathlib
import sys

path, sha = sys.argv[1], sys.argv[2]
text = pathlib.Path(path).read_text(encoding="utf-8")
line = f"Built from git commit {sha}.\n"
if "Built from git commit" not in text:
    text = text.replace("%description\n", "%description\n" + line, 1)
    pathlib.Path(path).write_text(text, encoding="utf-8")
PY
}

if [[ "${1:-}" == "--stamp-spec" ]]; then
    stamp_spec_commit "$2" "$3"
    exit 0
fi

if [[ -n "$(git -C "${ROOT}" status --porcelain)" && "${BUILD_RPMS_ALLOW_DIRTY:-0}" != 1 ]]; then
    echo "Refusing to build RPMs from a dirty git tree." >&2
    exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
    if [[ "$(uname -s)" == Darwin && "${BUILD_RPMS_LOCAL:-0}" != 1 ]]; then
        echo "rpmbuild is not on macOS — compiling and packing on rhel-qa, then copying dist/*.rpm back here." >&2
        exec bash "${ROOT}/lab/build_rpms_on_dev.sh"
    fi
    echo "rpmbuild is required. Refusing to report success after a parity-only check." >&2
    exit 1
fi

GIT_COMMIT="$(git -C "${ROOT}" rev-parse HEAD)"

# shellcheck source=../scripts/lib/version.sh
source "${ROOT}/scripts/lib/version.sh"
VERSION="$(policy_version "${ROOT}/selinux/myapp/policy_version.txt")"
# RPM Version comes from policy_version.txt only — do not hardcode in the .spec (rpmbuild cwd breaks fragile %define cat).

mkdir -p "${DIST}" "${RPMBUILD}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
OPS_SRC="${RPMBUILD}/BUILD/selinux-policy-ops-src"
mkdir -p "${OPS_SRC}/lib"
cp "${ROOT}/scripts/verify_file_contexts.sh" \
   "${ROOT}/scripts/wait_for_endpoints.sh" \
   "${ROOT}/scripts/monitor_avc.sh" \
   "${ROOT}/scripts/post_deploy_report.sh" \
   "${ROOT}/scripts/collect_soak_facts.sh" \
   "${ROOT}/scripts/check_soak_ready.sh" \
   "${ROOT}/scripts/check_soak_gate.sh" \
   "${ROOT}/scripts/check_audit_health.sh" \
   "${ROOT}/scripts/check_soak_days.sh" \
   "${ROOT}/scripts/record_soak_day.sh" \
   "${ROOT}/scripts/semodule_restore_dontaudit.sh" "${OPS_SRC}/"
cp "${ROOT}/scripts/lib/avc_query.sh" \
   "${ROOT}/scripts/lib/app_manifest.py" \
   "${ROOT}/scripts/lib/manifest_shell.sh" \
   "${ROOT}/scripts/lib/soak_net_new.py" "${OPS_SRC}/lib/"
mkdir -p "${OPS_SRC}/lib/pac_cli"
while IFS= read -r rel || [[ -n "${rel}" ]]; do
    [[ -z "${rel}" || "${rel}" == \#* ]] && continue
    cp "${ROOT}/cli/${rel}" "${OPS_SRC}/lib/pac_cli/"
done < "${ROOT}/packaging/pac_cli.list"

bash "${ROOT}/scripts/validate_rpm_ops_parity.sh"
bash "${ROOT}/scripts/validate_rpm_sepac_parity.sh"
bash "${ROOT}/scripts/compile_and_validate.sh" selinux/myapp --app myapp
bash "${ROOT}/scripts/compile_and_validate.sh" "${ROOT}/selinux/shopapi" --app shopapi
SHOPAPI_VERSION="$(policy_version "${ROOT}/selinux/shopapi/policy_version.txt")"

cp "${ROOT}/packaging/selinux-policy-ops.spec" "${RPMBUILD}/SPECS/"
cp "${ROOT}/packaging/myapp-selinux.spec" "${RPMBUILD}/SPECS/"
cp "${ROOT}/packaging/shopapi-selinux.spec" "${RPMBUILD}/SPECS/"
stamp_spec_commit "${RPMBUILD}/SPECS/selinux-policy-ops.spec" "${GIT_COMMIT}"
stamp_spec_commit "${RPMBUILD}/SPECS/myapp-selinux.spec" "${GIT_COMMIT}"
stamp_spec_commit "${RPMBUILD}/SPECS/shopapi-selinux.spec" "${GIT_COMMIT}"
cp "${ROOT}/selinux/myapp/myapp.pp" "${RPMBUILD}/SOURCES/myapp.pp"
cp "${ROOT}/selinux/myapp/myapp.te" "${RPMBUILD}/SOURCES/myapp.te"
cp "${ROOT}/selinux/myapp/myapp.fc" "${RPMBUILD}/SOURCES/myapp.fc"
cp "${ROOT}/config/myapp.manifest.yml" "${RPMBUILD}/SOURCES/selinux-manifest.yml"
cp "${ROOT}/selinux/shopapi/shopapi.pp" "${RPMBUILD}/SOURCES/shopapi.pp"
cp "${ROOT}/selinux/shopapi/shopapi.te" "${RPMBUILD}/SOURCES/shopapi.te"
cp "${ROOT}/selinux/shopapi/shopapi.fc" "${RPMBUILD}/SOURCES/shopapi.fc"

# Ops spec uses relative paths to scripts/ — patch SOURCEDIR via rpmbuild -D
rpmbuild -ba \
  --define "_topdir ${RPMBUILD}" \
  --define "_sourcedir ${RPMBUILD}/SOURCES" \
  "${RPMBUILD}/SPECS/selinux-policy-ops.spec"

rpmbuild -ba \
  --define "_topdir ${RPMBUILD}" \
  --define "_sourcedir ${RPMBUILD}/SOURCES" \
  --define "modver ${VERSION}" \
  "${RPMBUILD}/SPECS/myapp-selinux.spec"

cp "${ROOT}/config/shopapi.manifest.yml" "${RPMBUILD}/SOURCES/selinux-manifest.yml"
rpmbuild -ba \
  --define "_topdir ${RPMBUILD}" \
  --define "_sourcedir ${RPMBUILD}/SOURCES" \
  --define "modver ${SHOPAPI_VERSION}" \
  "${RPMBUILD}/SPECS/shopapi-selinux.spec"

# ── selinux-pac CLI package ──────────────────────────────────────────────────
SEPAC_SRC="${RPMBUILD}/BUILD/selinux-pac-src"
mkdir -p "${SEPAC_SRC}/bin" "${SEPAC_SRC}/cli" "${SEPAC_SRC}/scripts/lib" \
         "${SEPAC_SRC}/scripts/ci" "${SEPAC_SRC}/completions"

# bin/sepac installed wrapper
cat >"${SEPAC_SRC}/bin/sepac" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
exec python3 /usr/share/selinux-pac/cli/sepac.py "$@"
WRAPPER
chmod +x "${SEPAC_SRC}/bin/sepac"

# CLI Python modules
cp "${ROOT}"/cli/*.py "${SEPAC_SRC}/cli/"

# Scripts sepac calls (all .sh from scripts/ and scripts/lib/)
for f in "${ROOT}"/scripts/*.sh; do
    cp "$f" "${SEPAC_SRC}/scripts/"
done
for f in "${ROOT}"/scripts/lib/*.sh "${ROOT}"/scripts/lib/*.py; do
    cp "$f" "${SEPAC_SRC}/scripts/lib/"
done

# sepac.conf
cp "${ROOT}/packaging/sepac.conf" "${SEPAC_SRC}/sepac.conf"

# Generate bash completion
python3 "${ROOT}/cli/sepac.py" completion bash > "${SEPAC_SRC}/completions/sepac"

# Generate and compress man page
python3 "${ROOT}/cli/sepac.py" _man > "${SEPAC_SRC}/sepac.8"
gzip -9 "${SEPAC_SRC}/sepac.8"

SEPAC_VERSION="${VERSION}"
cp "${ROOT}/packaging/selinux-pac.spec" "${RPMBUILD}/SPECS/"
stamp_spec_commit "${RPMBUILD}/SPECS/selinux-pac.spec" "${GIT_COMMIT}"
rpmbuild -ba \
  --define "_topdir ${RPMBUILD}" \
  --define "sepac_version ${SEPAC_VERSION}" \
  "${RPMBUILD}/SPECS/selinux-pac.spec"

rm -f "${DIST}"/*.rpm
find "${RPMBUILD}/RPMS" -name '*.rpm' -exec cp {} "${DIST}/" \;
echo "Built RPMs in ${DIST}/"
ls -l "${DIST}"/*.rpm
