Name:           selinux-policy-ops
Version:        1.2.0
Release:        1%{?dist}
Summary:        Shared SELinux deploy/readiness scripts (app-independent)
License:        MIT
URL:            https://github.com/anurag-saran/selinux-pac
BuildArch:      noarch
Requires:       python3
Requires:       setools-console

%description
Operational scripts for SELinux policy canary, enforce, and soak gates.
Installed under %{_libexecdir}/selinux-policy-ops for use by Ansible playbooks
and admins. Shared across application policy packages (myapp, payments, etc.).

%prep
# Scripts are copied from the repository at build time (see build script or CI).

%install
install -d %{buildroot}%{_libexecdir}/selinux-policy-ops/lib
install -m 0755 %{_builddir}/selinux-policy-ops-src/verify_file_contexts.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/wait_for_endpoints.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/monitor_avc.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/post_deploy_report.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/collect_soak_facts.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/check_soak_ready.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/check_soak_gate.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/check_audit_health.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/check_soak_days.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/record_soak_day.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0755 %{_builddir}/selinux-policy-ops-src/semodule_restore_dontaudit.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/
install -m 0644 %{_builddir}/selinux-policy-ops-src/lib/avc_query.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/
install -m 0644 %{_builddir}/selinux-policy-ops-src/lib/manifest_shell.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/
install -m 0644 %{_builddir}/selinux-policy-ops-src/lib/app_manifest.py \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/
install -m 0644 %{_builddir}/selinux-policy-ops-src/lib/app_identity.sh \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/
install -m 0755 %{_builddir}/selinux-policy-ops-src/lib/soak_net_new.py \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/
install -d %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/pac_cli
install -m 0644 %{_builddir}/selinux-policy-ops-src/lib/pac_cli/*.py \
    %{buildroot}%{_libexecdir}/selinux-policy-ops/lib/pac_cli/

%files
%defattr(-,root,root,-)
%{_libexecdir}/selinux-policy-ops/verify_file_contexts.sh
%{_libexecdir}/selinux-policy-ops/wait_for_endpoints.sh
%{_libexecdir}/selinux-policy-ops/monitor_avc.sh
%{_libexecdir}/selinux-policy-ops/post_deploy_report.sh
%{_libexecdir}/selinux-policy-ops/collect_soak_facts.sh
%{_libexecdir}/selinux-policy-ops/check_soak_ready.sh
%{_libexecdir}/selinux-policy-ops/check_soak_gate.sh
%{_libexecdir}/selinux-policy-ops/check_audit_health.sh
%{_libexecdir}/selinux-policy-ops/check_soak_days.sh
%{_libexecdir}/selinux-policy-ops/record_soak_day.sh
%{_libexecdir}/selinux-policy-ops/semodule_restore_dontaudit.sh
%{_libexecdir}/selinux-policy-ops/lib/avc_query.sh
%{_libexecdir}/selinux-policy-ops/lib/manifest_shell.sh
%{_libexecdir}/selinux-policy-ops/lib/app_manifest.py
%{_libexecdir}/selinux-policy-ops/lib/app_identity.sh
%{_libexecdir}/selinux-policy-ops/lib/soak_net_new.py
%dir %{_libexecdir}/selinux-policy-ops/lib/pac_cli
%{_libexecdir}/selinux-policy-ops/lib/pac_cli/*

%changelog
* Tue Oct 13 2026 SELinux PaC maintainers <maintainer@example.com> - 1.2.0-1
- Host scripts take the app from --manifest or --app; no myapp defaults

* Wed Oct 07 2026 SELinux PaC maintainers <maintainer@example.com> - 1.1.0-2
- Soak gate fails closed, stores daily results, and skips host-wide semodule -B

* Wed Sep 16 2026 SELinux PaC maintainers <maintainer@example.com> - 1.1.0-2
- monitor_avc: net-new stays 0 when there are no matching AVCs (same-NVR lab reinstalls)

* Mon Mar 16 2026 SELinux PaC maintainers <maintainer@example.com> - 1.1.0-1
- Add soak net-new AVC analysis, check_soak_ready, manifest_shell

* Sat Sep 13 2025 SELinux PaC maintainers <maintainer@example.com> - 1.0.0-1
- Initial shared ops package for target-side readiness scripts
