Name:           myapp-selinux
# modver is passed by packaging/build_rpms.sh from selinux/myapp/policy_version.txt (single source of truth).
Version:        %{modver}
Release:        1%{?dist}
Summary:        SELinux policy module for Order Processor reference application
License:        MIT
URL:            https://github.com/anurag-saran/selinux-pac
BuildArch:      noarch

Requires:       selinux-policy-ops >= 1.0.0
Requires(post): policycoreutils
Requires(post): selinux-policy-base

Source0:        myapp.pp
Source1:        myapp.te
Source2:        myapp.fc
Source3:        selinux-manifest.yml

%description
Custom SELinux policy module (myapp) for the Order Processor reference application.
Installs type enforcement for myapp_t and myapp_backend_t with FHS paths under
/var/lib/myapp, /var/log/myapp, /run/myapp, and /var/run/myapp (RHEL maps /run).

%prep
# Binary policy built by scripts/compile_and_validate.sh; manifest from config/

%install
install -d %{buildroot}%{_datadir}/selinux/packages
install -m 0644 %{SOURCE0} %{buildroot}%{_datadir}/selinux/packages/myapp.pp
install -d %{buildroot}%{_sysconfdir}/myapp
install -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/myapp/selinux-manifest.yml
install -d %{buildroot}%{_datadir}/doc/%{name}-%{version}
install -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/doc/%{name}-%{version}/myapp.te
install -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/doc/%{name}-%{version}/myapp.fc

%pre
%selinux_relabel_pre -s targeted

%post
%selinux_modules_install -s targeted %{_datadir}/selinux/packages/myapp.pp
if command -v semanage >/dev/null 2>&1; then
    semanage port -a -t myapp_port_t -p tcp 8888 2>/dev/null || \
        semanage port -m -t myapp_port_t -p tcp 8888 2>/dev/null || true
    semanage port -a -t myapp_backend_port_t -p tcp 8889 2>/dev/null || \
        semanage port -m -t myapp_backend_port_t -p tcp 8889 2>/dev/null || true
fi

%postun
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s targeted myapp
    if command -v semanage >/dev/null 2>&1; then
        semanage port -d -p tcp 8888 2>/dev/null || true
        semanage port -d -p tcp 8889 2>/dev/null || true
    fi
fi

%posttrans
%selinux_relabel_post -s targeted

%files
%defattr(-,root,root,-)
%{_datadir}/selinux/packages/myapp.pp
%config(noreplace) %{_sysconfdir}/myapp/selinux-manifest.yml
%doc %{_datadir}/doc/%{name}-%{version}/myapp.te
%doc %{_datadir}/doc/%{name}-%{version}/myapp.fc

%changelog
* Wed Sep 16 2026 SELinux PaC maintainers <maintainer@example.com> - 1.1.3-1
- Label /var/run/myapp (RHEL file_contexts.subs maps /run)
- Allow dir search on myapp_script_exec_t; unix_stream connectto on myapp_t
- Ship .te/.fc under %{_datadir}/doc (rpmbuild %doc SOURCE was broken)

* Sun Sep 13 2026 SELinux PaC maintainers <maintainer@example.com> - 1.1.2-1
- Requires selinux-policy-ops; ship manifest under /etc/myapp/
- Policy 1.1.2 manage patterns, urand, narrowed /var/opt labeling

* Sun Sep 13 2026 SELinux PaC maintainers <maintainer@example.com> - 1.1.1-1
- Path traversal, daemon baseline, /var/log/myapp log type + filetrans
