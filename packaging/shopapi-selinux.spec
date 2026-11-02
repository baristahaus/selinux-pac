Name:           shopapi-selinux
# modver is passed by packaging/build_rpms.sh from selinux/shopapi/policy_version.txt.
Version:        %{modver}
Release:        1%{?dist}
Summary:        SELinux policy module for shopapi Spring Boot demo
License:        MIT
URL:            https://github.com/anurag-saran/selinux-pac
BuildArch:      noarch

Requires:       selinux-policy-ops >= 1.0.0
Requires(post): policycoreutils
Requires(post): selinux-policy-base

Source0:        shopapi.pp
Source1:        shopapi.te
Source2:        shopapi.fc
Source3:        selinux-manifest.yml

%description
Custom SELinux policy module (shopapi) for the Spring Boot demo JVM.
ExecStart is the wrapper /opt/shopapi/bin/shopapi (shopapi_exec_t); init_daemon_domain moves it to shopapi_t; the system JVM is bin_t and runs under the reviewed corecmd_exec_bin exception.

%prep

%install
install -d %{buildroot}%{_datadir}/selinux/packages
install -m 0644 %{SOURCE0} %{buildroot}%{_datadir}/selinux/packages/shopapi.pp
install -d %{buildroot}%{_sysconfdir}/shopapi
install -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/shopapi/selinux-manifest.yml
install -d %{buildroot}%{_datadir}/doc/%{name}-%{version}
install -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/doc/%{name}-%{version}/shopapi.te
install -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/doc/%{name}-%{version}/shopapi.fc

%pre
%selinux_relabel_pre -s targeted

%post
# Install the module only. Do not start the service. Canary sets the domain
# permissive and then restarts it.
%selinux_modules_install -s targeted %{_datadir}/selinux/packages/shopapi.pp

%postun
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s targeted shopapi
fi

%posttrans
%selinux_relabel_post -s targeted

%files
%defattr(-,root,root,-)
%{_datadir}/selinux/packages/shopapi.pp
%config(noreplace) %{_sysconfdir}/shopapi/selinux-manifest.yml
%doc %{_datadir}/doc/%{name}-%{version}/shopapi.te
%doc %{_datadir}/doc/%{name}-%{version}/shopapi.fc

%changelog
* Thu Sep 17 2026 SELinux PaC maintainers <maintainer@example.com> - 1.0.0-1
- Initial shopapi module RPM for the three-app customer demo
