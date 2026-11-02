Name:           selinux-pac
Version:        %{sepac_version}
Release:        1%{?dist}
Summary:        SELinux Policy as Code — admin CLI and tooling
License:        MIT
URL:            https://github.com/anurag-saran/selinux-pac
BuildArch:      noarch

Requires:       python3
Requires:       python3-pyyaml
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       setools-console
Requires:       audit
Recommends:     selinux-policy-devel
Recommends:     ansible-core

%description
SELinux Policy as Code (sepac) — single admin CLI for triage, generation,
CI checks, canary/soak/enforce lifecycle, and rollback of custom SELinux
policy modules on RHEL 9.

%prep
# Files are staged from the repository by packaging/build_rpms.sh.

%install
# /usr/bin/sepac wrapper
install -d %{buildroot}%{_bindir}
install -m 0755 %{_builddir}/selinux-pac-src/bin/sepac \
    %{buildroot}%{_bindir}/sepac

# /usr/share/selinux-pac/ — tool tree
install -d %{buildroot}%{_datadir}/selinux-pac/cli
install -d %{buildroot}%{_datadir}/selinux-pac/scripts/lib
install -d %{buildroot}%{_datadir}/selinux-pac/scripts/ci

install -m 0644 %{_builddir}/selinux-pac-src/cli/*.py \
    %{buildroot}%{_datadir}/selinux-pac/cli/

for f in %{_builddir}/selinux-pac-src/scripts/*.sh; do
    install -m 0755 "$f" %{buildroot}%{_datadir}/selinux-pac/scripts/
done
for f in %{_builddir}/selinux-pac-src/scripts/lib/*.sh; do
    install -m 0644 "$f" %{buildroot}%{_datadir}/selinux-pac/scripts/lib/
done
for f in %{_builddir}/selinux-pac-src/scripts/lib/*.py; do
    install -m 0644 "$f" %{buildroot}%{_datadir}/selinux-pac/scripts/lib/
done

# /etc/selinux-pac/
install -d %{buildroot}%{_sysconfdir}/selinux-pac/apps
install -m 0644 %{_builddir}/selinux-pac-src/sepac.conf \
    %{buildroot}%{_sysconfdir}/selinux-pac/sepac.conf

# bash completion
install -d %{buildroot}%{_datadir}/bash-completion/completions
install -m 0644 %{_builddir}/selinux-pac-src/completions/sepac \
    %{buildroot}%{_datadir}/bash-completion/completions/sepac

# man page
install -d %{buildroot}%{_mandir}/man8
install -m 0644 %{_builddir}/selinux-pac-src/sepac.8.gz \
    %{buildroot}%{_mandir}/man8/sepac.8.gz

%files
%defattr(-,root,root,-)
%{_bindir}/sepac
%dir %{_datadir}/selinux-pac
%{_datadir}/selinux-pac/cli/*.py
%{_datadir}/selinux-pac/scripts/*.sh
%{_datadir}/selinux-pac/scripts/lib/*.sh
%{_datadir}/selinux-pac/scripts/lib/*.py
%dir %{_sysconfdir}/selinux-pac
%dir %{_sysconfdir}/selinux-pac/apps
%config(noreplace) %{_sysconfdir}/selinux-pac/sepac.conf
%{_datadir}/bash-completion/completions/sepac
%{_mandir}/man8/sepac.8.gz

%changelog
* Tue Oct 13 2026 SELinux PaC maintainers <maintainer@example.com> - 1.0.0-1
- Initial selinux-pac CLI package: sepac, completion, man page, /etc/selinux-pac
