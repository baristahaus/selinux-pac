# Packaging Policy as RPMs

> Every SELinux module you ship is a deploy-time decision. Package it as a signed RPM, not as a `scp` of `.pp`. That choice makes the decision reversible, auditable, and reproducible. It is the difference between a change that works until the next reboot and a change that works until someone rolls it back.

## Why policy ships as a package

SELinux policy is code. It is also the single source of truth for what processes can touch on a host. The two delivery paths you will meet are:

1. **A compiled `.pp` copied into `/var/lib/selinux/targeted/custom/`**. Anyone with SSH access can reach it. `semodule -i` loads it, and nothing audits or rolls it back.
2. **A signed RPM that installs the `.pp`, registers ports and labels, and pulls the policy back on the next boot**. `dnf` reaches it, the change is audit-tracked, and a downgrade is the rollback primitive.

The rule that production hosts do not carry the repository exists for a reason. See `docs/admin/203-RHEL_TWO_HOST.md` and `docs/admin/304-ADOPTION_CHECKLIST.md` for the wording: "production host: no git clone; `selinux_ops_from_package: true`". If policy reaches the host as a tarball of your `selinux/` directory, the chain-of-custody question is open. Who compiled this? From which `.te`? On which box? If it reaches the host as an RPM signed with `SELINUX_GPG_NAME`, the answer is `rpm -Kv dist/*.rpm` plus `rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'`. The first command checks the signature and the package digest. The repo at `SELINUX_RPM_REPO` keeps the signed artifact.

The practical differences are:

| Property | `scp` + `semodule -i` | RPM |
|----------|----------------------|-----|
| Reproducibility | "it compiled once on the box I remember" | the same source and the same `policy_version.txt` give the same `modver`, the same NVR, and the same compiled `.pp` on any build host. The bytes of the RPM vary with the build host and its timestamps. The identity of the artifact does not |
| Versioning | manual, fragile | `%{modver}` comes from `selinux/<app>/policy_version.txt`, the single source of truth |
| Rollback | "unload and hope nothing broke" | `rpm -e` triggers `%postun`. A downgrade installs the older `.pp` |
| Install surface | every SSH key on the host | `dnf` against the internal repo, key-trusted |

:::: why Why not keep a repo clone on prod?
A `git clone` on prod lets you `tail -f selinux/myapp.te` and hot-fix a rule at 2am. That is exactly what SELinux suppresses: a developer in the box. The playbook owns the deploy. The RPM owns the binary on the host. The host only ever sees the artifact, not the source tree.
::::

## The two-package split

Two RPMs exist for each application:

| Package | Purpose | Who installs it |
|---------|---------|-----------------|
| `selinux-policy-ops` | shared operator tooling: scripts that run canary, soak, monitor, and report | every production host, regardless of which application is on it |
| `<app>-selinux` (for example `shopapi-selinux`, `myapp-selinux`) | one application's compiled module + manifest + types | only the host running that application |

The split exists because the operator tooling is generic. It queries AVC, checks `file_contexts`, computes the soak net-new, and checks readiness. It lives under `%{_libexecdir}/selinux-policy-ops`. It does not need to know the port or the domain of your app. The application module is the other half. It carries your policy, your manifest, and your ports, and it is the per-app artifact.

`selinux-policy-ops` depends on `setools-console`, so the playbooks can query policy for the operator. Each per-app spec has `Requires: selinux-policy-ops >= 1.0.0`. So the operator tooling must be present before you load your module.

## What each spec packages

Every per-app spec (`packaging/shopapi-selinux.spec`, `packaging/myapp-selinux.spec`) follows the same pattern. Each spec ships this material:

| Source index | File | Purpose |
|-------------|------|---------|
| `Source0` | compiled `.pp` | the binary policy that SELinux loads |
| `Source1` | `.te` | source type-enforcement, shipped as `%doc` |
| `Source2` | `.fc` | source file contexts, shipped as `%doc` |
| `Source3` | `selinux-manifest.yml` | the manifest-derived port + path declarations, shipped as `%config(noreplace)` under `/etc/<app>/` |

The `.pp` lands at `%{_datadir}/selinux/packages/<app>.pp`. That is the path `%selinux_modules_install` reads during `%post`, and it loads the module into the loaded-policy database. The manifest becomes a configuration file under `%{_sysconfdir}/<app>/selinux-manifest.yml`. The operator scripts read it through `app_manifest_path`.

Each app spec has `Requires(post)` on `policycoreutils` and `selinux-policy-base`. The host already has both tools. The RPM declares them because they produced the module on the build host.

The `%post` scriptlet of each app RPM does three things:

1. `%selinux_modules_install -s targeted <app>.pp` loads the compiled module into the running policy.
2. `semanage port -a/-m` registers each port in the manifest with its type, for example `shopapi_port_t` on TCP 8091, or `myapp_port_t` / `myapp_backend_port_t` on 8888 / 8889.
3. `|| true` absorbs a missing `semanage`, so the install does not block the host.

The `%postun` scriptlet removes the module only on an explicit erase. `if [ $1 -eq 0 ]` is true for `rpm -e` and false for `rpm -U`. This is the rollback primitive. If the operator or the playbook issues `rpm -e`, the erase rolls back every piece of SELinux state that came with the package.

:::: note The %postun conditional
`$1` in a scriptlet is the number of instances of the package that will remain after the transaction. It is `0` on erase, and `1` or more on upgrade. So `if [ $1 -eq 0 ]` uninstalls the module only when the package is really going away. During an upgrade, the scriptlet leaves the module, and the new `%post` replaces it. There is no `%{?_upgrading}` macro here. The numeric argument is the idiom.
::::

## Building RPMs

`packaging/build_rpms.sh` is the single build driver. It does the following:

1. It checks that `rpmbuild` is available. On macOS, when `rpmbuild` is missing, the script
   runs `scripts/build_rpms_on_dev.sh` instead, unless you set `BUILD_RPMS_LOCAL=1`. That
   script SSHes into `rhel-qa`, where `DEV_HOST` defaults to `192.168.64.6`, builds there, and
   `rsync`-copies the RPMs back to `dist/` on the controller. On Linux, when `rpmbuild` is
   missing, the script prints `Note: rpmbuild not found; validating spec parity only`, runs the
   parity check, and exits 0.
2. It reads the version from `selinux/policy_version.txt` for `myapp` and from `selinux/shopapi/policy_version.txt` for `shopapi`. Both go through the `policy_version` helper in `scripts/lib/version.sh`. The script stashes the value into `--define "modver …"`. The spec does not hardcode its version. The text file is the single source of truth.
3. Builds the `%prep` tree: copies scripts into `rpmbuild/BUILD/selinux-policy-ops-src/lib/`, the CLI under `lib/pac_cli/`, and the per-app `.pp`/`.te`/`.fc`/manifest into `SOURCES/`.
4. It calls `scripts/validate_rpm_ops_parity.sh` once, up front. When `rpmbuild` is absent, that check is the whole run. The script guards the `selinux-policy-ops` source allowlist, not the per-app specs.
5. Calls `scripts/compile_and_validate.sh` against the source trees, then runs `rpmbuild -ba` for each spec in turn.
6. Copies every produced `.rpm` into `dist/` and lists it.

The host needs `rpmbuild`, the SELinux policy toolchain (`make` / `checkmodule` / `semodule_package`), and `scripts/lib/version.sh` reachable from the workspace root. If `rpmbuild` is missing, the driver branches. On macOS it execs `scripts/build_rpms_on_dev.sh`, unless you set `BUILD_RPMS_LOCAL=1`. That script compiles and packs on rhel-qa, then copies `dist/*.rpm` back. On Linux it prints `Note: rpmbuild not found; validating spec parity only`, runs the parity check, and exits 0.

## Publishing

`packaging/publish_internal.sh` signs every RPM in `dist/` with the GPG key named by `SELINUX_GPG_NAME`. Set that name in `packaging/internal.env`, which you copy from `internal.env.example`. The script then copies the RPMs into `SELINUX_RPM_REPO`. That is the file directory that `httpd` / Pulp / Satellite serves as a yum repo. The script refreshes the metadata with `createrepo_c` or `createrepo`.

`packaging/internal.env.example` is the single piece of configuration:

```bash
SELINUX_RPM_REPO=/var/www/html/selinux-pac
SELINUX_GPG_NAME=selinux-pac
```

`packaging/publish_internal.sh` reads this environment, signs the artifact, and prints the `.repo` snippet that you place on each RHEL host. The snippet is a `[selinux-pac]` section on `baseurl=https://yum.example.internal/selinux-pac`, with `gpgcheck=1`, keyed by `RPM-GPG-KEY`. Nothing under `ansible/` reads this file. The playbooks install from the repo that the hosts in the inventory already use. So the `.repo` file is an admin step, not a playbook step.

::: try Inspect a spec from your own box
Do this on `rhel-qa`, or on any host with `rpm-build`. Run the command only if `rpmbuild` is installed. If it is not, say so plainly:

```bash
$ rpm -q --specfile /home/ansible/selinux-pac/packaging/shopapi-selinux.spec
```

Without `rpmbuild`, `packaging/build_rpms.sh` takes a shortcut, and the shortcut depends on the host. On Linux it prints `Note: rpmbuild not found; validating spec parity only`, runs the parity script, and exits 0. On macOS it `exec`s `scripts/build_rpms_on_dev.sh`, which rsyncs to the dev host and builds there. If you only want to read the spec, neither path is what you want. The parity script is its own command.

```bash
$ bash scripts/validate_rpm_ops_parity.sh
OK selinux-policy-ops sources match packaging spec allowlist
```

The script is the single guard on the ops package. It holds a fixed allowlist of the scripts and `scripts/lib` files that `selinux-policy-ops.spec` must declare. It fails when a listed source is missing from the tree or from the spec (`MISSING source: …`, `SPEC missing script: …`). It is an allowlist, not a discovery pass. A script you add to `scripts/` is not covered until you add it to the list and to the spec.
:::

## Versioning and upgrades

The module version travels with the RPM as `%{modver}`. The packager does not choose it. The build reads it from `selinux/<app>/policy_version.txt`. That text file changes whenever the `.te` changes. Each PR that lands a rule increment bumps the number, and the RPM rebuilds against the new value.

What an upgrade does:

1. `%post` installs the new `.pp`, because `%selinux_modules_install` runs `semodule -i`. The policy store keeps one module per name, so the new ruleset replaces the old one in place. You do not need `semodule -r`, and the scriptlet does not run it.
2. `semanage port -m` updates each port type to the new mapping declared by the manifest.
3. `%posttrans` re-applies relabels (`%selinux_relabel_post`) so the on-disk state matches the new policy.

What a downgrade does:

1. `dnf downgrade` (or `rpm -Uvh --oldpackage`) runs the `%post` of the older package. That scriptlet installs the older `.pp` over the newer one, the same in-place replace. No window exists where the host loads two versions of the module. You do not have to reload anything afterwards for the rules to change.
2. `rpm -e` triggers `%postun`, which unloads the module and drops the ports. That is the rollback primitive that Chapter 20 refers to.
3. When the operator wants the host back at an exact earlier state, `dnf history rollback` undoes the whole transaction, policy and packages together.

The rollback primitive is not theoretical. Take a mis-compiled `.pp` that grants `write` on `shadow_t`. You can roll it back completely: unload the policy, deregister the ports, and build a new NVR. All of it runs from `dnf`, and you never touch the policy database of the box by hand.

## Who does what

This table summarizes the lifecycle of each artifact:

| Artifact | Built by | Installed where | Updated by | Rolled back by |
|----------|----------|-----------------|------------|----------------|
| `selinux-policy-ops` RPM | `packaging/build_rpms.sh` on rhel-qa (or controller via `build_rpms_on_dev.sh`) | every production host (`ansible.builtin.dnf: name: selinux-policy-ops`) | `rpm -U` against the internal repo | `rpm -e`. The RPM owns those files, so erase removes them. The ops spec has no scriptlets |
| `<app>-selinux` RPM | `packaging/build_rpms.sh`, `modver` from `policy_version.txt` | only the host running that app | `rpm -U` after each PR that bumps `policy_version.txt` | `rpm -e` → `%postun` unloads module, drops ports |
| `policy_version.txt` | `selinux/<app>/` in each app repo | never on prod | git PR on the app repo | git revert, paired with `rpm` rebuild |
| Signed RPM payload | `packaging/publish_internal.sh` with `SELINUX_GPG_NAME` (`rpmsign --addsign`) | `dist/*.rpm` before publish | the RPM repo mirrors the signed artifact | publish the previous NVR again (`dnf downgrade` on the host) |
| Internal yum repo | `httpd` / Pulp / Satellite at `SELINUX_RPM_REPO` | each production host's `/etc/yum.repos.d/` | each new `publish_internal.sh` run | repo rotation: the previous NVR stays resolvable |

:::: warn Never install a locally built module on production
Do not install a module that you built on the host itself. `semodule -i` after your own compile is the single most common mis-step in this codebase. If you cannot name the source of the `.te` you compiled, you cannot roll back. You cannot check parity, and you cannot rebuild against `modver` later. The rule is: `rhel-qa` compiles, and `rhel-prod` consumes RPMs.
::::

:::: warn Never `semodule -i` a file you cannot name the source of
This is the corollary. Every time you skip an RPM and load a `.pp` by hand, the host loses the upgrade path. Upgrade becomes "apply rules by hand to the running policy, hope the permissive flag is the right one." Rollback becomes "reboot and hope nothing was cached." Live `.pp` files on prod hosts are the failure mode that Chapter 20 plans for.
::::

## What you can do now

- [ ] Inspect `packaging/build_rpms.sh` on rhel-qa. Check the `rpmbuild` path and the `BUILD_RPMS_LOCAL` escape hatch.
- [ ] Run `bash scripts/validate_rpm_ops_parity.sh` once. It exits 0 with one `OK` line when the allowlist matches. When it does not, the message names the missing file by path.
- [ ] Check that every per-app spec names every `.pp` source. Run `grep -E '^Source[0-9]' packaging/<app>-selinux.spec`.
- [ ] Bump `policy_version.txt` in the `selinux/` directory of your app. Rebuild with `packaging/build_rpms.sh`. Then check that the new NVR appears in `dist/`.
- [ ] Point an Ansible controller at your internal repo, and run `install_packages.yml`. Watch `selinux_ops_from_package: true` change the decision from `semodule -i` to `dnf`.
