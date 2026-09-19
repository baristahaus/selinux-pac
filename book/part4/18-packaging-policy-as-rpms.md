# Packaging Policy as RPMs

> Every SELinux module you ship is a deploy-time decision. Packaging it as a signed RPM rather than a `scp` of `.pp` makes that decision reversible, auditable, and reproducible — which is the difference between "it works until the next reboot" and "it works until someone rolls it back."

## Why policy ships as a package

SELinux policy is code. It is also the single source of truth for what processes can touch on a host. The two delivery paths you will meet are:

1. **A compiled `.pp` copied into `/var/lib/selinux/targeted/custom/`** — reachable by anyone who SSH-in-ed, loaded with `semodule -i`, never auditable, never roll-backable.
2. **A signed RPM that installs the `.pp`, registers ports and labels, and pulls the policy back on the next boot** — reachable by `dnf`, audit-tracked, downgrade primitive.

The rule that production hosts do not carry the repository (see `docs/admin/203-RHEL_TWO_HOST.md` and `docs/admin/304-ADOPTION_CHECKLIST.md` — "production host: no git clone; `selinux_ops_from_package: true`") exists for a reason. If policy reaches the host as a tarball of your `selinux/` directory, the chain-of-custody question becomes "who compiled this, from which `.te`, on which box?" If it reaches as an RPM signed with `SELINUX_GPG_NAME`, the answer is `rpm -Kv dist/*.rpm` (verifies the signature and the package digest) plus `rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'`, and the repo at `SELINUX_RPM_REPO` keeps the signed artefact.

The practical differences are:

| Property | `scp` + `semodule -i` | RPM |
|----------|----------------------|-----|
| Reproducibility | "it compiled once on the box I remember" | `rpmbuild` rebuilds to identical artifact from identical source + `modver` |
| Versioning | manual, fragile | `%{modver}` derived from `selinux/<app>/policy_version.txt` — single source of truth |
| Rollback | "unload and hope nothing broke" | `rpm -e` triggers `%postun`; downgrade installs older `.pp` |
| Install surface | every SSH key on the host | `dnf` against the internal repo, key-trusted |

:::: why Why not keep a repo clone on prod?
A `git clone` on prod lets you `tail -f selinux/myapp.te` and hot-fix a rule at 2am. That is exactly what SELinux is designed to suppress: a developer in the box. The playbook owns the deploy. The RPM owns the binary on the host. The host only ever sees the artifact, not the source tree.
::::

## The two-package split

Two RPMs exist for each application:

| Package | Purpose | Who installs it |
|---------|---------|-----------------|
| `selinux-policy-ops` | shared operator tooling — scripts that run canary, soak, monitor, and report | every production host, regardless of which application is on it |
| `<app>-selinux` (e.g. `shopapi-selinux`, `myapp-selinux`) | one application's compiled module + manifest + types | only the host running that application |

The split exists because the **operator tooling** is generic (it queries AVC, verifies `file_contexts`, computes soak net-new, checks readiness) and lives under `%{_libexecdir}/selinux-policy-ops`. It does not need to know about your app's port or domain. The **application module** carries your policy, your manifest, and your ports; it is the per-app artefact.

`selinux-policy-ops` depends on `setools-console` (so the playbooks can query policy for the operator), and the per-app specs `Requires: selinux-policy-ops >= 1.0.0` so the operator tooling must be present before you load your module.

## What each spec packages

Every per-app spec (`packaging/shopapi-selinux.spec`, `packaging/myapp-selinux.spec`) follows the same pattern. The material shipped:

| Source index | File | Purpose |
|-------------|------|---------|
| `Source0` | compiled `.pp` | the binary policy that SELinux loads |
| `Source1` | `.te` | source type-enforcement, shipped as `%doc` |
| `Source2` | `.fc` | source file contexts, shipped as `%doc` |
| `Source3` | `selinux-manifest.yml` | the manifest-derived port + path declarations, shipped as `%config(noreplace)` under `/etc/<app>/` |

The `.pp` lands at `%{_datadir}/selinux/packages/<app>.pp` — the path `%selinux_modules_install` reads during `%post` to load the module into the loaded-policy database. The manifest becomes a config file under `%{_sysconfdir}/<app>/selinux-manifest.yml`, which the operator scripts read via `app_manifest_path`.

The `Requires(post)` for each app spec are `policycoreutils` and `selinux-policy-base` — tools the box already has, but the RPM wants to declare they were the ones that produced the module on the build host.

The `%post` scriptlet of each app RPM does three things:

1. `%selinux_modules_install -s targeted <app>.pp` — loads the compiled module into the running policy.
2. `semanage port -a/-m` — registers each port listed in the manifest with its type (e.g. `shopapi_port_t` on TCP 8091, `myapp_port_t` / `myapp_backend_port_t` on 8888 / 8889).
3. `|| true` — survives missing `semanage` so the host is not blocked.

The `%postun` scriptlet removes the module only on an explicit erase — `if [ $1 -eq 0 ]` is true for `rpm -e` and false for `rpm -U`. This is the rollback primitive. If the operator or the playbook issues `rpm -e`, all SELinux state that came with the package is rolled back.

:::: note The %postun conditional
`$1` in a scriptlet is the number of instances of the package that will remain after the transaction: `0` on erase, `1` or more on upgrade. So `if [ $1 -eq 0 ]` uninstalls the module only when the package is really going away — during an upgrade the module is left to be replaced by the new `%post`. There is no `%{?_upgrading}` macro here; the numeric argument is the idiom.
::::

## Building RPMs

`packaging/build_rpms.sh` is the single build driver. It does the following:

1. Verifies `rpmbuild` is available. If it is not (e.g. on macOS), the script defers to `scripts/build_rpms_on_dev.sh`, which SSHes into `rhel-qa` (`DEV_HOST` defaults to `192.168.64.6`) and runs the build remotely, then `rsync`-copies the RPMs back to `dist/` on the controller.
2. Reads the version from `selinux/policy_version.txt` for `myapp` and from `selinux/shopapi/policy_version.txt` for `shopapi` — via `scripts/lib/version.sh` (`policy_version` helper) and stashes it into `--define "modver …"`. The spec does not hardcode its version; the text file is the single source of truth.
3. Builds the `%prep` tree: copies scripts into `rpmbuild/BUILD/selinux-policy-ops-src/lib/`, the CLI under `lib/pac_cli/`, and the per-app `.pp`/`.te`/`.fc`/manifest into `SOURCES/`.
4. Calls `scripts/validate_rpm_ops_parity.sh` before each build.
5. Calls `scripts/compile_and_validate.sh` against the source trees, then runs `rpmbuild -ba` for each spec in turn.
6. Copies every produced `.rpm` into `dist/` and lists it.

What it requires on the host: `rpmbuild`, the SELinux policy toolchain (`make` / `checkmodule` / `semodule_package`), and `scripts/lib/version.sh` reachable from the workspace root. If `rpmbuild` is missing and `BUILD_RPMS_LOCAL` is not set, it falls through to the remote-dev path.

## Publishing

`packaging/publish_internal.sh` signs every RPM in `dist/` with the GPG key named by `SELINUX_GPG_NAME` (set in `packaging/internal.env`, copied from `internal.env.example`), then copies them into `SELINUX_RPM_REPO` (the file directory served by `httpd` / Pulp / Satellite as a yum repo) and refreshes metadata with `createrepo_c` or `createrepo`.

`packaging/internal.env.example` is the single piece of configuration:

```bash
SELINUX_RPM_REPO=/var/www/html/selinux-pac
SELINUX_GPG_NAME=selinux-pac
```

`packaging/publish_internal.sh` reads this env, signs the artefact, and prints the `.repo` snippet you place on each RHEL host: a `[selinux-pac]` section on `baseurl=https://yum.example.internal/selinux-pac`, `gpgcheck=1`, keyed by `RPM-GPG-KEY`. Nothing under `ansible/` reads this file — the playbooks install from whatever repo the inventory's hosts are already configured against, so the `.repo` file is an admin step, not a playbook step.

::: try Inspect a spec from your own box
On `rhel-qa` (or any host with `rpm-build`) — and only if `rpmbuild` is installed, otherwise say so explicitly rather than pretending:

```bash
$ rpm -q --specfile /home/ansible/selinux-pac/packaging/shopapi-selinux.spec
```

Without `rpmbuild`, `packaging/build_rpms.sh` takes a shortcut — and which shortcut depends on the host. On Linux it prints `Note: rpmbuild not found; validating spec parity only`, runs the parity script, and exits 0. On macOS it `exec`s `scripts/build_rpms_on_dev.sh`, which rsyncs to the dev host and builds there. Neither is what you want if you only want to read the spec: the parity script is its own command.

```bash
$ bash scripts/validate_rpm_ops_parity.sh
OK selinux-policy-ops sources match packaging spec allowlist
```

The script is the single guard on the ops package: it holds a fixed allowlist of the scripts and `scripts/lib` files that `selinux-policy-ops.spec` must declare, and it fails loudly when a listed source is missing from the tree or from the spec (`MISSING source: …`, `SPEC missing script: …`). It is an allowlist, not a discovery pass — a script you add to `scripts/` is not covered until you add it to the list *and* the spec.
:::

## Versioning and upgrades

The module version travels with the RPM as `%{modver}`. It is not chosen by the packager; it is read at build time from `selinux/<app>/policy_version.txt`. That text file is updated whenever the `.te` changes — each PR that lands a rule increment bumps the number, and the RPM rebuilds against the new value.

What an upgrade does:

1. `%post` installs the new `.pp` (`%selinux_modules_install` runs `semodule -i`) — the policy store keeps **one module per name**, so the new ruleset replaces the old in place. No `semodule -r` is needed and none is run.
2. `semanage port -m` updates each port type to the new mapping declared by the manifest.
3. `%posttrans` re-applies relabels (`%selinux_relabel_post`) so the on-disk state matches the new policy.

What a downgrade does:

1. `dnf downgrade` (or `rpm -Uvh --oldpackage`) runs the older package's `%post`, which installs the older `.pp` over the newer one — the same in-place replace. There is no window where two versions of the module are loaded, and nothing to reload afterwards for the rules to change.
2. `rpm -e` triggers `%postun`, which unloads the module and drops the ports — the rollback primitive referenced in Chapter 20.
3. `dnf history rollback` undoes the whole transaction, policy and packages together, when the operator wants the host back at an earlier exact state.

The rollback primitive is not theoretical: a mis-compiled `.pp` that grants `write` on `shadow_t` can be fully rolled back, the policy un-loaded, the ports deregistered, and a new NVR built — all from `dnf`, without touching the box's policy database by hand.

## Who does what

This table summarises the lifecycle each artefact lives under:

| Artifact | Built by | Installed where | Updated by | Rolled back by |
|----------|----------|-----------------|------------|----------------|
| `selinux-policy-ops` RPM | `packaging/build_rpms.sh` on rhel-qa (or controller via `build_rpms_on_dev.sh`) | every production host (`ansible.builtin.dnf: name: selinux-policy-ops`) | `rpm -U` against the internal repo | `rpm -e` → `%postun` wipes the scripts |
| `<app>-selinux` RPM | `packaging/build_rpms.sh`, `modver` from `policy_version.txt` | only the host running that app | `rpm -U` after each PR that bumps `policy_version.txt` | `rpm -e` → `%postun` unloads module, drops ports |
| `policy_version.txt` | `selinux/<app>/` in each app repo | never on prod | git PR on the app repo | git revert, paired with `rpm` rebuild |
| Signed RPM payload | `packaging/publish_internal.sh` with `SELINUX_GPG_NAME` (`rpmsign --addsign`) | `dist/*.rpm` before publish | the RPM repo mirrors the signed artefact | publish the previous NVR again (`dnf downgrade` on the host) |
| Internal yum repo | `httpd` / Pulp / Satellite at `SELINUX_RPM_REPO` | each production host's `/etc/yum.repos.d/` | each new `publish_internal.sh` run | repo rotation: the previous NVR stays resolvable |

:::: warn Never install a locally built module on production
`semodule -i` on a host you compiled yourself is the single most common mis-step in this codebase. If you cannot name the source of the `.te` you compiled, you cannot roll back, you cannot verify parity, and you cannot rebuild against `modver` later. The rule is: `rhel-qa` compiles; `rhel-prod` consumes RPMs.
::::

:::: warn Never `semodule -i` a file you cannot name the source of
This is the corollary. Every time an RPM is skipped and a `.pp` is loaded by hand, the host loses the upgrade path. Upgrade becomes "apply rules by hand to the running policy, hope the permissive flag is the right one." Rollback becomes "reboot and hope nothing was cached." Live `.pp` files on prod hosts are the failure mode Chapter 20 plans for.
::::

## What you can do now

- [ ] Inspect `packaging/build_rpms.sh` on rhel-qa — confirm the `rpmbuild` path and the `BUILD_RPMS_LOCAL` escape hatch.
- [ ] Run `bash scripts/validate_rpm_ops_parity.sh` once — it exits 0 with a single `OK` line when the allowlist matches, and names the missing file by path when it does not.
- [ ] Verify every per-app spec names every `.pp` source: `grep -E '^Source[0-9]' packaging/<app>-selinux.spec`.
- [ ] Bump `policy_version.txt` in your app's `selinux/` directory; rebuild with `packaging/build_rpms.sh`; confirm the new NVR appears in `dist/`.
- [ ] Point an Ansible controller at your internal repo and run `install_packages.yml` — watch `selinux_ops_from_package: true` flip the decision from `semodule -i` to `dnf`.
