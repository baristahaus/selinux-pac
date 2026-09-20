# Your Lab

> Half of this book needs only a checkout. The other half needs a RHEL-family host with SELinux
> in Enforcing mode. A cloud instance and a local VM both count. Pick a path now, because every
> chapter states which path it needs.

## Three ways to run everything

| Path | What you have | What works | Time to set up |
|---|---|---|---|
| **A. Laptop only** | a checkout, Python 3.11+, no Linux host | Parts I, III (generator, fixtures, CI logic), the review chapters | 2 minutes |
| **B. One RHEL host** | RHEL/CentOS Stream/Fedora, root, SELinux enabled | everything except the two-host pipeline | 15 minutes |
| **C. Two hosts + controller** | `rhel-qa` and `rhel-prod`, plus macOS/Linux driving them | everything, including canary/soak/enforce/rollback | about an hour |

::: note macOS
macOS has no SELinux and no SELinux tooling. On a Mac, the laptop is always the Ansible
controller, and policy work happens on the RHEL guest. Path A still works on a Mac, because it
never touches a kernel.
:::

## Path A — laptop only (no Linux host) {#path-a}

This is the fastest way to see what the book is about. It runs the deterministic generator
against golden fixtures and checks every policy module in the repository.

```bash title="Clone and run the offline suite"
git clone https://github.com/anurag-saran/selinux-pac
cd selinux-pac
make deps      # installs the Python requirements for the CLI
make check     # fixtures + static validators + linters; no SELinux host required
```

::: good What you will see
`make check` runs the deterministic fixture suite, the payments and blast-radius suites, the
manifest checks, the policy linting, and the book link check. You will see `make test OK`
mid-run, then the lint results. The run ends with a `book: OK (N pages, M warnings)` line, and a
healthy tree reports `0 warnings`. A missing optional linter prints `SKIP` instead of failing.
The offline contract is "no network, no root, no kernel".
:::

Run one fixture by hand to see what the book means by "a denial is a question":

```bash title="Explain one golden fixture"
python3 cli/deterministic_gen.py --explain \
  --avc-log docs/examples/fixtures/deterministic/02-port-bind/avc.log \
  --manifest config/myapp.manifest.yml \
  --existing-te selinux/myapp.te \
  --existing-fc selinux/myapp.fc
```

Then read the expected answer for the fixture, which CI compares against:

```bash
cat docs/examples/fixtures/deterministic/02-port-bind/expected.json
```

## Path B — one RHEL host (the lab host, `rhel-qa`) {#path-b}

One host with SELinux enabled is enough for Chapters 3–15 and the incident chapter. The
repository bootstraps the whole demo estate: the JVM, the Spring Boot `shopapi` service, its
systemd unit, and a types-only policy seed:

```bash title="On rhel-qa, as root"
cd ~/selinux-pac
sudo bash scripts/demo_bootstrap.sh --shopapi-only
```

That command installs the JVM and the `shopapi` unit. It labels the launcher as
`shopapi_exec_t` and starts the service under the domain `shopapi_t`. It also makes only that
domain permissive for the first labs.

::: warn The host stays Enforcing
`demo_bootstrap.sh` never runs `setenforce 0` and never sets `SELINUX=permissive` in
`/etc/selinux/config`. It uses `semanage permissive -a shopapi_t`, which affects one domain.
Check this after the run: `getenforce` must print `Enforcing`.
:::

### Checking the host before you start

Any RHEL-family host works. Four commands tell you whether the tooling in this book will run there:

```bash title="Host doctor"
# getenforce                # must print Enforcing
# which ausearch sesearch    # audit + policy query tools
# rpm -q selinux-policy-devel policycoreutils-devel   # needed to compile module
# python3 --version          # the CLI needs 3.11 or newer
```

| Missing piece | Install |
|---|---|
| `ausearch`, `aureport` (and `auditd` itself) | `dnf install audit`. Then make sure that `auditd` is running |
| `sesearch`, `seinfo` | `dnf install setools-console` |
| `selinux-policy-devel` | `dnf install selinux-policy-devel` (compile only. The generator itself does not need it) |
| `sepolgen-ifgen` interface matching | `dnf install policycoreutils-devel`, then run `sepolgen-ifgen` once |

Without `sepolgen-ifgen`, the generator still works, but it cannot match refpolicy interfaces. It
says so loudly, and it refuses base-type AVCs unless you pass `--allow-degraded`. Chapter 8
explains what that trade-off costs.

## Path C — two hosts plus a controller {#path-c}

The full pipeline uses two hosts and an Ansible controller. It generates on QA, ships by RPM, and
runs canary and soak on production. The repository scripts the whole thing:

```bash title="On the controller"
bash scripts/setup_rhel_hosts.sh write --qa-host rhel-qa.example.com --prod-host rhel-prod.example.com
bash scripts/setup_rhel_hosts.sh ping      # SSH reachability to both
bash scripts/setup_rhel_hosts.sh doctor    # SELinux tools present on both
bash scripts/setup_rhel_hosts.sh bootstrap # prints the next commands; runs nothing
```

That writes gitignored inventories (`ansible/inventory.dev.yml` for QA,
`ansible/inventory.production.yml` for production). Production deliberately carries
`selinux_ops_from_package: true` and no git checkout. The full paced walkthrough is
[203-RHEL_TWO_HOST.md](repo:docs/admin/203-RHEL_TWO_HOST.md).

## Words you need before Chapter 1

Six terms carry the whole book. If you memorize nothing else, memorize these.

| Term | Short definition | First used in |
|---|---|---|
| **Label / context** | the four-part security tag on every process and object. Its third field is the type | Chapter 2 |
| **Type** | the name of a category, for example `shopapi_t`, or a file type, for example `shopapi_var_lib_t` | Chapter 2 |
| **Domain** | the type of a *running process*. Enforcement calls it the subject | Chapter 2 |
| **AVC** | Access Vector Cache: a denial record with subject, target, class, and permissions | Chapter 4 |
| **Policy module** | the compiled unit (`.pp`, built from `.te`/`.fc`) that the kernel loads | Chapter 6 |
| **Enforcing / permissive** | block-and-log versus log-only. Per-domain permissive applies the second to one domain | Chapter 5 |

## Verify your lab

Work through this before the first chapter. It takes two minutes and prevents a whole class of
confusion later.

- [ ] `make check` prints `make test OK` and finishes with `book: OK`
- [ ] The fixture 02 explanation names the verdict `private_port`
- [ ] On a RHEL host: `getenforce` prints `Enforcing`
- [ ] On a RHEL host: `ls -Z /usr/bin/passwd` shows a type in the third field of the label
- [ ] On a RHEL host: `ps -eZ | head` shows types for running processes, not only `-`

When those five pass, [Chapter 1](part1/01-the-default-answer.md) is about a decision you probably
made once, badly.
