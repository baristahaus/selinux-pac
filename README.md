# sepac — SELinux policy as code for RHEL

`sepac` gives RHEL admins one command for an application's SELinux policy: decide whether it needs new policy at all, collect the evidence, write the smallest policy that covers it, gate it like CI, try it on QA, and ship it as a signed RPM through canary, soak and enforce. The host stays **Enforcing** the whole time. Nobody runs `setenforce 0`, and nobody pipes `audit2allow` into `semodule -i` on production.

## What it does differently

| The usual way | With sepac |
|---------------|------------|
| Write a module for every app that logs a denial | `sepac triage` checks Red Hat's shipped policy first and refuses to duplicate it. Tomcat, httpd, BIND, PostgreSQL and JBoss get tuned, not rewritten. |
| `setenforce 0`, click around, `ausearch` | `sepac capture` restarts the app with full auditing, calls every endpoint in its manifest, and separates the denials you expected from the new ones. Only the app's domain is permissive. |
| `audit2allow -M` and load whatever it prints | `sepac generate` writes the smallest policy that covers the evidence: Red Hat interfaces before raw rules, file labels before wider rules. It stops for review on domain-weakening permissions (`execmem`) and refuses forbidden ones (`/etc/passwd`, shadow, wildcards). |
| Review by eye, if at all | `sepac check` is the same gate CI runs on every policy pull request: manifest, forbidden patterns, compile, and semantic checks against a throwaway copy of the policy store. |
| `semodule -i` on production | Production only gets a signed RPM: `sepac canary` (domain permissive), `sepac soak` (net-new denials against the installed policy), `sepac enforce` (needs a clean soak and a change ticket), `sepac rollback` (domain back to permissive, host still Enforcing). |

## A new app, on the QA host

```bash
sepac init orders --port 9090                 # manifest + scaffolded policy module
sepac triage orders                           # Red Hat's policy first
sepac load orders --permissive                # labels and port; the domain only logs
sepac capture orders --full-audit             # restart, call every endpoint, summarise denials
sepac generate orders                         # stops if a domain-weakening permission needs review
sepac generate orders --approve execmem --apply
sepac check orders                            # the CI gate, on your host
sepac load orders --enforcing                 # try it enforcing on QA
sepac status orders                           # host, module, domain, process, labels, denials
```

Then open a pull request with `selinux/orders/` and `config/orders.manifest.yml`. CI runs `sepac check`.

## Ship it, where Ansible runs

```bash
sepac build && sepac publish                       # signed RPMs in the internal repo
sepac canary  --env production --limit canary      # installed, domain permissive, soak starts
sepac soak    --env production --status            # net-new denials against the installed policy
sepac enforce --env production --ticket CHG123     # only after a clean soak
sepac rollback --env production                    # domain back to permissive; no setenforce 0
```

The same playbooks run as **Ansible Automation Platform** jobs (Release canary, a daily Soak monitor, Promote to enforce with an approval). See [docs/shipping.md](docs/shipping.md).

## Install

On QA hosts and the Ansible controller:

```bash
sudo dnf install selinux-pac
```

Managed hosts get `selinux-pac` from the Ansible role, which also writes `/etc/selinux-pac/role` and copies each app's manifest to `/etc/selinux-pac/apps/`. From a git checkout, run `bin/sepac` or `sudo make install-cli`.

sepac needs RHEL 9 with `python3` and `python3-pyyaml`. `generate` and `check` also need `selinux-policy-devel` and `setools-console` (the QA host); the shipping commands need `ansible-core` (the controller).

## Commands

| On the QA host | | Where Ansible runs | |
|----------------|---|--------------------|---|
| `init APP` | Manifest and a scaffolded module | `build` | Build the RPMs |
| `triage APP` | Does Red Hat already ship policy? | `publish` | Sign and publish them |
| `tune APP` | Host fixes for a vendor domain | `canary --env ENV` | Install, domain permissive, soak starts |
| `capture APP` | Restart, call endpoints, summarise denials | `soak --env ENV` | Daily soak gate (`--status`: read-only) |
| `denials APP` | The app's denials (`--why` explains) | `enforce --env ENV --ticket T` | Enforce after a clean soak |
| `generate APP` | Policy from the evidence | `rollback --env ENV` | Domain back to permissive |
| `check APP` | The CI gate | | |
| `load APP` | Load on QA (`--enforcing`, `--permissive`) | | |
| `status APP` | Where the app stands | | |

Every command takes `--dry-run` (print what would run, change nothing) and `-v`. Full reference: [docs/sepac.md](docs/sepac.md).

## Guardrails

- The host is never set permissive. Only the app's domain is, during capture on QA and during the canary soak.
- `load` refuses unless `/etc/selinux-pac/role` says `qa` or `dev`. Production gets policy only from the signed RPM.
- There is no blanket approval. `--approve PERM` names each domain-weakening permission, and the rest still stop.
- Forbidden targets (shadow, `/etc/passwd`, `setenforce`, wildcards, a raw `execute` on `bin_t`) are refused, with or without approval. The system JVM's `bin_t` execute needs a reviewed reason in the manifest.
- A port another application type owns is refused. sepac never runs `semanage port -m`.
- Policy for a vendor-covered app needs `--force "reason"`, and the reason goes on the pull request.
- `enforce` needs a change ticket. `--break-glass "reason"` skips the soak gate and records why.

## The book

*SELinux for Developers and Administrators* is a full manual built from this repository. It starts with one denial and ends with a reviewed module in production.

```bash
make book          # build the HTML into site/
make book-serve    # read it at http://127.0.0.1:8080
make book-check    # check every link, anchor and repository path
```

Sources live in [`book/`](book/). The rules for a chapter are in [book/AUTHORING.md](book/AUTHORING.md). `make check` runs `book-check`.

## Who wrote what

`@anurag-saran` started the project and writes the running parts: the generator, the policy source, Ansible, packaging, and CI. `@baristahaus` wrote the book and the tooling that builds it. Both sides used a coding agent. [AUTHORS.md](AUTHORS.md) names the split and the commit counts.

## Docs

| Read | For |
|------|-----|
| [docs/sepac.md](docs/sepac.md) | Every command, the manifest, the files on each host |
| [docs/shipping.md](docs/shipping.md) | QA → pull request → RPM → canary → soak → enforce → rollback, and a denial after ship |
| [docs/demo.md](docs/demo.md) | The customer demo, command by command (`bash lab/demo_present.sh`) |
| [book/](book/) | The manual: 25 chapters and three appendices |
| [docs/guides/](docs/guides/README.md) | SELinux training ([101](docs/guides/101-CONCEPTS.md) concepts → [102](docs/guides/102-COMMANDS.md) commands → [103](docs/guides/103-CONFIG-FILES.md) config files → [104](docs/guides/104-HAND-BUILT-MODULE.md) a module by hand), the two-host lab, testing, and the engine scripts behind sepac |

## Repository

| Directory | What is in it |
|-----------|---------------|
| `bin/`, `cli/` | `sepac` and the generator it drives |
| `config/`, `selinux/` | App manifests and their policy modules: the reviewed source of truth |
| `ansible/` | The `selinux_pac` role, the canary/soak/enforce/rollback playbooks, AAP objects |
| `packaging/` | RPM specs: `selinux-pac`, `selinux-policy-ops` (host scripts), one per app module |
| `scripts/` | The engine sepac runs: generator wrapper, validators, host scripts |
| `lab/` | The demos and their apps (`lab/apps/`), VM setup for the two-host lab |
| `tests/` | `make test`: offline tests and fixtures, no SELinux host needed |
| `docs/` | The three pages above, and `docs/guides/` |
| `book/`, `tools/book/` | The manual sources and its standard-library builder |
