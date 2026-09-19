# SELinux PaC

**The RHEL admin tool for shipping SELinux policy as code.** Developers open a PR, CI rejects dangerous allows (`forbidden-patterns`), admins compile and publish a signed RPM, **Ansible Automation Platform (AAP)** canaries, soaks, and enforces. The host stays **Enforcing**. Policy is a versioned product — not a one-off `audit2allow` on a box.

The **customer talk** is **202** — three applications (vendor Tomcat already enforcing, inherited Tomcat you tune, Spring Boot you generate). Finish **[101](docs/training/101-SELINUX.md)** first. The two-host generate/canary/soak pipeline is **203** (**shopapi**). Offline `make check` uses **deterministic fixtures** (`selinux/myapp.te`, `config/myapp.manifest.yml`) plus shopapi/payments modules — not a live Flask app. This tool repo is the generator, CI helpers, and AAP path. Numbered catalog: [docs/README.md](docs/README.md).

> **The book.** *SELinux for Developers and Administrators* — a full HTML manual built from this repository, from one denial to a reviewed module in production. `make book` builds it into `site/`, `make book-serve` reads it at `http://127.0.0.1:8080` (`BOOK_HOST=0.0.0.0 BOOK_PORT=9000 make book-serve` to open it from another device on your network — it prints the address), `make book-check` validates every link, anchor and repository reference. Sources live in [`book/`](book/), the guide for adding chapters is [book/AUTHORING.md](book/AUTHORING.md), and `.github/workflows/book.yml` publishes it to GitHub Pages.

| You are | Start here |
|---------|------------|
| **Reading the book** | `make book-serve`, or the published site (GitHub Pages, `book.yml` workflow) |
| **Writing a chapter** | [book/AUTHORING.md](book/AUTHORING.md) + [book/book.toml](book/book.toml) |
| **New to SELinux** | **[101](docs/training/101-SELINUX.md)** → **[102](docs/training/102-SELINUX_BASICS.md)** → **[202](docs/training/202-DEMO_GUIDE.md)** |
| **RHEL admin (customer env)** | [Admins: your environment](#admins-your-environment) |
| **Trying this on a Mac** | [Try it on a Mac](#try-it-on-a-mac) |
| **Application developer** | [Developers](#developers) and **[206](docs/developers/206-ONBOARDING.md)** |
| **Offline check (any laptop)** | `make check` (**205**) |

---

## Why this exists

SELinux is how RHEL actually confines an app. Turning it off (`setenforce 0`), flipping the whole OS to Permissive, or piping `audit2allow` into `semodule -i` on prod “unblocks” the service and **throws away the confinement**. Admins then own an unreproducible module that never went through review.

This tool is the other path: **policy-as-code for admins and developers together.**

| Without this tool | With this tool |
|-------------------|----------------|
| App team pastes AVCs into a ticket; admin writes `.te` by hand | Developer runs a **deterministic generator** on rhel-qa; humans merge |
| Bind ports and labels drift per environment | Ports live in the **committed manifest**; canary registers them with `seport` |
| Duplicate cron AVCs look like a failed soak | Soak gates **net-new** access vs installed policy (`sesearch`) |
| Prod is a git clone and a hope | **No git on prod** — signed RPMs + AAP playbooks only |
| Enforce is a Friday `semanage` | AAP **Promote to enforce** with a **change ticket** and an approval node |
| Outage → `setenforce 0` | AAP **Rollback** (domain permissive, optional RPM downgrade) → new PR |

**What you keep:** `getenforce` **Enforcing** at all times. Only the **app domain** is permissive during canary soak. That is the model a RHEL admin will accept.

---

## How this differs from Ed Qual’s enablement lab

SELinux PaC was built after looking at [Ed Qual’s automate-selinux](https://github.com/stoleas/automate-selinux) (AAP + Event-Driven Ansible + Orchestrator). That project is strong at **unblocking a host that is already failing** in production: collect AVCs, route, approve, apply a local fix (`fcontext` / port / boolean, or a live module). It is an **ops response** loop.

**SELinux PaC shifts policy creation left.** Developers generate policy from AVCs on rhel-qa, open a **PR**, CI and CODEOWNERS review it, admins ship a signed RPM, AAP **canaries**, **soaks** (net-new vs installed policy), then **enforces** with a change ticket. A denial after ship is another PR — not `semodule -i` on the box.

Those are complementary, not substitutes: his loop detects and routes; this tool authors and ships reviewed policy.

---

## Value

- **Developers own the allow list in git.** `.te` / `.fc` / `selinux_ports` are reviewed like application code. CI blocks `shadow_t`, wildcards, `bin_t` execute, and the rest of the forbidden set.
- **Admins own production mutation.** The only control plane is AAP (same YAML on a laptop until the project is imported). Execution nodes SSH in; they never clone this repo onto prod.
- **AAP is the promotion path, not an auto-fixer.** Workflows: **Release canary** → scheduled **Soak monitor** → **Promote to enforce** (Soak status → approval → Enforce). A denied file or port becomes a **PR**, not a click that patches the live host. ([docs/admin/303-DENIAL_RESPONSE.md](docs/admin/303-DENIAL_RESPONSE.md))
- **Soak is evidence, not a calendar sticker.** Daily net-new vs the installed module. Fail closed if `sesearch` is missing (`setools-console` is an RPM require).
- **Break-glass is still gated.** `force_enforce` defaults false and still needs `change_ticket`. Rollback does not require an API key.

---

## Shipping loop

```mermaid
flowchart TD
  subgraph developer [Developer on rhel-qa]
    avc[App hits a denial]
    gen[deterministic_gen.py]
    pr[PR: forbidden-patterns CI]
    avc --> gen --> pr
  end

  subgraph platform [Admin controller]
    rpm[Signed RPM repo]
    aap[AAP Automation Controller]
    pr --> rpm --> aap
  end

  subgraph production [rhel-prod — host Enforcing]
    canary[Release canary]
    soak[Soak monitor daily]
    promote[Promote to enforce]
    aap --> canary --> soak
    soak -->|net-new is 0| promote
    soak -->|net-new found| avc
  end

  promote -->|outage| rollback[Rollback]
  rollback --> avc
```

**Release canary** installs the module and puts **only** `myapp_t` (or your domain) in the permissive list. **Soak monitor** is a schedule, not a fake wait node. **Promote to enforce** is Soak status → human approval → Enforce. Objects: [ansible/aap/](ansible/aap/).

```text
QA       AVC → generator → PR (CI + CODEOWNERS)
Admin    compile_and_validate.sh → signed RPMs → internal yum/dnf
Prod     Release canary → Soak monitor → Promote to enforce
```

---

## Admins: your environment

Fork the repo and wire it to **two RHEL boxes** plus **AAP**. There is no one-click datacenter installer; this is the customer path. Full checklist: [docs/admin/304-ADOPTION_CHECKLIST.md](docs/admin/304-ADOPTION_CHECKLIST.md). Doc index: [docs/README.md](docs/README.md).

| Follow | For |
|--------|-----|
| **[304](docs/admin/304-ADOPTION_CHECKLIST.md)** | CODEOWNERS, CI, signed RPM repo, AAP objects |
| **[203](docs/admin/203-RHEL_TWO_HOST.md)** | QA box + prod box; **no git clone on prod** |
| **[301](docs/admin/301-ANSIBLE_OPERATIONS.md)** | Playbooks and extra-vars |
| [ansible/aap/README.md](ansible/aap/README.md) | Click-create job templates + **Release canary** / **Promote to enforce** |
| **[302](docs/admin/302-PRODUCTION_READINESS.md)** | Soak, enforce, rollback |
| **[303](docs/admin/303-DENIAL_RESPONSE.md)** | File/port denied after ship → PR, not live `semodule -i` |

**Scripts** (run from the controller — laptop or AAP execution node):

```bash
# write — create gitignored inventories (SSH host, soak days, RPM vs git checkout)
bash scripts/setup_rhel_hosts.sh write --qa-host rhel-qa.example.com --prod-host rhel-prod.example.com
# ping — Ansible SSH reachability to both boxes
bash scripts/setup_rhel_hosts.sh ping
# doctor — SELinux tools present (getenforce / ausearch / sesearch)
bash scripts/setup_rhel_hosts.sh doctor
# bootstrap — print (do not run) SSH steps for rhel-qa only
bash scripts/setup_rhel_hosts.sh bootstrap
# next app after the shopapi demo
bash scripts/selinux_pac_adopt.sh init payments     # see 206-ONBOARDING.md

# Package + publish (see packaging/internal.env.example)
bash packaging/build_rpms.sh                        # selinux-policy-ops + shopapi-selinux (demo) + myapp-selinux (test fixture)
bash packaging/publish_internal.sh                  # copy into your internal yum/dnf repo

# Same playbooks AAP workflows run
ansible-playbook -i ansible/inventory.production.yml ansible/deploy_canary.yml --limit canary
#   install module, shopapi_t permissive, HTTP probes, start soak clock
ansible-playbook -i ansible/inventory.production.yml ansible/soak_monitor.yml --limit canary
#   schedule daily in AAP — fail if net-new AVCs vs installed policy
ansible-playbook -i ansible/inventory.production.yml ansible/soak_status.yml --limit canary
#   read-only: days elapsed, AVC counts, fail_closed
ansible-playbook -i ansible/inventory.production.yml ansible/enforce_production.yml \
  -e change_ticket=CHG123
#   soak gate then remove permissive; needs change_ticket
```

Rollback: `ansible-playbook -i ansible/inventory.production.yml ansible/emergency_rollback.yml --limit canary`

Install `selinux-policy-ops` + `<app>-selinux` from a **signed internal repo**. Compile policy on RHEL with `selinux-policy-devel`. Playbooks: [ansible/README.md](ansible/README.md).

---

## Try it on a Mac

macOS has **no SELinux**. The Mac is the **Ansible controller**; policy still runs on Linux.

**Preferred — two RHEL VMs (Apple Silicon: aarch64 Boot ISO in UTM), then the same admin scripts.** Run these from **repo root on the Mac** (the Ansible controller). They do **not** install SELinux on macOS.

| Command | What it does | Good sign |
|---------|----------------|-----------|
| `bash scripts/setup_rhel_hosts.sh write --qa-host 192.168.64.6 --prod-host 192.168.64.5` | Writes gitignored `ansible/inventory.dev.yml` and `ansible/inventory.production.yml` with those SSH IPs. QA gets `soak_min_days: 0` (lab). Prod gets `soak_min_days: 7` and **no git clone** (`selinux_ops_from_package: true`). | Prints `Wrote …/inventory.dev.yml` and `…/inventory.production.yml` |
| `bash scripts/setup_rhel_hosts.sh ping` | Ansible `ping` module over SSH to both VMs (can the controller reach them?). | `SUCCESS` / `pong` for `rhel-qa` and `rhel-prod` |
| `bash scripts/setup_rhel_hosts.sh doctor` | On each VM (as sudo): hostname, `getenforce`, `ausearch`, `sesearch`. Prod also checks `selinux-policy-ops` and **does not fail** if that RPM is not installed yet. | `Enforcing`; paths to `ausearch` and `sesearch`. Prod may print `selinux-policy-ops: not installed (expected before RPMs)` |
| `bash scripts/setup_rhel_hosts.sh bootstrap` | **Prints** the SSH/`dnf`/`demo_bootstrap.sh --shopapi-only` commands for **rhel-qa only**. It does not run them. | A block starting `=== Bootstrap the QA RHEL box` |
| `bash scripts/sync_rhel_dev.sh` | rsync this checkout to `~/selinux-pac` on rhel-qa (shopapi lives here). | `Synced … -> ansible@192.168.64.6:selinux-pac/` |
| `bash scripts/reset_demo_vms.sh` | Between rehearsals: unload leftover `shopapi` modules and prod RPMs; untune App B (port 8090 / `/opt/appdata` / connect boolean). JVM stays. Restore the types-only `selinux/shopapi/` seed. | `Good: no shopapi (or leftover myapp) module loaded` on both VMs |

Those IPs are this Mac’s UTM shared network (`rhel-qa` = `192.168.64.6`, `rhel-prod` = `192.168.64.5`). Re-check with `ping` if a VM was recreated.

**You are not done.** `bootstrap` only printed the next commands. Run the paced lab from **[203](docs/admin/203-RHEL_TWO_HOST.md)** (plain-language, one computer at a time), especially [Present this lab (three terminals)](docs/admin/203-RHEL_TWO_HOST.md#present-this-lab-three-terminals). Re-run on the same VMs: `bash scripts/reset_demo_vms.sh`, then the Mac conductor.

**Before the talk (101):** [docs/training/101-SELINUX.md](docs/training/101-SELINUX.md) (one host, shopapi). Then pick **one** demo:

| Talk | Audience | Setup | Length | Start |
|------|----------|--------|--------|-------|
| **202** | Customer / first conversation | One RHEL host | ~20 min | `bash scripts/demo_present.sh` |
| **203** | Technical deep dive | Mac + rhel-qa + rhel-prod | ~45 min | `bash scripts/demo_e2e_mac.sh` |

`--help` on each script names the other. Do not run `demo_e2e_mac.sh` as the first customer conversation.

**202 customer talk:**

```bash
bash scripts/demo_present.sh --dry-run --profile customer   # any laptop
make demo-bootstrap                                        # RHEL VM, once
bash scripts/demo_present.sh --preflight
bash scripts/demo_present.sh --profile customer
```

See **[202](docs/training/202-DEMO_GUIDE.md)**. Already-tuned App B (second run): `bash scripts/reset_demo_vms.sh --dev-only`.

**203 three-host pipeline:** three Terminal windows. The Mac script is the conductor; press Enter between steps.

| Window | Start |
|--------|--------|
| Mac | `cd /Users/asaran/projects/selinux-pac` then `bash scripts/demo_e2e_mac.sh` |
| rhel-qa | `ssh ansible@192.168.64.6` — run the `--part` the Mac prints (`app`, then `generate`, later `--skip-export`) |
| rhel-prod | `ssh ansible@192.168.64.5` — run the `--part` the Mac prints (`app`, `rpms`, `soak`, `soak-avc`, `fail`, `restore`, `retest`) |

Unattended rehearsal: `bash scripts/demo_e2e_mac.sh --auto --no-type`. Talk-only: `--dry-run`. Policy PRs: `gh auth login` with push access to **this** repo (`selinux/shopapi/`). CI `forbidden-patterns` should go green (`validate_forbidden_patterns.sh` already ran at generate time).

Lab enforce uses `soak_min_days: 0` on **QA only** — never copy that onto prod. The paced talk uses `force_enforce=true` plus a change ticket on prod so a **clean** soak can be treated as complete; `inventory.production.yml` stays at 7 days.

---

## Developers

Training before the three-app talk: **[101](docs/training/101-SELINUX.md)**.

On **rhel-qa** (repo checkout, SELinux Enforcing):

```bash
sudo bash scripts/demo_bootstrap.sh --shopapi-only   # Spring Boot on rhel-qa
sudo bash scripts/dev_generate_policy.sh --apply --app-name shopapi --app-root "$(pwd)"
bash scripts/assemble_pr_body.sh
gh pr create --body-file policy_out/pr_body.md --label security --label selinux
```

The generator classifies the denial: **file** → `.fc` + `restorecon`; **port** → `selinux_ports` in the manifest; **boolean** → host `setsebool` (not in the RPM); **new allow** → `.te` under CI forbidden-patterns. It does not auto-edit production.

CI must pass `forbidden-patterns` and `version-consistency` (the generator already ran the same forbidden-pattern check). Compile on rhel-qa with `compile_and_validate.sh`. CODEOWNERS (`@anurag-saran`) review `selinux/` and `ansible/`.

New app: `bash scripts/selinux_pac_adopt.sh init payments` — **[206](docs/developers/206-ONBOARDING.md)**.

Ports stay in the committed manifest (`selinux_ports`). Probe host/IP is per inventory (`http_probe_host`).

---

## Layout

```text
config/       App manifests (bind ports, probes, domains)
selinux/      Policy source of truth (.te/.fc, policy_version.txt)
ansible/      selinux_pac role + aap/ Controller workflows
packaging/    selinux-policy-ops + <app>-selinux; publish_internal.sh
scripts/      setup_rhel_hosts.sh (admins), demo_e2e_*.sh (three-window lab talk track)
docs/training/    101 labs, 102 basics, 103 recap, 201 walkthrough, 202 talk
docs/admin/       203 two-host, 301–304 ship/run
docs/developers/  204 generator, 205 tests, 206 onboarding
docs/policy/      207 best practices
```

---

## Safety

- Never `force_enforce` without a change ticket. Never copy `soak_min_days: 0` from `inventory.dev.yml` onto prod (enforce refuses it on the `production` group). The three-window demo may pass `force_enforce=true` with `-e change_ticket=DEMO` so the talk can finish.
- If a file or port is denied after ship: [docs/admin/303-DENIAL_RESPONSE.md](docs/admin/303-DENIAL_RESPONSE.md) — PR + recanary, not live `semodule -i`.
- Optional LLM polishes `pr_summary.md` only. Legacy `--legacy-full-policy` is emergency/controller-only.
- AAP is the control plane (RPMs, `serial: 1`). Do not `semodule -i` generated policy on prod.
