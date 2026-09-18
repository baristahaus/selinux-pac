# SELinux PaC documentation

Guides are numbered like a course. **100** = learn, **200** = demo and develop, **300** = ship.

> **The book.** *SELinux for Developers and Administrators* is the long-form manual built from this repository: twenty-five chapters from one denial to a reviewed module in production, plus reference appendices. Its sources are in [`../book/`](../book/), it is validated by `make book-check` (part of `make check`), and [`.github/workflows/book.yml`](../.github/workflows/book.yml) publishes it to GitHub Pages at `https://anurag-saran.github.io/selinux-pac/` once Pages is enabled in the repository settings. Writers start at [`../book/AUTHORING.md`](../book/AUTHORING.md).

| Band | Meaning | Start |
|------|---------|--------|
| **100** | Labels, one AVC, generate a module | **[101](training/101-SELINUX.md)** then **[102](training/102-SELINUX_BASICS.md)** |
| **200** | Three-app talk, two-host lab, generator, new apps | **[202](training/202-DEMO_GUIDE.md)** (after 101) |
| **300** | AAP, soak, incidents, org rollout | **[301](admin/301-ANSIBLE_OPERATIONS.md)** |

| Pattern | Meaning |
|---------|---------|
| **Why** | What real problem this step solves |
| **Where** | Which machine and directory (controller vs RHEL server vs repo root) |
| **What / good sign** | What the command does and how you know it worked |

**Terms** like domain, AVC, `.te`, and **`semanage`** are defined in **[102](training/102-SELINUX_BASICS.md)**.

| You are | Start here |
|---------|------------|
| **New to SELinux** | **101** → **102** §1–4 if needed → **202** |
| **RHEL admin (customer env)** | **[304](admin/304-ADOPTION_CHECKLIST.md)** → **300**s below |
| **Trying this on a Mac** | [../README.md](../README.md#try-it-on-a-mac) — two RHEL VMs + `setup_rhel_hosts.sh` |
| **Laptop only (no VM)** | **101** [Appendix B](training/101-SELINUX.md#appendix-b-laptop-no-selinux) + `make check` (**205**) |

---

## Catalog

### 100 — Learn

| # | Guide | You need |
|---|--------|----------|
| **101** | [SELinux 101](training/101-SELINUX.md) | Typed shopapi loop on **one** RHEL box |
| **102** | [SELinux basics](training/102-SELINUX_BASICS.md) | Reading primer (lab 0 is §1–4) |
| **103** | [Hands-on recap](training/103-TRAINING_LAB.md) | One-screen recap after 101; `make training-lab` is the talk dry-run |

### 200 — Demo and develop

| # | Guide | You need |
|---|--------|----------|
| **201** | [Code walkthrough](training/201-CODE_WALKTHROUGH.md) | What each folder and script is for |
| **202** | [Three-app customer talk](training/202-DEMO_GUIDE.md) | `demo_present.sh` — one host, ~20 min; finish **101** first |
| **203** | [Two Linux VMs](admin/203-RHEL_TWO_HOST.md) | `demo_e2e_*.sh` — three hosts, ~45 min |
| **204** | [Deterministic policy](developers/204-DETERMINISTIC_POLICY.md) | Offline AVC → `.te` / `.fc` |
| **205** | [Testing](developers/205-TESTING.md) | `make check`, CI, endpoints |
| **206** | [Onboarding an application](developers/206-ONBOARDING.md) | Point a developer at a new app |
| **207** | [Best practices](policy/207-SELINUX_BEST_PRACTICES.md) | What this repo accepts in a policy PR |

### 300 — Ship

| # | Guide | You need |
|---|--------|----------|
| **301** | [Ansible operations](admin/301-ANSIBLE_OPERATIONS.md) | AAP / ansible-playbook |
| **302** | [Production readiness](admin/302-PRODUCTION_READINESS.md) | Soak, enforce, rollback |
| **303** | [Denial response](admin/303-DENIAL_RESPONSE.md) | File or port denied after ship |
| **304** | [Adoption checklist](admin/304-ADOPTION_CHECKLIST.md) | CODEOWNERS, RPM repo, branch protection |

**Contributors (no SELinux on laptop):** from repo root run `make check` — **205** §1.6.

Samples (not numbered): [examples/README.md](examples/README.md). App manifest schema: [../config/README.md](../config/README.md). Ansible playbooks: [../ansible/README.md](../ansible/README.md). New app: `bash scripts/selinux_pac_adopt.sh init <app>` (**206**). Repo entry: [../README.md](../README.md).
