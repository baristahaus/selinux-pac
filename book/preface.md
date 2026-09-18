# Preface

> This book exists because of one sentence that every RHEL administrator has heard: "SELinux is
> blocking the service, we turned it off to get the release out." The service came back. The
> confinement did not — and nobody could say what the host was still protecting.

## Why this book exists

There are two ways to be bad at SELinux, and both are common in production.

The first is to **disable it**. `setenforce 0` at boot, `SELINUX=permissive` in
`/etc/selinux/config`, done. The host now runs a kernel security module that logs what it would
have blocked and blocks nothing. Worse, re-enabling it later relabels the entire filesystem; on
a real host that is a maintenance window, so the setting survives change control.

The second is to **paper over it**. A denial appears, someone pipes `audit2allow` into
`semodule -i`, the denial stops, and the module now lives on one host. It is not in git, not
reviewed, not reproducible, and it is invisible to the next administrator — until it either
grants access nobody intended or is silently dropped during a rebuild.

This book is the third path: **treat policy as code**. A denial is a question the kernel asked.
Answer it with a small module, generated from the evidence in `audit.log`, tested offline,
reviewed like application code, and promoted by a pipeline rather than a shell.

::: why The point of the pipeline
The goal is not "fewer SELinux problems". It is that every rule you ship has observable evidence
behind it, exists in git with a reviewer, can be tested without a SELinux host, and can be
withdrawn at 02:00 without disabling the operating system's confinement. Chapters 13–21 build
exactly that.
:::

## What "security as code" means in this book

Five rules, applied consistently. They are also the rules the companion repository enforces in CI.

| Rule | What it looks like in practice |
|---|---|
| **Evidence first** | A rule is added because an AVC said so, not because it *might* be needed. `audit2allow` is an input to a process, never the process. |
| **Everything in git** | `.te`, `.fc`, port assignments (`selinux_ports`), and the app manifest describing paths and services are all reviewed artifacts. |
| **Small, named, reviewable** | Dedicated types per application (`shopapi_t`, `shopapi_var_lib_t`), never wildcards, never `bin_t:file execute`, never a broad `var_t` write. |
| **Testable without a host** | Golden fixtures: `avc.log` in, expected verdict and access delta out. `make check` runs them on a laptop in seconds. |
| **Promoted by a pipeline** | Signed RPMs, a canary that makes only the app domain permissive, a soak that compares net-new access to installed policy, then enforce with a change ticket. |

## Who this book is for

**Application developers** will learn which of their own habits cause denials — installing into
`/opt` and writing to `/tmp` — and how to produce a policy change their security team can accept
without a meeting.

**RHEL administrators** will learn the module lifecycle, the difference between a lab and
production, and how to answer the question a change board actually asks: *what happens if this
is wrong, and how do you undo it?*

**Neither** needs prior SELinux experience. Chapter 2 and Chapter 3 assume only that you have
used `ls -l` and `ps`.

## Conventions used in this book

```text
$ command        run as your normal user (repo checkout, controller laptop)
# command        run as root on a SELinux host (rhel-qa, rhel-dev, rhel-prod)
```

| Convention | Meaning |
|---|---|
| `rhel-qa` | the host where you generate and test policy — the only host with a git checkout that compiles policy |
| `rhel-prod` | the production-shaped host: RPMs and Ansible only, **no git clone** |
| controller | the Ansible controller (a laptop is fine; macOS included) |
| Boxes like this | A callout: intent (`why`), procedure (`how`), a runnable exercise (`try`), a hazard (`warn`), or expected output (`good`) |
| `chapter-name.md#anchor` | A cross-reference; every link in this book is checked at build time |

::: warn Permissions and privilege
Commands marked `#` change policy, labels booleans, or ports on a host. Nothing in Part III or
Part IV asks you to run such a command on production. If a chapter ever seems to, re-read it —
chapter 20 is the only place that touches a live host, and it does so through Ansible.
:::

## What you need

You need a repository checkout and, for about half the chapters, a RHEL-family host (RHEL,
CentOS Stream, or Fedora) with SELinux enabled. [Your Lab](lab.md) covers three setups,
including one that needs no Linux host at all:

- **Laptop only** — the offline fixture suites. Enough for Parts I, III and the review chapters.
- **One RHEL host** — the full generate/policy/incident loop.
- **Two RHEL hosts plus a controller** — the pipeline of Part IV: canary, soak, enforce, rollback.

## How this book is tested

Every listing that claims to be runnable was executed while writing. Two mechanisms keep that
honest:

1. `make check` runs the generator against `docs/examples/fixtures/deterministic/` and compares
   each result to its `expected.json`. A claim about the generator's behaviour is a failing test
   if the code changes.
2. The book itself is built and validated: internal links, anchors, and every `repo:` reference
   to a file in the repository must resolve, or the build fails.

If you find a claim the repository contradicts, the repository is right and the book has a bug.
