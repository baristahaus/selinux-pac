# Preface

> This book exists because of one sentence. Every RHEL administrator has heard it: "SELinux is
> blocking the service, we turned it off to get the release out." The service came back. The
> confinement did not come back. Nobody was able to say what the host still protected.

## Why this book exists

There are two ways to be bad at SELinux, and both are common in production.

The first is to disable it: `setenforce 0` at boot, `SELINUX=permissive` in
`/etc/selinux/config`, done. The host now runs a kernel security module. It logs every access that
a rule denies. It blocks nothing. Worse, re-enabling it later relabels the entire filesystem. On a
real host, that is a maintenance window, so the setting survives change control.

The second is to paper over it. A denial appears. Someone pipes `audit2allow` into
`semodule -i`. The denial stops, and the module now lives on one host. It is not in git, not
reviewed, and not reproducible. The next administrator cannot see it. In the end, the module
either grants access nobody intended, or a rebuild drops it silently.

This book is the third path: treat policy as code. A denial is a question the kernel asks.
Answer it with a small module. Generate the module from the evidence in `audit.log`. Test it
offline. Review it like application code. Promote it with a pipeline, not with a shell.

::: why The point of the pipeline
The goal is not "fewer SELinux problems". Every rule you ship must have observable evidence
behind it. It must exist in git with a reviewer. You must be able to test it without a SELinux
host. You must be able to withdraw it at 02:00 without disabling the confinement of the operating
system. Chapters 13–21 build exactly that.
:::

## What "security as code" means in this book

Five rules define this book. Apply all five consistently. The companion repository enforces the
same rules in CI.

| Rule | What it looks like in practice |
|---|---|
| **Evidence first** | A rule goes in only when an AVC shows that it is needed. `audit2allow` is an input to a process, never the process. |
| **Everything in git** | The `.te`, `.fc`, port assignments (`selinux_ports`), and app manifest for paths and services are all reviewed artifacts. |
| **Small, named, reviewable** | Use one dedicated type per application (`shopapi_t`, `shopapi_var_lib_t`). Do not use wildcards, `bin_t:file execute`, or a broad `var_t` write. |
| **Testable without a host** | Golden fixtures take `avc.log` in and return the expected verdict and access delta. `make check` runs them on a laptop in seconds. |
| **Promoted by a pipeline** | Ship signed RPMs. A canary makes only the app domain permissive. A soak compares net-new access to installed policy. Then enforce with a change ticket. |

## Who this book is for

Application developers will learn which of their own habits cause denials. Two examples are
installing into `/opt` and writing to `/tmp`. They will learn how to produce a policy change
that their security team can accept without a meeting.

RHEL administrators will learn the module lifecycle and the difference between a lab and
production. They will learn how to answer the question a change board asks: *what happens if this
is wrong, and how do you undo it?*

Neither needs prior SELinux experience. Chapter 2 and Chapter 3 only assume that you can use
`ls -l` and `ps`.

## Conventions used in this book

```text
$ command        run as your normal user (repo checkout, controller laptop)
# command        run as root on a SELinux host (rhel-qa, rhel-dev, rhel-prod)
```

| Convention | Meaning |
|---|---|
| `rhel-qa` | the host where you generate and test policy. It is the only host with a git checkout that compiles policy |
| `rhel-prod` | the production-shaped host: RPMs and Ansible only, no git clone |
| controller | the Ansible controller. A laptop is fine, and macOS is included |
| Boxes like this | A callout: intent (`why`), procedure (`how`), a runnable exercise (`try`), a hazard (`warn`), or expected output (`good`) |
| `chapter-name.md#anchor` | A cross-reference. The build checks every link in this book. |

::: warn Permissions and privilege
Commands marked `#` change policy, labels, booleans, or ports on a host. Nothing in Part III or
Part IV asks you to change policy on production by hand. The incident card in chapter 20 starts
with read-only reconnaissance (`getenforce`, `semanage permissive -l`, `ausearch`), then uses
Ansible. Roll back first. Then follow the same PR path as any other change. If a chapter seems to
ask for more, read it again.
:::

## What you need

You need a repository checkout. For about half the chapters you also need a RHEL-family host
(RHEL, CentOS Stream, or Fedora) with SELinux enabled. [Your Lab](lab.md) covers three setups.
One of them needs no Linux host at all:

- **Laptop only**: the offline fixture suites. This covers Parts I, III and the review chapters.
- **One RHEL host**: the full generate/policy/incident loop.
- **Two RHEL hosts plus a controller**: the pipeline of Part IV, with canary, soak, enforce, and rollback.

## How this book is tested

Every listing that claims to be runnable was executed while writing the book. Two mechanisms keep
that claim true:

1. `make check` runs the generator against `docs/examples/fixtures/deterministic/` and compares
   each result to its `expected.json`. If the code changes, a claim about the behavior of the
   generator becomes a failing test.
2. The build checks the book itself. Internal links, anchors, and every `repo:` reference to a
   file in the repository must resolve, or the build fails.

If you find a claim that the repository contradicts, the repository is right. The book has a bug.
