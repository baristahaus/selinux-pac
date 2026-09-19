# Glossary

> Every term in this book is a name for something the kernel actually checks. The glossary
> does not explain SELinux in general — each entry names the meaning each term holds in
> this book, the chapter where you first meet it, and the sentence that lets you read the
> kernel's answer.

| Term | What it means | First used |
|---|---|---|
| **AVC** | *Access Vector Cache*. The kernel's record of every policy decision — the tuple, the mode, and the permissive flag; the single most useful line in `audit.log`. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **allow rule** | The exact `allow <src_t> <tgt_t>:<class> { <perm> };` sentence the kernel reads each access decision against. Named types and named perms are what makes a reviewable rule. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **attribute** | A named collection of types: the keyword that lets a rule target every type carrying the attribute instead of naming each type. `typeattribute <src_t> <attr>;` adds the type; an allow rule reads `allow <src_t> <attr>:<class> { <perm> };`. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **base policy** | The vendor-shipped policy compiled by Red Hat into `/etc/selinux/<type>/policy/policy.<n>`. Custom application modules layer on top; the base policy never changes. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **boolean** | A policy toggle — each boolean is a switch that flips a broad allow in the base policy. Set with `setsebool -P`; never shipped in a module. | [Ports, Booleans and Transitions](repo:book/part2/10-ports-booleans-and-transitions.md) |
| **CIL** | *Common Intermediate Language*. The text representation of the compiled policy; the one humans can read when they need to review the policy XML. `sesearch` reads this directly. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **class** | The category of object the kernel decides about: `file`, `dir`, `tcp_socket`, `process`, `capability`. Each class has a fixed set of permissions; the class is what makes `write` meaningful on a file but not on a socket. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **constraint** | A CIL sentence that gates when a rule may fire: `constraint allow <src_t> <tgt_t>:<class> { <perm> } { <role> }`. Used by the vendor policy; rarely written in a module. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **context** | `user:role:type:level`. The four colon-separated fields each name a different slice of identity; only the third — the type — drives the access decision. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **DAC** | *Discretionary Access Control*. The classic Unix check — owner/group/mode bits; `chmod`, `chown`. SELinux does not consult DAC. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **domain** | The process type — the label of the running process. `myapp_t` is your app's domain; every process that runs it is constrained by its policy. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **dontaudit** | A rule that suppresses the AVC record for a tuple — the access is still **denied**, the log just stays quiet. Used by the vendor policy to silence noisy tuples; the reason `semodule -DB` exists. | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| **entrypoint** | A type-level allow: the rule that lets a domain `open`/`read`/`execute` a file (or `transition` to a process) — the single allow that lets a daemon start. | [Designing a Domain](repo:book/part2/11-designing-a-domain.md) |
| **enforcing** | The kernel mode that blocks each unmatched access — the default mode, the state you ship to production. | [Modes, and the Cost of Off](repo:book/part1/05-modes-and-the-cost-of-off.md) |
| **file context** | The policy rule that tells SELinux what label each path should have; written in `.fc`; stored at `/etc/selinux/<type>/contexts/files/`. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **gen_context** | The `.fc` directive that names the label a path should carry — `gen_context(system_u:object_r:myapp_var_lib_t,s0)`. Its arguments are the context fields, never an object class; `restorecon` uses the file as its source of truth. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **interface** | A refpolicy `.if` file — a shared macro that lets a module write `audit_file_read(myapp_t)` instead of an explicit `allow`. Each interface is a reviewable bundle of allow rules. | [Allow Rules and Interfaces](repo:book/part2/08-allow-rules-and-interfaces.md) |
| **label** | The SELinux context attached to a file or process — the answer the kernel reads each access decision against. `ls -Z` is the most useful label command. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **MAC** | *Mandatory Access Control*. The kernel-side access control: every decision is answered by the policy, not by the account. `root` does not escape MAC. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **MCS** | *Multi-Category Security*. The level (fourth field) of the context — used for compartmentalisation across categories. The book uses `s0` (unclassified) throughout. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **MLS** | *Multi-Level Security*. The broader framework that includes both sensitivity levels (the fourth field) and categories (MCS); the default RHEL policy uses `s0` only. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **neverallow** | A CIL sentence that refuses a particular allow: `neverallow <src_t> <tgt_t>:<class> { <perm> };` — used by refpolicy to guard against the broadest shapes. | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| **permissive** | A mode — either domain-level permissive (`semanage permissive -a <domain>`) or system-level (`setenforce 0`). In permissive, every AVC is *logged*, never *blocked*. | [Modes, and the Cost of Off](repo:book/part1/05-modes-and-the-cost-of-off.md) |
| **policy module** | A compiled piece of policy — a `.pp` binary — that layers on top of the base policy. `semodule -i` loads it; `semodule -r` removes it. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **`.pp`** | The compiled policy module binary — what `semodule -i` loads. Produced by `make -f /usr/share/selinux/devel/Makefile`. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **`.te`** | The *Type Enforcement* file — where `allow` rules, `policy_module()`, and `typeattribute` declarations live. The reviewable policy source. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **`.fc`** | The *File Contexts* file — where each path gets its label rule. `gen_context` and per-path rules live here. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **`.if`** | A refpolicy *interface* — a shared macro that lets a module write `audit_file_read(myapp_t)` instead of a raw `allow` rule. | [Allow Rules and Interfaces](repo:book/part2/08-allow-rules-and-interfaces.md) |
| **refpolicy** | The policy grammar and interface library shipped with `selinux-policy-devel`; every rule in this book is written against it. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **relabel** | Re-applies expected labels to a path or a filesystem — either per-path with `restorecon`, or full-file-system with `fixfiles relabel`. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **restorecon** | `restorecon -R -v` — the single most useful command in this book; it re-applies the expected label to a path. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **role** | The second field of the context (`system_r`, `user_r`, `sysadm_r`). The base policy assigns the role; the module never touches it. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **sandbox** | The design goal: each domain may touch only its own paths, ports and processes — the narrowest allow set the kernel will accept. | [Designing a Domain](repo:book/part2/11-designing-a-domain.md) |
| **sepolgen** | The Python library the generator uses to match a denial against refpolicy interfaces. It reads a database that `sepolgen-ifgen` builds; if that database is missing the generator refuses base-type AVCs. | [Querying the Installed Policy](repo:book/part2/07-types-attributes-and-classes.md) |
| **sesearch** | `sesearch -A -s <src_t> -t <tgt_t> -c <class> -p <perm>` — the rule lookup command. Returns each matching `allow` rule verbatim. | [Querying the Installed Policy](repo:book/part2/07-types-attributes-and-classes.md) |
| **soak** | The monitoring phase after canary deployment — watch for net-new AVCs against the installed policy. Zero net-new is the gate to enforcing. | [Canary, Soak, Enforce](repo:book/part4/19-canary-soak-enforce.md) |
| **spc_t** | The *super-privileged container* type — the domain a container gets when label separation is off (`podman run --security-opt label=disable`, or `--privileged`). It is close to unconfined, which is why Chapter 23 treats those flags as decisions. | [Containers, Namespaces and MCS](repo:book/part5/23-containers.md) |
| **type** | The third field of the context — the *only* field the kernel checks. Every access decision names a type; every rule names a type. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **type transition** | A `type_transition <src_t> <tgt_t>:<class> <new_t>;` rule — the kernel's way of letting a process start under a new domain. Used for daemons, services, and user-space processes. | [Ports, Booleans and Transitions](repo:book/part2/10-ports-booleans-and-transitions.md) |
| **typeattribute** | A line that adds a type to an attribute — `typeattribute <src_t> <attr>;` — used to build the named collections that allow rules target. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **unconfined_t** | The default interactive shell domain — broad allows, no denials. Every process on a typical RHEL box runs as `unconfined_t`. Your module is different. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **user space vs kernel space** | The boundary each access decision lives on: the kernel mediates every syscall; each syscall asks the policy once. The application runs in user space; each file, socket and fork is asked separately. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |

:::: note not every term is a command
A term is a decision, not a command. Each entry answers the question: *what does the kernel
actually check about this thing?* Every rule, type, and mode is a decision; every command is
a way to observe that decision.
::::

## What you can do now

- Pick each term above, name a file or a command in the book that answers it, and read
  the first chapter where it appears.
- Run `getenforce`, `ls -Z`, `ps -eZ`, and `id -Z` — each one answers a different field of
  the context.
- Read every term you just learned against the rule that names it: a `allow` rule always
  names a source type, a target type, a class, and a set of permissions.
