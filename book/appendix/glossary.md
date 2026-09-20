# Glossary

> Every term in this book is a name for something the kernel actually checks. The glossary
> does not explain SELinux in general. Each entry names the meaning a term holds in this book,
> and a chapter that teaches it. That chapter is usually the place the term is used hardest,
> not the first mention.

| Term | What it means | Taught in |
|---|---|---|
| **AVC** | *Access Vector Cache*. The kernel's record of every policy decision: the tuple, the mode, and the permissive flag. It is the single most useful line in `audit.log`. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **allow rule** | The exact `allow <src_t> <tgt_t>:<class> { <perm> };` sentence the kernel reads each access decision against. Named types and named perms are what makes a reviewable rule. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **attribute** | A named collection of types: the keyword that lets a rule target every type carrying the attribute instead of naming each type. `typeattribute <src_t> <attr>;` adds the type. An allow rule reads `allow <src_t> <attr>:<class> { <perm> };`. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **base policy** | The vendor-shipped policy compiled by Red Hat into `/etc/selinux/<type>/policy/policy.<n>`. Custom application modules layer on top. The base policy never changes. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **boolean** | A policy toggle: each boolean is a switch that flips a broad allow in the base policy. Set it with `setsebool -P`. It is never shipped in a module. | [Ports, Booleans and Transitions](repo:book/part2/10-ports-booleans-and-transitions.md) |
| **CIL** | *Common Intermediate Language*. The policy language `secilc` compiles into the kernel's binary policy (`policy.<n>`). It is text, so it is the form to read when the binary is not. But `sesearch` and `seinfo` read the *binary*, and `semodule -i` is what takes a `.cil` module. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **class** | The category of object the kernel decides about: `file`, `dir`, `tcp_socket`, `process`, `capability`. Each class has a fixed set of permissions. The class is what makes `write` meaningful on a file but not on a socket. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **constraint** | A rule that gates when an allow can fire: a boolean expression over users, roles, types and classes, carried by the base policy (the check that keeps an ordinary user out of the admin's files is one). It is written in policy source and CIL, rarely in a module. Check them with `seinfo --constrain <class>`. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **context** | `user:role:type:level`. The four colon-separated fields each name a different slice of identity. Only the third field, the type, drives the access decision. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **DAC** | *Discretionary Access Control*. The classic Unix check: owner/group/mode bits, `chmod`, `chown`. SELinux does not consult DAC. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **domain** | The process type, that is, the label of the running process. `myapp_t` is your app's domain. Every process that runs it is constrained by its policy. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **dontaudit** | A rule that suppresses the AVC record for a tuple. The access is still **denied**, but the log stays quiet. The vendor policy uses it to silence noisy tuples. That is the reason `semodule -DB` exists. | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| **entrypoint** | A permission in the `file` class: the *new* domain must hold `entrypoint` on the executable it exec's, alongside a matching `type_transition`. That pair is what lets a daemon start under its own domain. | [Designing a Domain](repo:book/part2/11-designing-a-domain.md) |
| **enforcing** | The kernel mode that blocks each unmatched access: the default mode, and the state you ship to production. | [Modes, and the Cost of Off](repo:book/part1/05-modes-and-the-cost-of-off.md) |
| **file context** | The policy rule that tells SELinux what label each path must have. It is written in `.fc` and stored at `/etc/selinux/<type>/contexts/files/`. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **gen_context** | The `.fc` directive that names the label a path must carry: `gen_context(system_u:object_r:myapp_var_lib_t,s0)`. Its arguments are the context fields, never an object class. `restorecon` uses the file as its source of truth. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **interface** | A refpolicy `.if` macro: a named bundle of allow rules a module calls in one line, for example `dev_read_urand(myapp_t)`. Each one is reviewable in the policy source that ships with `selinux-policy-devel`. | [Allow Rules and Interfaces](repo:book/part2/08-allow-rules-and-interfaces.md) |
| **label** | The SELinux context attached to a file or process, that is, the answer the kernel reads each access decision against. `ls -Z` is the most useful label command. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **MAC** | *Mandatory Access Control*. The kernel-side access control: every decision is answered by the policy, not by the account. `root` does not escape MAC. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **MCS** | *Multi-Category Security*. The level (fourth field) of the context. It is used for compartmentalization across categories. The book uses `s0` (unclassified) throughout. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **MLS** | *Multi-Level Security*. The broader framework that includes both sensitivity levels (the fourth field) and categories (MCS). The default RHEL policy uses `s0` only. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **neverallow** | A CIL sentence that refuses a particular allow: `neverallow <src_t> <tgt_t>:<class> { <perm> };`. Refpolicy uses it to guard against the broadest shapes. | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| **permissive** | A mode: either domain-level permissive (`semanage permissive -a <domain>`) or system-level (`setenforce 0`). In permissive, the kernel *logs* every AVC and never *blocks* it. | [Modes, and the Cost of Off](repo:book/part1/05-modes-and-the-cost-of-off.md) |
| **policy module** | A compiled piece of policy, a `.pp` binary, that layers on top of the base policy. `semodule -i` loads it. `semodule -r` removes it. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **`.pp`** | The compiled policy module binary, that is, what `semodule -i` loads. `make -f /usr/share/selinux/devel/Makefile` produces it. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **`.te`** | The *Type Enforcement* file, where `allow` rules, `policy_module()`, and `typeattribute` declarations live. It is the reviewable policy source. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **`.fc`** | The *File Contexts* file, where each path gets its label rule. `gen_context` and per-path rules live here. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **`.if`** | A refpolicy *interface* file, where those macros are declared. The module calls one (`dev_read_urand(myapp_t)`) instead of writing the raw `allow` rules itself. | [Allow Rules and Interfaces](repo:book/part2/08-allow-rules-and-interfaces.md) |
| **refpolicy** | The policy grammar and interface library shipped with `selinux-policy-devel`. Every rule in this book is written against it. | [Anatomy of a Module](repo:book/part2/06-anatomy-of-a-module.md) |
| **relabel** | Re-applies expected labels to a path or a filesystem: either per-path with `restorecon`, or the full filesystem with `fixfiles relabel`. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **restorecon** | `restorecon -R -v` is the single most useful command in this book. It re-applies the expected label to a path. | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| **role** | The second field of the context (`system_r`, `user_r`, `sysadm_r`). The base policy assigns the role. The module never touches it. | [Labels Are the Interface](repo:book/part1/03-labels-are-the-interface.md) |
| **sepolgen** | The Python library the generator uses to match a denial against refpolicy interfaces. It reads a database that `sepolgen-ifgen` builds. If that database is missing, the generator refuses base-type AVCs. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **sesearch** | `sesearch -A -s <src_t> -t <tgt_t> -c <class> -p <perm>` is the rule lookup command. It returns each matching `allow` rule verbatim. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **soak** | The monitoring phase after canary deployment. Watch for net-new AVCs against the installed policy. Zero net-new is the gate to enforcing. | [Canary, Soak, Enforce](repo:book/part4/19-canary-soak-enforce.md) |
| **type** | The third field of the context, and the *only* field the kernel checks. Every access decision names a type. Every rule names a type. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **type transition** (`type_transition`) | A `type_transition <src_t> <tgt_t>:<class> <new_t>;` rule, that is, the kernel's way of letting a process start under a new domain. Use it for daemons, services, and user-space processes. | [Ports, Booleans and Transitions](repo:book/part2/10-ports-booleans-and-transitions.md) |
| **typeattribute** | A line that adds a type to an attribute: `typeattribute <src_t> <attr>;`. It builds the named collections that allow rules target. | [Types, Attributes and Classes](repo:book/part2/07-types-attributes-and-classes.md) |
| **unconfined_t** | The domain a user session runs in. It is broad, but not unbounded: it is enforcing and does take denials. Daemons do not run here. Each has its own domain (`httpd_t`, `postgresql_t`). An unconfined *service* lands in `unconfined_service_t`, and a JVM lands in `unconfined_java_t`. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |
| **user space vs kernel space** | The boundary each access decision lives on. The kernel mediates every syscall, and each syscall asks the policy once. The application runs in user space. The kernel asks about each file, socket and fork separately. | [What SELinux Actually Checks](repo:book/part1/02-what-selinux-actually-checks.md) |

:::: note not every term is a command
A term is a decision, not a command. Each entry answers the question: *what does the kernel
actually check about this thing?* Every rule, type, and mode is a decision. Every command is
a way to observe that decision.
::::

## What you can do now

- Pick each term above, name a file or a command in the book that answers it, and read
  the first chapter where it appears.
- Run `getenforce`, `ls -Z`, `ps -eZ`, and `id -Z`. Each one answers a different field of
  the context.
- Read every term you just learned against the rule that names it: a `allow` rule always
  names a source type, a target type, a class, and a set of permissions.
