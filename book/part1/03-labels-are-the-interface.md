# Labels Are the Interface

> Every denial in `audit.log` is the answer to one tuple. This chapter opens the label itself: the four colon-separated fields, why only the third one carries the decision, and how a file or a process actually gets its tag on the box.

## Two questions about one file

When a process opens a file, Linux answers two questions — and both of them read the same value, a *type*.

| Question | Classic Unix (DAC) | SELinux (MAC) |
|---|---|---|
| Does this **user** own the file? | `ls -l` | irrelevant |
| Is this **domain** allowed to do this **permission** to this **type**? | irrelevant | `ls -Z`/`ps -eZ` |

The two commands are not interchangeable. `ls -Z` reads the *file's* tag; `ps -eZ` reads the *process's* badge. Policy matches badge against room. Without that match, nothing happens — not even `root`, and not even the owner.

The three files you will read most often — `audit.log`, `myapp.te`, `myapp.fc` — are all talking about the same thing: the type, the third field of the context string.

## The four fields of the context string

A full label reads `user:role:type:level`. Each field exists, and each field is *not* the one the kernel uses to decide:

| Field | Meaning | Typical value | Why you look at it |
|---|---|---|---|
| **user** | identity of the bearer | `system_u` | rarely changes |
| **role** | the role a process or file may exercise | `system_r` (process), `object_r` (file) | tells you the difference between *process* and *object* |
| **type** | the category the policy actually checks | `shopapi_t`, `myapp_exec_t`, `var_log_t` | the only field that gates an `allow` rule |
| **level** | sensitivity or category in MLS/MCS | `s0` | ignored unless your org uses multi-tenant classification |

In this project everything uses `system_u`, `system_r`/`object_r`, and `s0`. The field that carries the decision is the third one — the type. That is why `docs/policy/102-SELINUX_BASICS.md` §3 spends half its page telling readers to look at the third field, and why `docs/training/101-SELINUX.md` lab 0 asks readers to "explain what is the difference between the type on the file and the type on the running process".

::: why The three other fields are useful
The role lets policy tell the difference between *process* and *object* at a glance: a rule `allow system_r object_r` is legible because the reader knows which side is which. The user distinguishes a daemon from a user login; `unconfined_u` is a real object you will meet. The level gates top-secret environments. They all help you read the string — but only `type` answers the question at the hook.
:::

## Where each label sits

The same concept lives in two different places, and you cannot read a process label with `ls -Z` because it is not on the inode.

| Object | Where the label lives | Command to see it |
|---|---|---|
| **File** | extended attribute `security.selinux` on the inode | `ls -Z` and `getfattr -n security.selinux <path>` |
| **Process** | the kernel `task_struct` — a field on each running thread | `ps -eZ` |
| **Kernel** | the loaded policy object (under `/var/lib/selinux/targeted/active/`) | `semodule -l` (what is loaded) |

A file's tag is stored as an extended attribute. On the inode:

```bash title="Read a file's SELinux tag from the inode"
$ getfattr -n security.selinux /opt/myapp/app.py
# file: /opt/myapp/app.py
security.selinux="system_u:object_r:myapp_exec_t:s0"
```

`getfattr` reads the attribute directly. It shows the raw string, not `ls`'s columnar layout. The same call on a process does not exist: the kernel keeps the string in memory, exposes it to userland only through `ps -eZ`.

:::: note The extended attribute is the source of truth
`restorecon` reads the policy's `.fc` list and *rewrites* this attribute on the inode. A mislabelled file has the wrong string in the field even when the policy allows everything. That is the single most common "rule is correct but the denial persists" case — Chapter 9 covers the full lifecycle.
::::

## How a file gets its label

At creation time, the kernel looks at the file-context list in the policy and compares each line to the path being created. The first matching line wins: the new inode receives that type.

This is a live rule. A file created *before* a labelling entry was added keeps whatever it got — even if the policy later says the path should carry a dedicated type. `restorecon` repairs it: it walks the policy list, matches the path, and rewrites the inode.

```bash title="The kernel reads your .fc at creation time"
$ cat selinux/myapp.fc | head -n 3
/opt/myapp                                 gen_context(system_u:object_r:myapp_exec_t,s0)
/opt/myapp/app\.py                         gen_context(system_u:object_r:myapp_exec_t,s0)
/opt/myapp/backend_stub\.py                gen_context(system_u:object_r:myapp_backend_exec_t,s0)
```

The same `gen_context` pattern appears in every `.fc` in the repository: each line answers "what label does this path carry?" and the kernel uses it the moment the file appears on disk. When the path was already there when the module was first loaded, the kernel never revisits it. `restorecon` is the only tool that goes back. Chapter 9, `09-file-contexts-and-the-label-lifecycle.md`, walks the full lifecycle.

## How a process gets its domain

A process does not start as `unconfined_t` because the binary's filename was wrong — it starts as a domain because policy decides at exec time. The rule that makes this happen is the **entrypoint/transition** pair:

```text
allow init_t myapp_exec_t:file entrypoint;     # systemd may exec this file
type_transition init_t myapp_exec_t:process myapp_t;  # therefore it enters myapp_t
```

That is exactly the pair on lines 44–45 of `selinux/myapp.te`. `init_daemon_domain(myapp_t, myapp_exec_t)` is a thin wrapper that emits the same two lines plus the `require` block. The kernel consults this pair *the moment `init` (or `systemd`) execs the labelled entrypoint file*: the new process inherits the target type as its domain.

Two ways to start a process under a custom domain, illustrated by `selinux/shopapi/shopapi.te`:

| Path | How it works | When you use it |
|---|---|---|
| **systemd `SELinuxContext=`** | systemd's unit file pins the context on exec; the JVM is a `bin_t`/`java_exec_t` shared binary | preferred — no labelled wrapper needed |
| **labelled wrapper + `type_transition`** | the launcher file is labelled `shopapi_exec_t`; the transition rule forces the JVM into `shopapi_t` | useful when systemd is not yet on the box |

The comment block at the top of `selinux/shopapi/shopapi.te` makes the choice explicit:

```text
# Live start: systemd SELinuxContext=system_u:system_r:shopapi_t:s0
# (java is a shared bin_t/java_exec_t binary). Alternative: labelled wrapper
# at the app install_root labeled shopapi_exec_t + type_transition.
```

Both paths produce the same outcome: the running JVM has the type `shopapi_t` in the third field of its context string. Neither path is the name of the binary — `java` is the name; `shopapi_t` is the domain the policy *assigns*.

:::: why Domain is a *type*, not a *kind*
People say "domain" as if it is a new category. It is not: a domain is a type that a process runs in. `shopapi_t` is a type. A *running process* with `shopapi_t` in the third field is a domain. The kernel does not ask which word you prefer — it only reads the third field.
::::

## Type versus domain — the commands you read them with

Every chapter returns to this pairing. Here is the table that earns its keep once.

| Term in the policy | What it names | Command that shows it |
|---|---|---|
| **Domain** | a running *process* type | `ps -eZ` |
| **Type** (object) | a *file* type | `ls -Z` |
| **Type** (file context) | the *path-pattern* line in `.fc` | read the `.fc` file |
| **Type** (type declaration) | the `type` line in `.te` | read the `.te` file |
| **Per-domain permissive** | an *allow-log* tag on one domain | `sudo semanage permissive -l` |
| **Whole-system mode** | `Enforcing` / `Permissive` / `Disabled` | `getenforce` |

When the policy says "processes labelled `shopapi_t` may write to files labelled `shopapi_log_t`", you have one entry on each side of the row: the domain side, the object side. Both come from the third field.

## Attributes — grouping types without writing per-type rules

Each `allow` rule names specific types on each side. If a project declares fifty log types, you do not write fifty `allow … logging_log_t` lines. Instead you give each type a **shared attribute**, and rules name the attribute:

```text
files_type(shopapi_log_t)
```

That line from `selinux/shopapi/shopapi.te` (line 27) says: *any rule that names `logging_log_file` also applies to `shopapi_log_t`*. The same pattern covers every log type in the base policy; the same applies to network ports (`corenet_port()`) and PID files (`files_pid_file()`).

```text
# in the base policy, a rule that reads log files:
allow myapp_t logging_log_t:file { read open getattr };
# because each log file carries the attribute `logging_log_file`:
```

When you read an `allow` rule and it names an attribute instead of a type on one side, the rule covers *every* type that carries that attribute — not just the one. That is why the review rule in Chapter 17 asks "did this rule widen an attribute?" before adding an allow. The attribute chapter, `07-types-attributes-and-classes.md`, is where that review happens in full.

:::: note Attributes scale rules, not privileges
An attribute is not a new kind of permission. It is a *named group* of types. Adding `files_type(foo_t)` does not widen `bar_t`; it only extends the *existing* allow rule to `foo_t` as well.
::::

## One real transition, traced

Here is the whole path — from policy file to running process — traced against `myapp.te`:

```bash title="The entrypoint → transition pair"
$ sed -n '39,53p' selinux/myapp.te
require {
    type init_t;
    class process { transition dyntransition siginh rlimitinh };
    class file entrypoint;
}

allow init_t myapp_exec_t:file { execute read open getattr map ioctl execute_no_trans entrypoint };
allow init_t myapp_t:process { transition dyntransition siginh rlimitinh };
allow myapp_t myapp_exec_t:file entrypoint;
type_transition init_t myapp_exec_t:process myapp_t;

allow init_t myapp_lib_t:dir { search getattr open read };
allow init_t myapp_lib_t:file { read open getattr map ioctl };
```

`init_t` (or `systemd`) execs `/opt/myapp/app.py` — a file labelled `myapp_exec_t`. Because the `entrypoint` allow covers this file, and the `type_transition` rule names the target type `myapp_t`, the new process inherits `myapp_t` as its domain. No other file in `/opt/myapp` makes this happen: the rule is *about this path*.

:::: try Read labels on your own host
A RHEL-family host, any role — lab box, cloud instance, development VM. No changes to policy; only reads.

```bash title="On rhel-qa, as a privileged user"
$ getenforce
Enforcing

$ ls -Z /usr/bin/passwd
system_u:object_r:passwd_file_t:s0   /usr/bin/passwd

$ ps -eZ | head
system_u:system_r:unconfined_t:s0  1234 ?  ... /usr/lib/systemd/systemd --system
system_u:system_r:sshd_t:s0        2345 ?  ... sshd: user@pts/0
system_u:system_r:unconfined_t:s0  3456 pts/0  ... -bash

$ id -Z
system_u:system_r:unconfined_r:s0

$ getfattr -n security.selinux /etc/passwd
# file: /etc/passwd
security.selinux="system_u:object_r:passwd_file_t:s0"

$ semanage fcontext -l | head
# the first fcontext matches: /etc/passwd                system_u:object_r:passwd_file_t:s0
```

The third field of `ls -Z /usr/bin/passwd` is `passwd_file_t`. The third field of `ps -eZ | head` is `unconfined_t` (or `sshd_t`). The third field of `getfattr` on `/etc/passwd` is the same `passwd_file_t`. You are now looking at three different views of the same concept: the type.

*No host?* That is fine. You do not need one to read the chapter. `make check` reads the golden fixtures and the CLI prints the same three fields for each row; see [Path A](lab.md#path-a) in `book/lab.md`.
:::

## What you can do now

- **Read a label and tell which side it is on.** The third field is the type; the field before it is the role, which separates process from object.
- **Find a file's tag on disk.** `ls -Z` gives the answer; `getfattr -n security.selinux` gives it from the inode.
- **Find a running process's tag.** `ps -eZ` — the third field is the domain.
- **Name the entrypoint/transition pair that starts an app.** `type_transition <start_type> <file_type>:process <target_type>;` plus the `entrypoint` allow is the only rule that makes a process enter a new domain.
- **Read an attribute-based allow.** One rule that names an attribute on one side covers every type that carries that attribute; adding `files_type(...)` does not widen a privilege, it only attaches the existing rule to a new type.

These are all you need for the rest of Part I. Chapter 4 shows what to do with the tuple after you can read it; Chapter 9 takes the lifecycle of the file-context label in full.
