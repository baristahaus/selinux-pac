# Labels Are the Interface

> Every denial in `audit.log` is the answer to one tuple. This chapter opens the label itself. It
> covers the four colon-separated fields and why only the third one carries the decision. It also
> shows how a file or a process gets its tag on the box.

## Two questions about one file

When a process opens a file, Linux answers two questions. Both read the same value, a *type*.

| Question | Classic Unix (DAC) | SELinux (MAC) |
|---|---|---|
| Does this **user** own the file? | `ls -l` | irrelevant |
| Is this **domain** allowed to do this **permission** to this **type**? | irrelevant | `ls -Z`/`ps -eZ` |

The two commands are not interchangeable. `ls -Z` reads the tag on the *file*. `ps -eZ` reads the
badge on the *process*. Policy matches badge against room. Without that match, nothing happens, not
even for `root`, and not even for the owner.

The three files you will read most often are `audit.log`, `myapp.te`, and `myapp.fc`. All three
talk about the same thing: the type, which is the third field of the context string.

## The four fields of the context string

A full label reads `user:role:type:level`. All four fields exist, but only one carries the
decision:

| Field | Meaning | Typical value | Why you look at it |
|---|---|---|---|
| **user** | identity of the bearer | `system_u` | rarely changes |
| **role** | the role a process or file can exercise | `system_r` (process), `object_r` (file) | tells you the difference between *process* and *object* |
| **type** | the category the policy actually checks | `shopapi_t`, `myapp_exec_t`, `var_log_t` | the only field that gates an `allow` rule |
| **level** | sensitivity or category in MLS/MCS | `s0` | the kernel ignores it unless your org uses multi-tenant classification |

In this project everything uses `system_u`, `system_r`/`object_r`, and `s0`. The third field
carries the decision, and that field is the type. That is why
`docs/policy/102-SELINUX_BASICS.md` §3 spends half its page telling readers to look at the third
field. It is also why `docs/training/101-SELINUX.md` lab 0 asks readers to "explain what is the
difference between the type on the file and the type on the running process".

::: why The three other fields are useful
The role lets policy tell the difference between *process* and *object* at a glance. A rule like
`allow system_r object_r` is legible because the reader knows which side is which. The user
distinguishes a daemon from a user login. `unconfined_u` is a real object you will meet. The level
gates top-secret environments. All three help you read the string, but only `type` answers the
question at the hook.
:::

## Where each label sits

The same concept lives in two different places, and you cannot read a process label with `ls -Z` because it is not on the inode.

| Object | Where the label lives | Command to see it |
|---|---|---|
| **File** | extended attribute `security.selinux` on the inode | `ls -Z` and `getfattr -n security.selinux <path>` |
| **Process** | the kernel `task_struct`, which is a field on each running thread | `ps -eZ` |
| **Kernel** | the loaded policy object (under `/var/lib/selinux/targeted/active/`) | `semodule -l` (what is loaded) |

A file keeps its tag as an extended attribute on the inode:

```bash title="Read a file's SELinux tag from the inode"
$ getfattr -n security.selinux /opt/myapp/app.py
# file: /opt/myapp/app.py
security.selinux="system_u:object_r:myapp_exec_t:s0"
```

`getfattr` reads the attribute directly. It shows the raw string, not the column layout of `ls`.
There is no equivalent call for a process. The kernel keeps that string in memory and shows it to
user space only through `ps -eZ`.

:::: note The extended attribute is the source of truth
`restorecon` reads the `.fc` list of the policy and *rewrites* this attribute on the inode. A
mislabeled file has the wrong string in the field even when the policy allows everything. That is
the most common "rule is correct but the denial persists" case. Chapter 9 covers the full
lifecycle.
::::

## How a file gets its label

At creation time the kernel does not read this list. A new inode gets its type from its parent
directory, plus any `type_transition` rule that names it. It can also get the type from a
user-space `setfscreatecon` when the program asks for a specific label. The `.fc` entries are a
table for user space. The build compiles that table into the file-context table of the policy, and
`restorecon` and `matchpathcon` are the tools that consult it.

That is why you must apply the rule, not only write it. A file created *before* a labeling entry
was added keeps the type it got. It keeps that type even when the policy now says that path must
carry a dedicated type. `restorecon` repairs it: it walks the compiled table, matches the path, and
rewrites the inode.

```bash title="What your .fc compiles into"
$ cat selinux/myapp.fc | head -n 3
/opt/myapp                                 gen_context(system_u:object_r:myapp_exec_t,s0)
/opt/myapp/app\.py                         gen_context(system_u:object_r:myapp_exec_t,s0)
/opt/myapp/backend_stub\.py                gen_context(system_u:object_r:myapp_backend_exec_t,s0)
```

The same `gen_context` pattern appears in every `.fc` in the repository. Each line answers "what
label does this path carry?", and the kernel uses it the moment the file appears on disk. If the
path was already there when the module first loaded, the kernel never revisits it. `restorecon` is
the only tool that goes back. Chapter 9, `09-file-contexts-and-the-label-lifecycle.md`, walks the
full lifecycle.

## How a process gets its domain

A process does not start as `unconfined_t` because the filename of the binary was wrong. It starts
in a domain because policy decides at exec time. The rule that makes this happen is the
entrypoint/transition pair:

```text
allow init_t myapp_exec_t:file entrypoint;     # systemd may exec this file
type_transition init_t myapp_exec_t:process myapp_t;  # therefore it enters myapp_t
```

That is the pair on lines 44–45 of `selinux/myapp.te`. `init_daemon_domain(myapp_t, myapp_exec_t)`
is a thin wrapper that emits the same two lines plus the `require` block. The kernel consults this
pair *the moment `init` (or `systemd`) execs the labeled entrypoint file*. The new process inherits
the target type as its domain.

Two ways to start a process under a custom domain, illustrated by `selinux/shopapi/shopapi.te`:

| Path | How it works | When you use it |
|---|---|---|
| **systemd `SELinuxContext=`** | the unit file of systemd pins the context on exec. The JVM is a `bin_t`/`java_exec_t` shared binary | preferred. It needs no labeled wrapper |
| **labeled wrapper + `type_transition`** | the launcher file is labeled `shopapi_exec_t`. The transition rule forces the JVM into `shopapi_t` | useful when systemd is not yet on the box |

The comment block at the top of `selinux/shopapi/shopapi.te` makes the choice explicit:

```text
# Live start: systemd SELinuxContext=system_u:system_r:shopapi_t:s0
# (java is a shared bin_t/java_exec_t binary). Alternative: labelled wrapper
# at the app install_root labeled shopapi_exec_t + type_transition.
```

Both paths produce the same outcome: the running JVM has the type `shopapi_t` in the third field of
its context string. Neither path is the name of the binary. `java` is the name. `shopapi_t` is the
domain that the policy *assigns*.

:::: why Domain is a *type*, not a *kind*
People say "domain" as if it is a new category. It is not: a domain is a type that a process runs
in. `shopapi_t` is a type. A *running process* with `shopapi_t` in the third field is a domain. The
kernel does not ask which word you prefer. It only reads the third field.
::::

## Type versus domain — the commands you read them with

Every chapter returns to this pairing. This table covers it once.

| Term in the policy | What it names | Command that shows it |
|---|---|---|
| **Domain** | a running *process* type | `ps -eZ` |
| **Type** (object) | a *file* type | `ls -Z` |
| **Type** (file context) | the *path-pattern* line in `.fc` | read the `.fc` file |
| **Type** (type declaration) | the `type` line in `.te` | read the `.te` file |
| **Per-domain permissive** | an *allow-log* tag on one domain | `sudo semanage permissive -l` |
| **Whole-system mode** | `Enforcing` / `Permissive` / `Disabled` | `getenforce` |

When the policy says "processes labeled `shopapi_t` can write to files labeled
`shopapi_log_t`", you have one entry on each side of the row: the domain side and the object side.
Both come from the third field.

## Attributes — grouping types without writing per-type rules

Each `allow` rule names specific types on each side. If a project declares fifty log types, you do
not write fifty `allow … logging_log_t` lines. Instead, give each type a shared attribute, and let
rules name the attribute:

```text
logging_log_file(shopapi_log_t)
```

That line comes from `selinux/shopapi/shopapi.te` (line 27). It puts `shopapi_log_t` into the
log-file group of the base policy. Every rule written against that group also covers
`shopapi_log_t`. The same pattern covers every log type in the base policy, and it also applies to
network ports (`corenet_port()`) and PID files (`files_pid_file()`).

```text
# in the base policy, a rule that reads log files:
allow myapp_t logging_log_t:file { read open getattr };
# because each log file carries the attribute `logging_log_file`:
```

When you read an `allow` rule and it names an attribute instead of a type on one side, the rule
covers *every* type that carries that attribute. It does not cover only the one you see. That is
why the review rule in Chapter 17 asks "did this rule widen an attribute?" before you add an allow.
The attribute chapter, `07-types-attributes-and-classes.md`, is where that review happens in full.

:::: note Attributes scale rules, not privileges
An attribute is not a new kind of permission. It is a *named group* of types. Adding
`files_type(foo_t)` does not widen `bar_t`. It only extends the *existing* allow rule to `foo_t` as
well.
::::

## One real transition, traced

Here is the whole path, from policy file to running process, traced against `myapp.te`:

```bash title="The entrypoint → transition pair"
$ sed -n '35,53p' selinux/myapp.te
require {
    type init_t;
    class process { transition dyntransition siginh rlimitinh };
    class file entrypoint;
}

# systemd (init_t) starts user units on FCOS — transition on labeled entrypoints
allow init_t myapp_exec_t:file { execute read open getattr map ioctl execute_no_trans entrypoint };
allow init_t myapp_t:process { transition dyntransition siginh rlimitinh };
allow myapp_t myapp_exec_t:file entrypoint;
type_transition init_t myapp_exec_t:process myapp_t;

allow init_t myapp_lib_t:dir { search getattr open read };
allow init_t myapp_lib_t:file { read open getattr map ioctl };

allow init_t myapp_backend_exec_t:file { execute read open getattr map ioctl execute_no_trans entrypoint };
allow init_t myapp_backend_t:process { transition dyntransition siginh rlimitinh };
allow myapp_backend_t myapp_backend_exec_t:file entrypoint;
type_transition init_t myapp_backend_exec_t:process myapp_backend_t;
```

`init_t` (or `systemd`) execs `/opt/myapp/app.py`, a file labeled `myapp_exec_t`. The `entrypoint`
allow covers this file, and the `type_transition` rule names the target type `myapp_t`. So the new
process inherits `myapp_t` as its domain. No other file in `/opt/myapp` makes this happen: the rule
is *about this path*.

:::: try Read labels on your own host
Use a RHEL-family host, in any role: lab box, cloud instance, or development VM. Make no changes to
policy. Read only.

```bash title="On rhel-qa, as a privileged user"
$ getenforce
Enforcing

$ ls -Z /usr/bin/passwd
system_u:object_r:passwd_exec_t:s0   /usr/bin/passwd

$ ps -eZ | head
system_u:system_r:unconfined_t:s0  1234 ?  ... /usr/lib/systemd/systemd --system
system_u:system_r:sshd_t:s0        2345 ?  ... sshd: user@pts/0
system_u:system_r:unconfined_t:s0  3456 pts/0  ... -bash

$ id -Z
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

$ getfattr -n security.selinux /etc/passwd
# file: /etc/passwd
security.selinux="system_u:object_r:passwd_file_t:s0"

$ matchpathcon /etc/passwd
/etc/passwd	system_u:object_r:passwd_file_t:s0
```

The third field of `ls -Z /usr/bin/passwd` is `passwd_exec_t`. That is the type for the *binary*.
The third field of `ls -Z /etc/passwd` is `passwd_file_t`, the type for the *file*. The third field
of `ps -eZ | head` is the process domain, `unconfined_t` (or `sshd_t`). The same path through
`matchpathcon` answers the other direction: *what label must this path carry?* The
`semanage fcontext -l` command dumps the whole table, which is a different question. You are now
looking at several views of the same concept: the type.

*No host?* That is fine. You do not need one to read the chapter. `make check` reads the golden
fixtures, and the CLI prints the same three fields for each row. See [Path A](lab.md#path-a) in
`book/lab.md`.
:::

## What you can do now

- **Read a label and tell which side it is on.** The third field is the type. The field before it
  is the role, and the role separates process from object.
- **Find a file's tag on disk.** `ls -Z` gives the answer. `getfattr -n security.selinux` gives it
  from the inode.
- **Find a running process's tag.** Run `ps -eZ`. The third field is the domain.
- **Name the entrypoint/transition pair that starts an app.** The only rules that make a process
  enter a new domain are the `type_transition <start_type> <file_type>:process <target_type>;`
  line and the `entrypoint` allow.
- **Read an attribute-based allow.** One rule that names an attribute on one side covers every type
  that carries that attribute. Adding `files_type(...)` does not widen a privilege. It only
  attaches the existing rule to a new type.

These are all you need for the rest of Part I. Chapter 4 shows what to do with the tuple after you
can read it. Chapter 9 takes the lifecycle of the file-context label in full.
