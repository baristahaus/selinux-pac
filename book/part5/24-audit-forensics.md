# Audit Forensics

> An AVC is the question the kernel asks; `audit.log` is the question's answer.
> Every denials page in this book is built from one of those answers. Learning
> to read that answer — and to find the answers the kernel lost — is the
> skill that turns a broken app into an incident report in five minutes.

## The audit pipeline on a RHEL host

Three components speak the same language, and each can quietly silence the
story.

1. **The kernel** — every LSM hook (file, socket, process, IPC) asks the policy a
   question and records the answer as an audit event.
2. **`auditd`** — the daemon that writes those events to
   `/var/log/audit/audit.log`. Its behaviour is governed by
   `/etc/audit/auditd.conf`.
3. **Userland tooling** (`ausearch`, `aureport`) — reads the log back into a
   form humans can reason about.

The kernel records first. `auditd` writes. Tools read.

One component can lose events. That component is **`auditd`** — specifically,
when its disk fills or its rate limit fires. A denial that reaches the kernel,
that the policy decides against, and that `auditd` does not deliver to the log
is an event that `ausearch` will not show — and the policy generator will not
see. This is the single biggest hidden failure mode in an audit-forensics
investigation.

## `auditd.conf` settings that matter

These are the real parameter names and what each governs. A mis-set value
hides denials from you.

| Parameter | What it governs | Hidden-denial mode |
|-----------|-----------------|---------------------|
| **`max_log_file`** | Maximum size of each log file (MB). | Set too low — the log wraps and overwrites old denials before you read them. |
| **`num_logs`** | Number of historical copies to keep before oldest is dropped. | Set to zero or one — the oldest file, where an early denial lived, is gone by the time you reach it. |
| **`space_left`** | Bytes of free disk before `auditd` escalates. | Default is conservative. When the disk fills below this threshold, `space_left_action` runs. |
| **`admin_space_left`** | Bytes of free disk before a "critical" alert fires. | Set too low — no operator wakes for the wrapping. |
| **`space_left_action`** | Action on reaching `space_left`. | **Default: `SYSLOG`.** On a log-full host, the old records keep arriving while `auditd` writes the new ones, and the operator thinks "everything is fine" because nothing is stopping. |
| **`admin_space_left_action`** | Action on critical shortage. | **Default: `SINGLE`.** Locks the admin out until a page arrives. |
| **`max_log_file_action`** | Action when a file exceeds `max_log_file`. | **Default: `ROTATE`.** Each wrap creates a new file; the oldest is dropped. |
| **`disk_full_action`** | Action when no space left. | **Default: `SINGLE`.** Locks the host until someone `rm` clears space. |
| **`disk_error_action`** | Action when a disk error. | **Default: `SINGLE`.** Same: lock out until someone responds. |
| **`kern_log_rate_limit`** | Per-event kernel message limit (msgs/s). | **Default: 0 = unlimited.** Setting a limit drops rate-limited messages silently; an attacker who generates denial storms can push the host into `SINGLE` or just silence the audit. |

The two most commonly forgotten values are **`space_left_action`** and
**`disk_full_action`**. Both default to locking the admin out on a full disk.
A log that wraps and never grows past `max_log_file` keeps the same story
quiet — that is the silent one.

## `ausearch` in practice

Every question asks about the same log. Each query selects a different lens.

| Query | What it answers |
|-------|-----------------|
| **`ausearch -m avc`** | *What did the policy block today?* |
| **`ausearch -ts recent`** | *What happened in the last hour?* |
| **`ausearch --start 2026/09/17 14:00:00`** | *What happened during this window?* |
| **`ausearch -p 1234`** | *What did this process do?* |
| **`ausearch -i`** | *What does this log look like to a human?* (enables the human-readable `-i` format.) |
| **`ausearch --format text`** | *What do I get back for downstream tooling?* (machine-friendly plain output, no enrichment.) |

Combine them when you need all three. The order of selection is
independent — each filter applies to every record before the tool prints.

The `--subject` filter is the per-domain search — every denials page in this
book starts with it: `ausearch --subject myapp_t`. That gives you only the
denials that belong to your domain. Everything else is the OS's noise.

## `aureport`

Each report type answers a different question about the same log.

| Report | What it answers |
|--------|-----------------|
| **`aureport --avc`** | *Which domains are denying what right now?* |
| **`aureport --summary`** | *How many denials did the policy block per domain?* |
| **`aureport --failed`** | *Which actions failed, and what was the target?* |

`aureport --summary` is the first thing you look at in a soak report — it
numbers each domain's denials. The per-domain totals are what the
`soak_monitor.yml` compares against the marker's deploy epoch.

## Reconstructing an event

An AVC alone tells you *what was attempted, by which domain, on which target,
and whether it was blocked*. It does not tell you what happened before,
what happened after, or who started it.

The audit serial is the thread. Each `msg=audit(…:N):` carries the same
number `N` across every event in the syscall record. Follow it:

```bash
$ ausearch --start 2026/09/17 14:00:00 -m avc --uid 0
```

The `uid=0` filter is the privilege pivot — every event that fired under root
is the same thread. The syscall record is the full action chain: the
`execve` that launched the process, the `open` that reached the target, the
`exit` that finished it. The AVC alone is the *access vector cache* — one
decision, recorded once, at the moment of conflict. The full audit record
is the *event* — one operation, recorded every step.

What the AVC alone does not tell you:

- **who started the process** — that is the parent PID, captured in the
  syscall record's `ppid`.
- **what the process did before the denial** — that is the `execve` line
  that started it.
- **what the process did after the denial** — that is the exit syscall and
  the final state of the target.

Each is recoverable with the audit serial; you already have the
instrument.

## `audit2why`

`audit2why` reads each AVC line, produces the matching `allow` rule, and
prints why the policy says each denial would happen.

```bash
$ audit2why < /var/log/audit/audit.log
```

It does the translation for you — takes a `scontext`/`tcontext`/`tclass`/
`permission` tuple and turns it into the human-readable rule that would
grant it. That is what it does, and that is why it needs a human decision
afterwards.

The mechanics live in earlier chapters — Chapter 6 covers the module files and the install path,
Chapter 8 covers every `allow` rule, Chapter 5 covers the permissive-versus-enforcing decision, and
Chapter 9 takes the label lifecycle. `audit2why` is the translation step
between the log and the policy — every rule it generates is a candidate for
the generator's PR.

## Evidence for two audiences

Two audiences read the same log. Each audience needs the same story in a
different form.

### Incident review

An incident review needs: *what happened, when, to which process, under which
context, and when is it still visible*.

```bash
$ ausearch -m avc --subject shopapi_t --start 2026/09/17 14:00:00 -i
```

Each line returns the serial, the timestamp, the subject, the target, and
the operation. Pair each line with a retention note:

- retention window is `max_log_file × num_logs`.
- on wrap, the oldest records go.
- on `disk_full_action=SINGLE`, the records are locked and unavailable.

### Policy PR

The policy generator needs: *each unique denials tuple, deduplicated, with
the manifest paths that triggered them*.

The repository's export path is the pipeline already in `monitor_avc.sh`
and `lib/avc_query.sh`. Each step is named and ordered.

```bash
# Step 1: capture
$ bash scripts/monitor_avc.sh --domain shopapi_t --paths /var/lib/myapp,/var/log/myapp
# Step 2: filter the captured lines by the manifest paths
$ avc_filter_lines_by_paths "/var/lib/myapp,/var/log/myapp" shopapi_t
# Step 3: export
$ export_app_avcs_to_file shopapi_t
# Step 4: subtract what the installed policy already allows, and see what is left
$ python3 cli/verify_avc_coverage.py \
    --avc-log policy_out/avc.log \
    --te selinux/myapp.te \
    --manifest config/myapp.manifest.yml
```

`cli/avc_preprocess.py` does the merge, dedupe and subtract work, but it is a
module: the commands above are the entry points that call it
(`verify_avc_coverage.py` reads the log against the candidate `.te` and prints
the tuples the policy does not yet cover).

The pipeline's filters keep: manifest-path hits; pathless non-file denials
(name_bind, execmem); pathless file denials whose target type belongs to this
module. It drops: `/etc/passwd`, `/tmp`, `/usr/lib/jvm`, `/proc`, `/sys` —
those are not app trees.

## Extended visibility beyond SELinux

SELinux owns the access vector cache. Two audit features operate outside it.

### Audit watch rules

```bash
$ auditctl -w /var/lib/myapp -p wa -k myapp-watch
```

A watch rule captures every access to a path — regardless of context,
regardless of domain, regardless of policy. It fires on `open`, on
`chmod`, on `restorecon` — it does not consult the policy. It is what you
add when you need to know that the labels changed on the tree, and the
labels changed under which user, regardless of SELinux.

### execve accounting

```bash
$ auditctl -a exit,always -f 4 -k execve
```

The `execve` accounting rule captures every process spawn. That is the
entry point of every operation that SELinux cares about — the command
that reaches the target, the command that started the denial. It is what
you add when you need to know that a process spawned, regardless of domain,
regardless of labels, regardless of SELinux.

Both are separate from SELinux policy and both fire on each operation the
kernel does not consult the policy about. A security-conscious host wants
both — watch rules tell you *what changed on the tree*, execve accounting
tells you *who was there and what they spawned*. Together, they give you a
full picture that the policy alone does not carry.

## Forensic questions an AVC can and cannot answer

One AVC line. One question each.

| Question | Can an AVC answer it? | Answer form |
|----------|----------------------|-------------|
| Was access attempted? | **yes** — `denied { … }` is the attempt. |
| By which domain? | **yes** — `scontext`'s type field names it. |
| On which target? | **yes** — `tcontext`'s type field names it. |
| Was it blocked? | **yes** — `permissive=0` means blocked; `permissive=1` means logged only. |
| Did the data leave? | **no** — SELinux only knows the access vector cache, not the exit. |
| Was the process compromised? | **no** — domain is the label, the process is the label's holder. |
| What did the attacker read? | **no** — every access vector cache decision is one access, not the whole read. |

Each row pairs a plain-English question with the shape of the answer — or
the shape of the silence. An AVC can answer the *what was attempted*
question; every other question lives in the audit record, not in the policy.

::: try host-side audit reading

Run these on a RHEL host. Each line is host-only state — each one changes
the machine once.

```bash
$ ausearch -m avc -ts today | tail
# Top-of-today's denials — no filter, every denial today.

$ aureport --avc --summary
# Per-domain denial counts — what the soak report numbers against.

$ auditctl -w /tmp/soak-scratch -p wa -k soak-scratch
# Adding a watch rule on /tmp/soak-scratch. It captures every access, regardless of context.

$ auditctl -W /tmp/soak-scratch
# Removing the watch rule afterwards — the state change is undone.
```

Each step produces state. `tail` on `ausearch` shows you what was today's
last denial. `aureport --summary` shows you the per-domain totals. `auditctl
-w` adds a watch rule — every access to the path is now captured by audit,
regardless of domain or policy. `auditctl -W` removes it — the state change
is undone.

:::

:::: why each command produces state — each produces the answer to a question
The AVC alone is *what was attempted*; the audit record is *what happened*. Each has a different audience, each needs a different form, each is the same story in different language. `ausearch` and `aureport` read the kernel's decision back into a form humans can reason about; each query selects a different lens. `auditctl -w` adds a watch rule — that is the state change, every access to the path is now captured by audit regardless of domain or policy; `auditctl -W` removes it — the state change is undone. Each step produces evidence; each step produces the answer to a question about the same log.
::::

## What you can do now

The audit pipeline is complete: the kernel emits, `auditd` writes, tools read,
and each tool answers a different question about the same log. Each setting
in `/etc/audit/auditd.conf` governs a retention variable; each mis-set value
hides a denial. Each command shown above — `ausearch`, `aureport`, `audit2why`,
`auditctl` — produces state; each produces evidence; each produces the
answer to a question.

Every question is recoverable. The AVC alone is the *what was attempted*;
the audit record is the *what happened*. Each has a different audience. Each
needs a different form. Each is the same story in different language.
