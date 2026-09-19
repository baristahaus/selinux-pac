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
| **`max_log_file`** | Maximum size of each log file (MiB). | Set too low — the log wraps and overwrites old denials before you read them. |
| **`num_logs`** | Number of historical copies to keep before the oldest is dropped. | Set to zero or one — the oldest file, where an early denial lived, is gone by the time you reach it. |
| **`space_left`** | Free space (MiB, or a percentage such as `5%`) before `auditd` escalates. | Set too low — the first warning arrives after the wrap has already begun. |
| **`admin_space_left`** | Free space (MiB or `%`) at which the emergency action fires. | Set too low — no operator wakes before logging stops. |
| **`space_left_action`** | Action on reaching `space_left`. | **Default: `SYSLOG`.** A warning line in the system log and nothing else: the host keeps writing audit records until the next threshold. |
| **`admin_space_left_action`** | Action at the emergency threshold. | **Default: `SUSPEND`.** `auditd` stops writing records to disk; the host keeps running and the trail goes quiet. |
| **`max_log_file_action`** | Action when a file exceeds `max_log_file`. | **Default: `ROTATE`.** Each wrap starts a new file; the oldest is dropped. |
| **`disk_full_action`** | Action when no space is left. | **Default: `SUSPEND`.** Same silence: no space, no new records, no outage to alert anyone. |
| **`disk_error_action`** | Action on a disk error while writing. | **Default: `SUSPEND`.** A failing disk stops the audit trail without stopping the workload. |
| **`q_depth`** | Depth of the internal queue between the kernel and `auditd`'s child processes. | **Default: 2000.** A denial storm fills the queue faster than it drains, and the events that no longer fit are lost — see `overflow_action`. |
| **`overflow_action`** | Action when that queue overflows. | **Default: `SYSLOG`.** The overflowing events are dropped; the log keeps its warning line, not the denials. |

The values above are the defaults shipped in the sample `auditd.conf`; the three stages are `space_left` (first warning, `SYSLOG`), `admin_space_left` (emergency, `SUSPEND`), and a completely full partition (`disk_full_action`, `SUSPEND`). **`SUSPEND` stops the write while the host keeps serving** — the app is still being denied, and the audit trail simply stops saying so. Only `single` puts the machine into single-user mode and locks the admin out; `halt` is deprecated as an action. Read what your host actually runs before trusting any of it:

```bash
$ grep -E '^(max_log_file|num_logs|space_left|admin_space_left|space_left_action|admin_space_left_action|disk_full_action|disk_error_action|q_depth|overflow_action) =' /etc/audit/auditd.conf
max_log_file = 8
num_logs = 5
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
q_depth = 2000
overflow_action = SYSLOG
```

## `ausearch` in practice

Every question asks about the same log. Each query selects a different lens.

| Query | What it answers |
|-------|-----------------|
| **`ausearch -m avc -ts today`** | *What did the policy block today?* Without `-ts` the search covers the whole log range, not today. |
| **`ausearch -ts recent`** | *What happened in the last ten minutes?* (the keywords are `now`, `recent` — ten minutes — `this-hour`, `boot`, `today`, `yesterday`, `this-week`, `week-ago`, `this-month`, `this-year`, and `checkpoint`.) |
| **`ausearch -ts 09/17/2026 14:00:00`** | *What happened during this window?* The date must match your locale — `date +%x` prints the format `ausearch` will accept. |
| **`ausearch -p 1234`** | *What did this process do?* |
| **`ausearch -i`** | *What does this log look like to a human?* (interprets uids and contexts into names.) |
| **`ausearch --format csv`** | *What do I get back for downstream tooling?* (one normalized CSV row per event; `--format text` is the opposite — an English sentence with the detail dropped.) |

Combine them when you need all three. The order of selection is
independent — each filter applies to every record before the tool prints.

The `--subject` filter is the per-domain search — every denials page in this
book starts with it: `ausearch --subject myapp_t`. That gives you only the
denials that belong to your domain. Everything else is the OS's noise.

## `aureport`

Each report type answers a different question about the same log.

| Report | What it answers |
|--------|-----------------|
| **`aureport --avc`** | *Which AVCs fired, in order?* — one row per event, with the subject and the target. |
| **`aureport --summary`** | *How much did the policy block in total?* — the main summary report, with a `Number of AVC's` line. |
| **`aureport --failed`** | the *Failed Summary Report* — counts per category, not per event. For the rows, add the report: `aureport --syscall --failed` prints `# date time syscall pid comm auid event`, which is how you find a service that fails quietly. |

The soak path does its own counting, per domain rather than in total: `scripts/lib/avc_query.sh` converts the marker's epoch with `avc_epoch_to_ts` (epoch seconds are not a valid `-ts` value) and then runs `ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -ts "<MM/DD/YYYY HH:MM:SS>" --subject <domain> --format raw`, counting the `type=AVC` lines. **That** is the number the soak gate compares against the marker's deploy epoch — `aureport` is for reading, not for gating.

## Reconstructing an event

An AVC alone tells you *what was attempted, by which domain, on which target,
and whether it was blocked*. It does not tell you what happened before,
what happened after, or who started it.

The audit serial is the thread. Every record that belongs to one syscall carries the same number in `msg=audit(…:N):` — the AVC, the `SYSCALL`, the `CWD`, the `PATH`. Take the number from the AVC and ask for the whole event:

```bash
$ ausearch -m avc -ts recent | head -n 1
type=AVC msg=audit(1758110412.417:844): avc:  denied  { write } for  pid=4123 comm="report" ...
#                                        ^^^ event id 844

$ ausearch -a 844 -i
# every record that shares event id 844: the SYSCALL that made it, the PATH it touched, the CWD it ran from
```

`-a` is the event id, and it is the only filter that returns the whole action chain. An added `--uid 0` narrows the same search to events that ran as root — useful when the denial arrived from a `sudo` session, useless as a correlation of its own. The syscall record is the full action chain: the `execve` that launched the process, the `open` that reached the target, the `exit` that finished it. The AVC alone is the *access vector cache* — one
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

`audit2why` reads each AVC line and prints *why* the policy refused it — a missing type-enforcement allow, a file whose label is wrong, a boolean that is off, a port whose type was never registered. It does not write policy; `audit2allow` is the tool that prints candidate `allow` rules.

```bash
$ ausearch -m avc -ts recent | audit2why
type=AVC msg=audit(1758110412.417:844): avc:  denied  { write } for  pid=4123 comm="report" name="audit" ...
	Was caused by:
		Missing type enforcement (TE) allow rule.

		You can use audit2allow to generate a loadable module to allow this access.
```

The classification is the useful part. The repository reads it the same way: `cli/tune_report.py` sorts each `audit2why` answer into `boolean`, `label`, `port`, or `te`, and compares that against the verdict its own classifier reached — when the two disagree, the report says so rather than papering over it.

```bash
$ bash scripts/dev_generate_policy.sh --tune-report --app-name tomcat
```

The mechanics live in earlier chapters — Chapter 6 covers the module files and the install path,
Chapter 8 covers every `allow` rule, Chapter 5 covers the permissive-versus-enforcing decision, and
Chapter 9 takes the label lifecycle. `audit2why` is the translation step between the log and the
policy — what `audit2allow` prints for the same tuple is the candidate the generator's PR carries.

## Evidence for two audiences

Two audiences read the same log. Each audience needs the same story in a
different form.

### Incident review

An incident review needs: *what happened, when, to which process, under which
context, and when is it still visible*.

```bash
$ ausearch -m avc --subject shopapi_t -ts this-week -i
```

Each line returns the serial, the timestamp, the subject, the target, and
the operation. Pair each line with a retention note:

- retention window is `max_log_file × num_logs`.
- on wrap, the oldest records go.
- on `disk_full_action=SUSPEND` (the shipped default), the writes stop and the records that would have been written are gone — the host keeps running while the trail stops.

### Policy PR

The policy generator needs: *each unique denials tuple, deduplicated, with
the manifest paths that triggered them*.

The repository's export path is the pipeline already in `monitor_avc.sh`
and `lib/avc_query.sh`. These are sourced shell functions, not commands on
`PATH`, so the entry point is the script that sources them:

```bash
# The whole export in one command — what dev_generate_policy.sh runs for you:
$ bash scripts/dev_generate_policy.sh --skip-export --app-name shopapi \
    --avc-log policy_out/avc.log          # operates on a log you already captured
$ bash scripts/dev_generate_policy.sh   # capture + classify, on rhel-qa

# Reading the library directly (source it first):
$ source scripts/lib/avc_query.sh
# export_app_avcs_to_file OUTFILE [SINCE_TS] PRIMARY_DOMAIN [BACKEND_DOMAIN] PATHS_CSV
$ export_app_avcs_to_file policy_out/avc.log boot shopapi_t shopapi_backend_t /var/lib/shopapi,/var/log/shopapi

# Then subtract what the installed policy already allows, and see what is left:
$ python3 cli/verify_avc_coverage.py \
    --avc-log policy_out/avc.log \
    --te selinux/myapp.te \
    --manifest config/myapp.manifest.yml
```

`monitor_avc.sh` is the daily soak view of the same library: it runs the same
`ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR --subject
<domain> --format raw` query and reports the count against `--max-net-new`.

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
$ auditctl -a always,exit -F arch=b64 -S execve -k execve
# Same rule for 32-bit binaries on a 64-bit host:
$ auditctl -a always,exit -F arch=b32 -S execve -k execve
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

Run these on a RHEL host. The first two only read the log; the `auditctl` pair writes and then undoes one piece of host state.

```bash
$ ausearch -m avc -ts today | tail
# The last few denials from today — no filter, every denial the log holds.

$ aureport --summary | grep -i "AVC"
# Total AVCs in the whole log — the fast sanity number, not the per-domain one.

$ auditctl -w /tmp/soak-scratch -p wa -k soak-scratch
# Adding a watch rule on /tmp/soak-scratch. It captures every access, regardless of context.

$ auditctl -W /tmp/soak-scratch
# Removing the watch rule afterwards — the state change is undone.
```

Each step produces state. `tail` on `ausearch` shows you what was today's
last denial. `aureport --summary` totals the log. `auditctl
-w` adds a watch rule — every access to the path is now captured by audit,
regardless of domain or policy. `auditctl -W` removes it — the state change
is undone.

:::

:::: why watch rules and AVCs are different instruments
The AVC is *what the policy refused*; the watch and execve rules are *what happened*, whether or not the policy was consulted. A `restorecon` that relabels a tree fires the watch rule and writes no AVC; a `setsebool` that flips an allow turns the next access into a success and leaves the AVC count unchanged. Each instrument answers a different question about the same log.
::::

## What you can do now

- **Read** the pipeline: the kernel emits, `auditd` writes, tools read — and know which component loses events when the disk fills or the queue overflows.
- **Check** the retention knobs before you need them: `max_log_file × num_logs` is how far back you can see, and `SUSPEND` is how the log goes quiet without an alarm.
- **Ask** each tool its own question — `ausearch` for the event, `aureport` for the count, `audit2why` for the reason, `auditctl` for what SELinux never saw.
- **Follow** the event id (`ausearch -a <id>`) rather than the AVC line alone; the syscall record around it is what tells you who started the process and what it did next.
- **Count** denials the way the soak does, per domain since the deploy epoch, so the number you quote is the number the gate uses.
