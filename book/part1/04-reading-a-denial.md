# Reading a Denial

> Every AVC line is a question the kernel answered. The four values inside it — source type, target type, object class, and permission — are the same four values every allow rule writes. Learning the anatomy of that line turns every log file from a firehose into a single review task.

Chapter 1 told you the loop: *a denial is a question and the loop is the answer.* Chapter 2 explained what the kernel asks. Chapter 3 taught you to read the labels. Now comes the practical part: what the line itself looks like, what each field means, how the tooling reads it, and how to turn one line into the rule that answers it.

## The anatomy of one AVC line

Every AVC line is an `audit.log` record the kernel wrote at the moment a request reached a security hook. A full line reads like this, from the fixture `01-mislabeled-var-lib`:

```text
type=AVC msg=audit(1710000100.000:200): avc:  denied  { write } for  pid=1234 comm="python3" name="data.log" path="/var/lib/myapp/data.log" dev="vda4" ino=12345 scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=1
```

Each segment is a piece of information. Reading them left to right:

| Segment | What it carries | Why it matters |
|---------|-----------------|----------------|
| `msg=audit(1710000100.000:200)` | Timestamp and audit serial | Correlates with other events, feeds retention policies |
| `avc: denied { write }` | The operation — here `write` | Names the single permission the request asked for |
| `pid=1234 comm="python3"` | Process identity | Links the rule to the running program; useful for triage |
| `name="data.log" path="/var/lib/myapp/data.log"` | Target file | Names the object the process tried to reach; present when the target was a file or directory |
| `dev="vda4" ino=12345` | Device and inode | Full provenance, rarely needed in review |
| `scontext=system_u:system_r:myapp_t:s0` | **Source context** | The running process; the type — `myapp_t` — is the side the rule names first |
| `tcontext=system_u:object_r:var_lib_t:s0` | **Target context** | The object being accessed; the type — `var_lib_t` — is the side the rule names second |
| `tclass=file` | Object class | `file`, `dir`, `tcp_socket`, `process`, … — each class only exposes a subset of permissions |
| `permissive=1` | Permissive flag | The source domain was permissive — the request succeeded but the line was still written; in enforcing mode it reads `permissive=0` or is absent |

A note on `scontext` and `tcontext`: both are *full* contexts. The four colon-separated fields — user, role, type, level — all travel together, and the type is always the third field. The permissive flag is a per-domain state; the host may still be `Enforcing`. Chapter 5 covers the difference in full; for now, treat `permissive=1` as "this would have broken in Enforcing".

The same shape appears across all three deterministic fixtures. The `12-execmem-review` fixture shows the bare minimum form — no `name`, no `path`, no `dev` or `ino`:

```text
type=AVC msg=audit(1710000300.000:301): avc:  denied  { execmem } for  pid=1234 comm="java" scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:system_r:myapp_t:s0 tclass=process permissive=1
```

Notice the source and target carry *the same type* here (`myapp_t`); the target is a process, not a file. The `02-port-bind` fixture shows the network case:

```text
type=AVC msg=audit(1710000150.000:210): avc:  denied  { name_bind } for  pid=1234 comm="python3" src=8888 scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=1
```

The `src=8888` field is the port number; no `path` here — the target is a socket.

::: why The type is the third field, each time. Look at the third field first. The rule you write names types; never the user, never the role, never the level. Chapter 3 spends half its page proving the same point; this callout saves a paragraph each time you re-read the string.
:::

## The tooling in order

Each command answers a different question about the same line.

| Tool | Command | Answer it gives you | When to reach for it |
|------|---------|---------------------|----------------------|
| `ausearch -m avc -ts recent` | Pulls every AVC from the audit log | *What is happening right now?* | First thing on the host; gives the raw lines |
| `ausearch -i` | Decodes identifiers (PIDs, users, files) | *Who owns this process? which file was it? what does this UID belong to?* | When you need the human-meaning behind the machine identifiers |
| `aureport --avc` | Summarises denials into per-process / per-host reports | *What is the volume? which process denies most?* | For dashboards and on-call triage |
| `audit2why` | Reads one line, finds the allow rule that is missing | *Is this denial covered by existing policy?* | Before adding a rule — answers "should we add, or should we relabel / change the code?" |

The most common mistake is piping `audit2allow` directly into `semodule -i`. That command is a *generator* — it emits the smallest rule that removes the denial on that tuple. It is **not** a reviewed artifact and it is **not** a command to install. `audit2allow` names the target type, but never the review: is that target type a category covering thousands of files? Is the permission appropriate for the code path? Every generated rule becomes a pull request that CI gates before it ships. Chapter 16 covers the gates in full; Chapter 17 covers how a human reads the diff.

## Why adding one rule reveals the next denial

A rule names a tuple: source type, target type, class, permissions. Each hook on the kernel makes an independent decision. When you add an allow for `write` on a file, the next hook that runs — `open`, or `getattr`, or `append` — decides again. If the first rule only names `file:write`, but the code path also needs `dir:add_name` to create the file first, or `file:open` to read back what it just wrote, the second request trips the second denial.

```text
# Rule 1 — the quick fix:
allow myapp_t var_lib_t:file write;        # clears the write denial

# Rule 2 — it was not enough:
avc: denied { open } for pid=1234 comm="python3"
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:var_lib_t:s0
  tclass=file permissive=0
```

The `open` denial here is not a regression. It is the same tuple, but a *different permission*, and the first rule never named `open`. The second rule names the class `file` again but the permission `open`. The mechanism is identical on the directory case: `allow myapp_t var_lib_t:dir search;` clears the first `dir:search` denial, and then the code calls `mkdir`, which needs `add_name` on the directory — the second denial names a second permission on the same tuple. The audit log keeps writing the same question with different answers, because each request is judged on its own merits. This is the single most common "but I added the rule and it still fails" trap, and the one the generator subtracts for you: the `cli/avc_preprocess.py` `subtract_covered` call matches merged needs against existing `allow` lines and splits each need into net-new versus already covered.

## Coalescing and rate limiting

The AVC is the *Access Vector Cache*. Each tuple of (source type, target type, class, permission) is remembered. If the same tuple fires fifty times in one second, the kernel may log only the first, and auditd may coalesce the rest. This has two consequences:

1. **A single line can represent thousands of attempts.** Do not read `count=1` as "the service failed once"; read it as "the kernel decided once and the log is quiet about repeat attempts".
2. **A silence during a storm is not proof of absence.** When the audit subsystem is rate-limited, the log may drop lines. Treat the visible denials as the *lower bound*. A missing line during a denial storm is normal — do not assume the second code path is fine because nothing showed up in the log.

This is also why the permissive flag matters: a permissive domain logs on every attempt, so the volume you read from a permissive box is the true volume, not the throttled volume.

## A worked reading — the `01-mislabeled-var-lib` fixture

This fixture is the canonical example for Chapter 9. Read it line by line.

```text
avc:  denied  { write } for  pid=1234 comm="python3"
  name="data.log" path="/var/lib/myapp/data.log"
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:var_lib_t:s0
  tclass=file permissive=1
```

The tuple is: *process `myapp_t` asked to `write` a file labelled `var_lib_t`*. The file sits under `/var/lib/myapp`, a path the application owns. The `python3` process is the running domain. The denial has a permissive flag: the application kept writing, but every attempt was logged — the true volume is the line count on the box.

The **naive fix** is `allow myapp_t var_lib_t:file write;` — that clears the denial on this tuple. The process writes the next batch of log entries. And then it calls something that needs `dir:write` to create a sibling file, or `file:open` to read its own output back — the second denial follows.

The **correct answer** is two changes: one line of file-context policy, naming the dedicated type for this path (`myapp_var_lib_t`), and one run of `restorecon` at deploy time. After `semodule -i` the policy allows `myapp_t` → `myapp_var_lib_t` for write, and `restorecon` moves the existing inode to `myapp_var_lib_t` — the type that matches the allow. No rule is needed on `var_lib_t`; the generic type never sees the domain. Chapter 9, `09-file-contexts-and-the-label-lifecycle.md`, walks the full lifecycle. Chapter 14, `14-the-verdict-table.md`, classifies this fixture as `fc_drift` and names the dedicated target type in `expected.json` as the verdict.

## The `permissive=1` case — a silent failure

Every line in the fixtures carries `permissive=1`. That is not decoration: it is the operating condition for staging and soak. A permissive domain logs on every attempt; the application keeps running. An admin looks at the service and sees health. The alert fires only when the *net-new access needs* exceed the threshold.

```text
::: warn
`permissive=1` is not success.
The application runs while being denied. An intermittent data path failure, or a security control that silently does nothing, is common. Read this flag as "this would have broken in Enforcing" — and treat every net-new denial during soak as a blocking signal, even though the service appears healthy.
:::

When you take a domain off permissive, the first denial after that flip is not a regression. It is the state you already knew about: the application failed while permissive, the log carried the memory. Enforcing surface that condition.

## Exporting evidence — the way this repository does it

The audit log contains every domain on the host. `policy_out/avc.log` does not; it carries only the lines relevant to the application being reviewed. `scripts/monitor_avc.sh` performs that filtering during permissive soak: it queries each named domain across a window (`--since`, default `recent`), filters by path substrings, and runs `cli/soak_net_new.py` against the matches to classify each as net-new or covered. The script needs root or a SELinux-enabled RHEL host — `ausearch` and `/var/log/audit/audit.log` are not present on a laptop — and its failure mode is "soak_net_new.py missing on this host" or "sesearch / policy.kern failed".

The output it produces is structured: a JSON payload with the domain, the count, the net-new threshold, the fail-closed reason, and the last ten matching event lines. On `rhel-qa`, this is the command that keeps the canary honest:

```bash
# On rhel-qa, as root
$ sudo bash scripts/monitor_avc.sh --domain myapp_t --paths "/var/lib/myapp,/run/myapp" --max-avc 100 --max-net-new 3
```

On a laptop without SELinux, the same reading works against the fixture:

```bash
$ cat docs/examples/fixtures/deterministic/01-mislabeled-var-lib/avc.log
```

The fixture log is the deterministic replay: no host required, no `ausearch`, no kernel policy. It is the form readers pull for Chapter 13 when they want to follow the generator end-to-end without touching a box.

::: try Read denials on your own host
Nothing changes state; only reads.

```bash
# On rhel-qa, as a privileged user
$ sudo ausearch -m avc -ts recent | tail -n 5
```

If the box is quiet you will see nothing — a host denies nothing that is not already handled. Chapter 15 produces denials deliberately, so you never need a noisy production host to learn on.

```bash
# On any laptop — use the fixture
$ cat docs/examples/fixtures/deterministic/01-mislabeled-var-lib/avc.log
```

Read the six fields: `denied { permissions }`, `pid`/`comm`, `path` (or `src`), `scontext`, `tcontext`, `tclass`, `permissive`. The third field of each context is the type. The type is the only thing that gates an allow rule. The same six fields appear on every line, in every host, in every fixture.
:::

## What you can do now

- **Read a denial line and name each field.** The `permissive` flag, the type in the third field of each context, the object class, the permission. Each segment is a value, each value is a value for the rule you write.
- **Run `ausearch -m avc -ts recent` and `tail` on the result.** The output is the same six fields every time; you are training your eye on them, not looking for a specific bug.
- **Read `audit2why` on one line.** The answer is the missing allow, and the answer is the missing allow *in context* — "is this target type the right category for this rule?". Chapter 17 turns this reading into a review habit.
- **Remember that one line represents a decision, not a volume.** The coalesced log is quiet about repeat attempts; the permissive log is loud about volume. Read each state separately.
- **Read the fixture log on your laptop.** The `01-mislabeled-var-lib` fixture is the canonical file-context drift case. The naive rule on `var_lib_t` adds noise; the correct answer names a dedicated type and runs `restorecon` at deploy time. Chapter 9 takes the full lifecycle; Chapter 14 classifies the same fixture in `expected.json` as `fc_drift`.

These are all you need for the rest of the loop. The next step is a real denial on a host, Chapter 9 takes the label lifecycle in full, and Chapter 13 turns the generator's output into a reviewed pull request.
