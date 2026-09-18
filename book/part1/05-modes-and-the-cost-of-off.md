# Modes, and the Cost of Off

> A host is either enforcing, permissive for one domain, or disabled. The moment it is disabled, everything you spent the last chapters learning about becomes unreadable — denials disappear, relabeling returns, and the next incident is decided in minutes instead of days. This chapter shows how to read each mode, why the repository keeps the host enforcing while only the app domain is permissive, and what is on the line when you flip each switch.

## Four states, each reachable with one command

SELinux exposes four states, each reachable with one command or one config value. Each one answers a different question about the host.

| State | Set with | What it means |
|---|---|---|
| **Enforcing** | `setenforce 1` or `SELINUX=enforcing` in `/etc/selinux/config` | denials block; AVCs written with `permissive=0` |
| **Domain permissive** | `sudo semanage permissive -a <domain>` | denials log only for that domain (`permissive=1`); every other domain still blocks |
| **System permissive** | `setenforce 0` or `SELINUX=permissive` in `/etc/selinux/config` | every domain logs instead of blocking |
| **Disabled** | `SELINUX=disabled` in `/etc/selinux/config`; unload policy | no LSM hooks fire; no AVCs at all |

Each state is reachable without writing a rule. That is why each state costs something when it is the surprise answer.

`getenforce` answers only one of those states — it reads the *whole-system* mode. `sudo semanage permissive -l` answers the other. They are independent, and both of them are the two checks the book requires at every moment of an on-call incident.

```bash title="The two checks every on-call run"
$ getenforce
Enforcing

$ sudo semanage permissive -l
shopapi_t
```

Both of those lines agree. The host is *enforcing* globally; only `shopapi_t` (or whatever domain is on the list) is log-only. The book's rule — Chapter 1 restates it, `docs/policy/102-SELINUX_BASICS.md` §7 repeats it, `docs/admin/302-PRODUCTION_READINESS.md` §6 enforces it — is that the host *always* stays in Enforcing, and only the app's own domain is made permissive.

:::: why Two checks, not one
`setenforce 0` is the wrong answer at the level of *immediate recovery* — it stops the kernel from blocking the service. It is the right answer at the level of *immediate damage*: an attacker walks away with the Unix privileges of the account, no denials to read, no rule to review. The argument for the two checks is the same one Chapter 1 built: **cost over a year**, and **evidence at the change board**.
::::

The most common bad answer in an incident is `setenforce 0` — permissive, whole host. The most damaging bad answer is `SELINUX=disabled`. The difference is not cosmetic; it is structural.

| Condition | When it happens | What is lost |
|---|---|---|
| **Permissive** (`setenforce 0` or permissive in config) | a hotfix to restore service on the bridge | denials still appear in `audit.log`; the missing rule is legible — same four values as an Enforcing denial, only the final field differs |
| **Disabled** (`SELINUX=disabled`) | a longer-term "SELinux is a tax" decision | no LSM hooks fire. No AVCs. No `permissive=` field. The access succeeds or fails silently; the missing rule is unknowable without auditing every process |
| **Permissive-to-enforcing** transition | the pipeline flips the app domain back | *a relabel*. Every file the policy ever mentions needs a context rewrite; on a busy host with millions of inodes, that is not a change you make casually during business hours |

:::: warn A disabled host looks healthy because nothing is blocking anything
The health is a *negative*: no denials, no `permissive=` field, no audit. On a disabled host, the next incident looks like a memory leak until someone remembers to re-read the process list.
::::

## Per-domain permissive — the commands, and what changes at the hook

Per-domain permissive is *not* `setenforce 0`. It is `sudo semanage permissive -a <domain>`. Every other domain is still blocking; only processes running as the named domain get the log-only answer. The same command, reversed, is `sudo semanage permissive -d <domain>`.

| Command | What it does | Where it lives |
|---|---|---|
| `sudo semanage permissive -a <domain>` | add the named domain to the permissive list | kernel LSM — every hook on that domain now answers `permissive=1` |
| `sudo semanage permissive -l` | list every domain currently on the permissive list | read-only inspection |
| `sudo semanage permissive -d <domain>` | remove the named domain from the permissive list | kernel LSM — every hook on that domain now answers `permissive=0` again |

The permissive list is stored in the kernel's live policy DB. Every hook on the host consults it: a file access, a socket bind, a `fork` — whichever operation the hook mediates, if the source domain is on the list, the answer is `permissive=1`. Off the list, every hook answers `permissive=0`.

```bash title="Per-domain permissive, end to end"
$ getenforce
Enforcing

$ sudo semanage permissive -a shopapi_t
# success — no output; that is normal

$ sudo semanage permissive -l
shopapi_t

# ... after soak, admin enforce:

$ sudo semanage permissive -d shopapi_t

$ sudo semanage permissive -l
# (empty output — no domains listed)
```

Both phases keep `getenforce` = **Enforcing**. Only `shopapi_t` is log-only — the OS stays protected. The two-phase timeline from `docs/policy/102-SELINUX_BASICS.md` §7.5 repeats: staging discovery permissive while `dev_generate_policy.sh` collects AVCs, and canary soak permissive after the full module is installed. Both phases share the same state: **the host stays enforcing, only the app domain is log-only**.

:::: note Domain vs system permissive — not interchangeable
`semanage permissive -a shopapi_t` is *not* `setenforce 0`. The first is granularity: the hook consults a permissive list only for one domain. The second is blanket: every hook answers log-only on every domain. The book uses only the first; production workflows never run `setenforce 0`.
::::

## The two-layer model — the book's hard rule

The book's hard rule is the two-layer model: the host stays Enforcing, only the app domain is permissive. This is not a preference; it is a rule enforced by the playbooks in `ansible/roles/selinux_pac/tasks/enforce.yml` and `tasks/rollback.yml`, and by the `check_soak_ready.sh` gate in `docs/admin/302-PRODUCTION_READINESS.md` §12.

| Layer | Check | Value during canary / soak |
|---|---|---|
| **Whole-system mode** | `getenforce` | **Enforcing** — SSH, cron, systemd, every other domain stay fully protected |
| **Per-domain log-only list** | `sudo semanage permissive -l` | **`shopapi_t`** (or whatever domain is on the list) — denials log only; the app keeps working |

The enforce and rollback paths read both layers. `enforce.yml` fails when `soak_min_days` is below the production threshold (`line 16–17` of the file — the lab value `soak_min_days: 0` on `rhel-qa` is refused on a host in group `production`). `rollback.yml` switches the domain back to permissive first — stock `semanage`/Ansible module — before any RPM or module change, so the host never flips state. The soak jobs (`soak_monitor.yml`, `soak_status.yml`) read neither layer: they count events, and a mode they do not check cannot fail their gate.

## The cost of flipping back

Enforcing-to-permissive is cheap — a single command, no relabel. The way back is cheap too, as long as SELinux was never disabled: a mode flag does not touch a single inode. The expensive transition is the one people confuse with it — disabled to enabled, which relabels the whole filesystem. The book's rule is therefore *a domain rather than the host*: every flip is on the domain, not on the whole system.

| Transition | Cost | Why it matters |
|---|---|---|
| **Enforcing → permissive (one domain)** | one `semanage permissive -a` | cheap — no filesystem change |
| **Permissive (one domain) → enforcing** | one `semanage permissive -d`, then `restorecon -Rv` over the application's paths | cheap for the mode; the relabel is for files created while permissive that picked up the wrong type, so `enforce.yml` relabels `install_root`, `var_dir` and `log_dir`, and the runtime dir once the service has restarted |
| **Enforcing → permissive (whole system, `setenforce 0`) → enforcing** | nothing, both ways | free — `setenforce` moves no labels |
| **Enforcing → disabled → enforcing** | full filesystem relabel | expensive — a disabled kernel writes no labels at all, so every inode is suspect when it returns (`/.autorelabel`, then a reboot) |



:::: warn A permissive service is not a healthy service
A permissive domain lets the application keep running while being denied. A security control that silently does nothing, or a data path that fails intermittently, is common. Do not treat zero HTTP 500s during soak as evidence the policy is correct — the policy may be right about every HTTP path and wrong about every logrotate run. `check_soak_ready.sh` (see `docs/admin/302-PRODUCTION_READINESS.md` §12) gates on the soak window, the event count since the canary marker, and the deploy report — never on HTTP 200s.
::::

## Soak at this level — a domain observed permissive while the pipeline watches for net-new access

Soak is a *single domain* observed permissive, while the pipeline watches the policy's blind spot: the access the installed policy does not already allow. `docs/admin/302-PRODUCTION_READINESS.md` §3.5 spells out the daily schedule — `soak_monitor.yml` runs on the canary group and `net_new_count=0` is the gate. The raw count matters too: `monitor_avc.sh` fails when the event count exceeds `soak_max_avc`, and that default is `0`, so a repeat denial from a cron job fails the gate exactly like a new one. `net_new_count` is the number that separates them: a raw AVC the policy already covers is noise, and a net-new one is a promise the policy did not keep.

```bash title="The soak gate, as check_soak_ready.sh prints it"
$ sudo bash scripts/check_soak_ready.sh \
    --domain shopapi_t \
    --marker-file /var/lib/shopapi/selinux_canary_deployed_at \
    --report-file /var/lib/shopapi/selinux_deploy_report.json \
    --manifest config/shopapi.manifest.yml

[INFO] Soak: 8 day(s) elapsed (minimum 7)
[INFO] Events since canary deploy for shopapi_t: 0 (maximum 0)
[INFO] Deploy report confirms endpoint coverage and domain context
[INFO] Soak gate passed — safe to enforce shopapi_t
```
:::: warn `soak_min_days: 0` is lab-only
The lab inventory (`ansible/inventory.dev.yml`) sets `soak_min_days: 0` so the pipeline can demonstrate the whole loop without waiting. Production inventories refuse that value — `enforce.yml` line 16–17 fails when `soak_min_days < 7` on a host in group `production`. Do not copy that value onto prod without documented break-glass approval and on-call awareness.
::::


## Your turn — on `rhel-qa`

Nothing here changes state — only reads.

```bash title="On rhel-qa, as a privileged user"
$ getenforce
Enforcing

$ sestatus | head -n 5
    SELinux status:                 enabled
    SELinuxfs mount:                /sys/fs/selinux
    SELinux root directory:         /etc/selinux
    Loaded policy name:             targeted

$ sudo semanage permissive -l
# (empty — nothing listed; every domain is enforcing)

$ grep ^SELINUX= /etc/selinux/config
SELINUX=enforcing
```

Each line answers one state. `getenforce` answers the whole-system state. `sestatus` answers both: the *status* and the *policy name* loaded. `sudo semanage permissive -l` answers the per-domain state — and the empty result tells you that every domain on the host is still fully protected. `/etc/selinux/config` answers the persistent state — if someone logs in and runs `setenforce 0`, the next reboot re-reads the config file.

:::: try Read each of those four states on your own host
Nothing here changes state; every command is read-only. If `semanage permissive -l` shows a domain, that domain is on the list and every hook on it answers `permissive=1`. If `/etc/selinux/config` shows `SELINUX=permissive`, the next reboot will run permissive unless somebody changes it.
::::

## What you can do now

- **Name every state a host can be in.** Enforcing, domain permissive, system permissive, disabled — each reachable with one command or one config line.
- **Read the two checks every on-call run.** `getenforce` answers the whole-system state; `sudo semanage permissive -l` answers the per-domain state. Both of them are required; each of them is independent.
- **Say which state is worse, and why.** `disabled` is worse than `permissive` because no records exist, and re-enabling triggers a full relabel; on a disabled host, the next incident is decided in minutes instead of days.
- **Name what each command does at the kernel hook.** `sudo semanage permissive -a` adds a domain to the permissive list — every hook on that domain answers `permissive=1`; `sudo semanage permissive -l` lists every domain currently on the list; `sudo semanage permissive -d` removes a domain — every hook on that domain answers `permissive=0` again.
- **Read permissive as "this would have broken in Enforcing."** A permissive service looks healthy while guarded operations are denied; zero HTTP 500s during soak is not evidence the policy is correct — the policy may be right about every HTTP path and wrong about every logrotate run.
- **Name the book's hard rule.** The host stays Enforcing; only the app domain is permissive. Every flip is on the domain, not the host, and a mode flip moves no labels — the relabel belongs to the disabled-to-enabled path.
- **Name the soak gate.** Marker age ≥ 7 days; events since the marker within `soak_max_avc`; net-new access needs at zero; deploy report signed off — `check_soak_ready.sh` prints the pass line, `enforce.yml` flips the domain back to enforcing, the deploy report records that every endpoint still returned 200.
- **Name the trap.** `soak_min_days: 0` is lab-only; production inventories refuse it — `enforce.yml` fails on a host in group `production` when the value is below 7.
- **Read each line of `audit.log`.** The `permissive=` field is the only difference between `permissive=0` and `permissive=1` — the missing rule is the same tuple; the difference is only the flag.

Chapter 6 moves to the policy language itself — the files that make a module, the type system underneath them, and the decisions that separate a reviewable rule from a dangerous one.
