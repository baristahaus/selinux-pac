# Command Reference

> Every page in this manual builds on a small handful of kernel-facing commands. Keep the
> short list in your head: `getenforce`, `ls -Z`, `restorecon`, `ausearch`, `audit2allow`,
> and the single Makefile line that actually compiles your module. Each section names the
> exact invocation this book relies on.

## See the mode and the state

The host tells you whether it is enforcing, permissive, or permissive-system — and these
commands each show one slice of that status. All four must be run on a SELinux host.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `getenforce` | Returns `Enforcing`, `Permissive`, or `Disabled` — the kernel's current decision state | `rhel host` |
| `sestatus` | Policy version, current mode, and which policy types are loaded on the box | `rhel host` |
| `semanage permissive -l` | Lists every domain currently running in permissive mode; useful before you trust a denial | `rhel host`, `root` |
| `cat /etc/selinux/config` | Shows the `SELINUX=` and `SELINUXTYPE=` values the host will use on the next boot; never `getenforce`'s answer | `rhel host`, `root` |

:::: why Each of these answers a different question
`getenforce` is "is it currently blocking", `sestatus` is "what is the policy version",
`semanage permissive -l` is "which domains are we tolerating", and `/etc/selinux/config` is
"what would we be on reboot". They answer different slices of the same truth — and they
routinely disagree, which is the point: `setenforce 0` leaves `getenforce` saying `Permissive`
while the config file still says `SELINUX=enforcing`, and a kernel `enforcing=0` changes the
running state without touching either. Never read one as proof of another.
::::

## See labels

SELinux makes labels *visible* the moment the kernel decides: every access asks the label.
These commands each show a different side of the label surface.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `ls -Z` | Object labels on the path you name — the third field, the type, is what the kernel actually checks | `rhel host` |
| `ps -eZ` | All running processes: domain (third field), role, user, level | `rhel host` |
| `id -Z` | Your own shell's context — useful when you are debugging a user-space failure | `rhel host` |
| `getfattr -n security.selinux <path>` | The extended-attribute value the file actually holds, even if `ls -Z` cannot see it | `rhel host` |
| `matchpathcon <path>` | "What label **should** this path have", per `/etc/selinux/<type>/contexts/files/` — the answer you compare to what is on the box. `-m <kind>` forces the lookup for a file type (`file`, `dir`, `pipe`, `chr_file`, `blk_file`, `lnk_file`, `sock_file`); `-V` verifies the context on disk against the default and prints only the mismatches | `rhel host` |

:::: note `ls -Z` is the one command you never forget
Because every access decision names the object's label, `ls -Z` is the most useful command
in this book. When a file label is wrong, every other command in this appendix is the answer;
when a process label is wrong, the second set is the answer.
::::

## Fix labels

These commands repair the gap between the label a path *should* have and the label it *has*.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `restorecon -R -v <path>` | Re-applies the expected label from `/etc/selinux/.../contexts/files/` to the target and its children; `-v` is verbose | `rhel host`, `root` |
| `semanage fcontext -a/-l/-d <path>` | Add, list, or delete a file context rule — used when `restorecon` cannot find the rule | `rhel host`, `root` |
| `fixfiles relabel` | Relabels every mounted filesystem in place; it prompts about `/tmp` first (deleting those files is the one destructive option) | `rhel host`, `root` |
| `fixfiles onboot` | Schedules a relabel for the next boot (writes `/.autorelabel`) — this is the one that needs a reboot and a maintenance window | `rhel host`, `root` — **warning: reboot** |

::: warn `fixfiles` is the nuclear option
`fixfiles relabel` re-labels *every* mounted filesystem, in place, while the host runs — and it
asks first whether to delete the contents of `/tmp`, which is the part that destroys data.
`fixfiles onboot` is the other shape: it schedules the relabel for the next boot, which is the
one that costs a maintenance window. Use either only when the file context set itself has
drifted at scale, never for a single path — that is `restorecon`.
:::

## Ports

SELinux labels TCP/UDP ports by category: each process that `bind()`s on a port asks for
the `name_bind` allow, and the port's type tells the answer.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `semanage port -a/-m/-d/-l` | Add, modify, delete, or list port type definitions. The repository's port registrations are driven from the manifest's `selinux_ports` (Ansible `seport`, or the packaged `ports_from_manifest.cil` where `semanage` is absent) — `semanage port -a` is the command you run by hand to inspect or repair, not the one the pipeline uses on production | `rhel host`, `root` |

## Booleans

Booleans are the policy's switch: each one toggles an allow that the vendor policy shipped
by default. They never persist in a `.te` module — they persist in the loaded policy.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `getsebool -a` | Lists every boolean and its current state | `rhel host`, `root` |
| `setsebool -P <name>=<value>` | Sets the boolean for the running policy; `-P` is the persist flag that also writes `/etc/selinux/.../semanage_boolean` | `rhel host`, `root` |

::: note `-P` is the only flag that matters
`setsebool` without `-P` is a change that unsets itself on the next policy load. Every
production host carries `-P`; every lab host carries `-P`.
:::

## Modules — compile, install, remove

These commands each own a different step of the policy module lifecycle. Each invocation
is verified against `scripts/compile_and_validate.sh` and `scripts/lib/compile_policy.sh`.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `semodule -i <module>.pp` | Loads a compiled module binary into the running policy | `rhel host`, `root` |
| `semodule -l` | Lists every module loaded into the running policy | `rhel host`, `root` |
| `semodule -r <name>` | Removes a module from the running policy; unloads its rules | `rhel host`, `root` |
| `checkmodule` | Compiles a single policy source file into a binary module (`checkmodule -M -m myapp.te -o myapp.mod`); it never reads a `.fc` | `build host` |
| `semodule_package` | Wraps that binary module plus its file contexts into the installable package (`semodule_package -o myapp.pp -m myapp.mod -f myapp.fc`) | `build host` |
| `make -C <work_dir> -f /usr/share/selinux/devel/Makefile <name>.pp` | The canonical refpolicy build invocation: copies `.te`/`.fc`/`.if` into a work directory, runs `make` there, and emits `<name>.pp` | `build host` |

::: why the Makefile is the only build line
The repository's `scripts/compile_and_validate.sh` calls the `make -f /usr/share/selinux/devel/Makefile`
line for every module: the single invocation this book relies on, no shims, no custom wrapper.
Each module named in the build gets its own invocation (see the Makefile: `compile_and_validate.sh`
is re-run for `payments` and `shopapi` as well as `myapp`).
:::

## Query the installed policy

These commands each let you ask the loaded policy what it allows. The questions you ask
each one are different — `sesearch` is a rule lookup, `seinfo` is an attribute lookup, and
`sepolgen-ifgen` is a database build for the generator.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `sesearch -A -s <src_t> -t <tgt_t> -c <class> -p <perm>` | Searches the running policy for matching `allow` rules; returns each rule verbatim | `rhel host`, `root` |
| `seinfo -a <attribute> -x` | Lists every type that carries `<attribute>`. It reads the binary policy — the running one, or a `--policy <policy.kern>` file — and ships in `setools-console`, the same package as `sesearch` | `rhel host`, `root` |
| `sepolgen-ifgen` | Builds the interface database interface matching reads: it parses the refpolicy headers under `/usr/share/selinux/devel` and reads the binary policy's attributes, then writes `/var/lib/sepolgen/interface_info`. It generates no `.if` files — those ship with `selinux-policy-devel` | `rhel host`, `root` |

::: note The generator asks the database, not a hint command
Interface suggestions in this book come from `sepolgen` reading the database that
`sepolgen-ifgen` builds — the same path `cli/deterministic_gen.py` takes. If the database is
missing, the generator says so and refuses base-type AVCs unless you pass `--allow-degraded`;
it never guesses an interface from the running policy.
:::

## Audit

These commands each look at a different slice of `audit.log`:

| Command | What it tells you or changes | Needs |
|---|---|---|
| `ausearch -m avc -ts recent` | Filters `audit.log` for AVC events since a time; `-ts` takes the keywords `now`, `recent`, `this-hour`, `boot`, `today`, `yesterday`, `this-week`, `week-ago`, `this-month`, `this-year`, or a date/time pair in your locale's format (`date +%x` prints it). Epoch seconds are not accepted | `rhel host`, `root` |
| `aureport --avc -i` | The AVC report — one row per denial with its subject and target. (`-au/--auth` is the authentication report, not this one) | `rhel host`, `root` |
| `audit2why` | Names the cause of each denial — missing type-enforcement allow, wrong label, boolean, port — and tells you to use `audit2allow`. It does not print rules | `rhel host`, `root` |
| `audit2allow` | Converts each AVC into an allow rule verbatim; output is a suggestion requiring review, never piped directly into `semodule -i` | `rhel host`, `root` |

::: warn `audit2allow` is the most dangerous command in the book
The output of `audit2allow` is a raw `allow` per AVC — broad enough that a single run can
turn `myapp_t` into `unconfined_t`. Read it; review it; never pipe it into `semodule -i`.
This book's generator produces the same rule set, but gated by `validate_forbidden_patterns.sh`.
:::

## This repository's own entry points

Each invocation is verified against the script or Makefile that owns it. No inferred flags,
no guessed defaults.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `make check` | Offline health check: `test` (fixtures + static + smoke), `lint`, `book-check`; no SELinux host required, but the `deps` step wants `pip3` and the linters skip themselves when absent | `laptop` |
| `make test-fixtures` | Runs `scripts/run_deterministic_fixtures.sh`, `scripts/run_deterministic_payments_check.sh`, `scripts/run_blast_radius_fixtures.sh`, and `scripts/run_tune_report_fixtures.sh` | `laptop` |
| `make book` | Builds the HTML manual into `site/` via `python3 tools/book/build.py` | `laptop` |
| `make book-check` | Validates the manual (internal links, anchors, `repo:` references) via `python3 tools/book/build.py --check` | `laptop` |
| `bash scripts/dev_generate_policy.sh` | Developer self-service: export AVCs → run `cli/deterministic_gen.py` → generate policy → diff → promote into `selinux/`; supports `--apply`, `--tune-report`, `--force REASON`, `--allow-needs-review`, `--skip-export`, `--open-pr` | `build host` (for promote) / `laptop` (for explain) |
| `bash scripts/setup_rhel_hosts.sh doctor` | `getenforce`, `ausearch`, and `sesearch` probes on each RHEL host — configured in `inventory.dev.yml` and `inventory.production.yml` | `rhel host`, `root` |
| `ansible-playbook` (canary) / `ansible-playbook` (soak) | Deploys the canary module (`part4/19-canary-soak-enforce.md`) or runs the daily soak monitor — `soak_monitor.yml` calls `monitor_avc.sh --manifest … --max-net-new …`, `soak_status.yml` calls `collect_soak_facts.sh`. (`check_soak_ready.sh` is the host-side CLI for the same checks; the role itself runs `collect_soak_facts.sh`) | `controller`, `rhel host` |

::: note `make test-fixtures` is the smoke test for the generator
Because every classification verdict has at least one golden fixture under
`docs/examples/fixtures/deterministic/`, this target catches drift before it ships.
A failing fixture is the same signal as a failing test — CI fails, the PR is blocked.
:::

## What you can do now

- Pick one host, run `getenforce`, `sestatus`, `id -Z`, and `ls -Z /var` — you now own the
  four slices of truth that each command answers.
- Find a mislabeled file: `matchpathcon` against `restorecon` against `semanage fcontext -l`.
- Compile a policy module: `bash scripts/compile_and_validate.sh selinux` on the build host.
- Read an AVC, suggest an allow, and write a diff: `bash scripts/dev_generate_policy.sh --skip-export --app-name <app>`.
- Gate a dangerous rule: `make test-fixtures`. If your verdict has no golden row, the fixture is missing.
