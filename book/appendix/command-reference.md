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
"what would we be on reboot". They never disagree with each other; they each answer a
different slice of the same truth.
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
| `matchpathcon -p <kind> <path>` | "What label **should** this path have", per /etc/selinux/<type>/contexts/files/ — the answer you compare to what is on the box | `rhel host` |

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
| `fixfiles relabel` | Full-file-system relabel; triggers a reboot if SELinux runs on the root filesystem | `rhel host`, `root` — **warning: reboot or live FS check** |

::: warn `fixfiles relabel` is the nuclear option
The command re-labels *every* file on the box. When SELinux runs on `/`, the filesystem must
boot into a special state for the relabel to complete — meaning a maintenance window is
required. Use it only when the file context set itself has drifted at scale, not for a single
path.
:::

## Ports

SELinux labels TCP/UDP ports by category: each process that `bind()`s on a port asks for
the `name_bind` allow, and the port's type tells the answer.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `semanage port -a/-m/-d/-l` | Add, modify, delete, or list port type definitions; every port in this repository is managed this way | `rhel host`, `root` |

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
| `checkmodule` | Syntax-checks a `.te`/`.fc` pair; used by the build pipeline but rarely called directly | `build host` |
| `semodule_package` | Builds a `.pp` from `.te`/`.fc`/`.if`/`policy_version.txt`; the thin wrapper around the build | `build host` |
| `make -C <work_dir> -f /usr/share/selinux/devel/Makefile <name>.pp` | The canonical refpolicy build invocation: copies `.te`/`.fc`/`.if` into a work directory, runs `make` there, and emits `<name>.pp` | `build host` |

::: why the Makefile is the only build line
The repository's `scripts/compile_and_validate.sh` calls the `make -f /usr/share/selinux/devel/Makefile`
line for every module: the single invocation this book relies on, no shims, no custom wrapper.
Each module named in the build gets its own invocation (see the Makefile: `compile_and_validate.sh`
is re-run for `payments` and `shopapi` as well as `myapp`).
:::

## Query the installed policy

These commands each let you ask the loaded policy what it allows. The questions you ask
each one are different — `sesearch` is a rule lookup, `seinfo` is an attribute lookup,
`sepolicy generate` is a suggestion, and `sepolgen-ifgen` is a generator for the generator.

| Command | What it tells you or changes | Needs |
|---|---|---|
| `sesearch -A -s <src_t> -t <tgt_t> -c <class> -p <perm>` | Searches the running policy for matching `allow` rules; returns each rule verbatim | `rhel host`, `root` |
| `seinfo -a <attribute> -x` | Lists every type that carries `<attribute>`; requires policy XML (from `policycoreutils-devel`) | `rhel host`, `root` |
| `sepolicy generate -t <src> -c <class> -p <perm>` | Suggests an `allow` rule from the running policy (approximation: the kernel class/perms are a fixed subset, not the full refpolicy grammar) | `rhel host`, `root` |
| `sepolgen-ifgen` | Generates `.if` files for each policy XML entry so `sepolicy generate` can match refpolicy interfaces; requires `policycoreutils-devel` | `rhel host`, `root` |

::: note `sepolicy generate` is a hint, not a command
`sepolicy generate` reads the running policy and suggests what the tuple would look like —
but it does not know about refpolicy interfaces, macros, or the custom types this book adds.
Every suggestion is a candidate for review, never a copy-paste.
:::

## Audit

These commands each look at a different slice of `audit.log`:

| Command | What it tells you or changes | Needs |
|---|---|---|
| `ausearch -m avc -ts <time>` | Filters `audit.log` for AVC events around `<time>`; supports `recent`, `-i`, or epoch | `rhel host`, `root` |
| `aureport -au -i` | Produces an audit summary report — summarised access events across all subjects | `rhel host`, `root` |
| `audit2why` | Converts each AVC into the allow rule that would have made it pass; returns a reviewable sentence for each denial | `rhel host`, `root` |
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
| `ansible-playbook` (canary) / `ansible-playbook` (soak) | Deploys the canary module (`part4/19-canary-soak-enforce.md`) or runs the soak gate (`scripts/check_soak_ready.sh`); requires the Ansible controller and `ansible/roles/selinux_pac/` | `controller`, `rhel host` |

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
