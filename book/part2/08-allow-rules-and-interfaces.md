# Allow Rules and Interfaces

> A rule is a tuple, and a module is a library: you write rules for what your module needs, you
> publish interfaces so other modules can reach yours without learning its type names. The
> decision is always `allow source target:class { perms };` — the only syntax the kernel reads.

## The rule, in full

Every allow rule is the same four-slot tuple written in refpolicy syntax:

```text
allow source target:class { perms };
```

Read it as: *processes labeled `source` may perform each `perm` listed against `class` on
objects labeled `target`.* A single rule can list any number of permissions inside the braces,
and each permission is the unit of access — `write` does not imply `create`, `open` does not
imply `getattr`, and a rule listing `read open getattr` on a `dir` is read-only traversal, not
mutation.

There are two rule shapes you will meet.

| | Syntax | Scope |
|---|---|---|
| One permission | `allow src tgt:class perm;` | same tuple; only one slot |
| Many permissions | `allow src tgt:class { p1 p2 p3 };` | same tuple; grouped for review |

Both describe the same decision. The only difference is ergonomics for the reviewer. A
multi-permission rule is the default for net-new access, because it lets you read the rule as a
single audit unit instead of a chain of smaller grants that each widen the domain by one.

## Default deny, stated once

Absence of a matching allow rule is a denial. That is the single rule of refpolicy, repeated in
every module, enforced by the kernel, and recorded in `audit.log` when the mode is enforcing.
Chapter 2 restates it as part of the decision tuple; the rest of this chapter assumes the
tuple is already the model you use for every denial you read.

## Direct allows versus interfaces

A **direct allow** names the types that appear in the AVC: it writes `allow shopapi_t
shopapi_var_lib_t:dir { search add_name write };` and is correct when every type involved is
owned by the module that writes it. It is what every module writes about itself.

An **interface** is a refpolicy macro that a module publishes — `list_dirs_pattern`,
`manage_files_pattern`, `payments_read_public_state` — so that other modules can request access
to the same object without learning the module's type names. The interface names *intent*; the
consumer supplies the domain and receives the allow, written in a form the reader can audit as a
pattern rather than a per-type grant.

The distinction matters at review time. A direct allow on a type the writer owns is legible: it
names the type, the class, and the exact permission set. An interface call is also legible, but
legibility lives in the macro definition — the caller does not read the macro body, and the
body is what a reviewer should open for audit.

A real interface call and its expansion, from the `payments` module shipped with this book:

```text
## Inside selinux/payments/payments.if
interface(`payments_read_public_state',`
    gen_require(`
        type payments_var_lib_t;
        class dir  { getattr open read search list };
        class file { getattr open read ioctl lock map };
    ')
    list_dirs_pattern($1, payments_var_lib_t)
    read_files_pattern($1, payments_var_lib_t, payments_var_lib_t)
')

## Inside selinux/payments/payments.te — consumer uses it
# (another module would call this after gen_require)
```

A caller writes `payments_read_public_state(myapp_t)` and receives, after the macro expands, the
allow rules that `myapp_t` needs to read directories and files in
`payments_var_lib_t` — `list_dirs_pattern` for the directory permissions, `read_files_pattern` for
the read side. The caller never sees those type names. The publisher does: the `gen_require`
block inside the `.if` declares them for any module that pulls the interface.

Every published interface carries the same contract as the types it names. The publisher is
vouching that `payments_var_lib_t` is the right object for the access the consumer asked for.
That is what `gen_require` makes visible to the module author who has to add it: the types the
interface reaches into, the classes, the permissions. Treat every published interface as a
review boundary — read the `gen_require` block and the pattern macros it expands, not just the
one line that calls it.

## How to find the right interface

The refpolicy ships with hundreds of pattern macros. Most of them have `*_pattern` in the name
because they name a bounded set of permissions against a generic type, and they are what you
should reach for before writing a raw allow. The refpolicy tooling that finds the macro for a
given AVC is `sepolgen-ifgen`, shipped with `policycoreutils-devel` — it indexes the interface
set into `/var/lib/sepolgen/interface_info` and the Python bindings the generator consumes query
it. Without it, the generator cannot run interface matching.

The workflow is:

| Step | Command | What it produces |
|---|---|---|
| Install toolchain | `sudo dnf install -y policycoreutils-devel setools-console` | `sepolgen-ifgen`, `sesearch` |
| Index the interfaces | `sudo sepolgen-ifgen` | `/var/lib/sepolgen/interface_info` |
| Ask for an allow | `sesearch --allow --source myapp_t --target var_log_t --class dir --perm search` | the exact allow rule refpolicy ships for that tuple |
| Ask for a boolean | `sesearch --allow --bool …` | booleans that cover the same tuple |

`sesearch` is the most useful of these for review, because it lets you ask *what the vendor policy
already does* for a given access, instead of guessing whether a new allow is the right fix. Run
it when the module under review is a dependency of the OS — `httpd_t`, `sshd_t`,
`postgresql_t` — and the answer tells you which pattern macros the distribution already reached
for, and which ones you still need to add.

`seinfo -c` is the structural cousin: it lists every class and its permissions without reading a
policy binary, useful when you want the class namespace rather than a specific allow. The
`sepolicy generate` utility is scaffolding, not audit: it writes starter `.te` and `.if` files
but never commits them — the reviewed `.if` you publish is authored by hand.

When `sepolgen-ifgen` is missing — laptop, CI, air-gapped build — the generator prints a banner
to stderr and still emits verdicts for everything but base-type allow rules:

```text
SEPOLGEN INTERFACE MATCHING IS NOT AVAILABLE
```

Base-type denies (`var_log_t`, `usr_t`, `etc_t`, any of the generic port types) refuse to
generate a raw allow against them. That is `VERDICT_TOOLCHAIN`. To force generation in that
state, the operator passes `--allow-degraded`:

```bash
python3 cli/deterministic_gen.py --explain \
  --avc-log docs/examples/fixtures/deterministic/09-direct-no-interface/avc.log \
  --manifest config/myapp.manifest.yml \
  --allow-degraded
```

`--allow-degraded` tells the generator to emit raw allows on base types anyway, and records
`engine=degraded` in `findings.json` for reviewers who want a higher-scrutiny banner on those
allow rules. It is not the default; it is the escape hatch for offline runs.

## House rules

Each rule — which targets are acceptable, which are forbidden, which permission sets collapse
into pattern macros — is written in `cli/policy_rules.py` and enforced before interface matching.

### Targets that are refused

| Verdict | Target | Why |
|---|---|---|
| `forbidden` | `shadow_t`, `passwd_file_t` | password file store |
| `forbidden` | `unconfined_t`, `sysadm_t` | unconfined / sysadm |
| `forbidden` | `security_t` | security subsystem |
| `forbidden` | `selinux_config_t` | SELinux own state |

Each of these four types is legible as dangerous by itself.

### Targets that are generic and should be relabeled

| Verdict | Target | Why |
|---|---|---|
| `fc_fix` / `fc_drift` | `var_t`, `var_lib_t`, `var_log_t`, `var_run_t` | app-own directory, relabel first |
| `fc_fix` / `fc_drift` | `usr_t`, `etc_t`, `tmp_t`, `default_t` | same |
| `fc_fix` / `fc_drift` | `unlabeled_t`, `home_root_t`, `user_home_t`, `user_home_dir_t` | same |
| `private_port` | `unreserved_port_t`, `port_t`, `reserved_port_t`, `ephemeral_port_t` | app owns a private port type |

The house rule prefers a relabel over a raw allow against these types.

### Pattern macros that consume permission sets

| Pattern macro | Permissions it absorbs |
|---|---|
| `manage_files_pattern` | `create write unlink rename setattr append read open getattr` |
| `manage_dirs_pattern` | `create write add_name remove_name rmdir search read open getattr` |
| `read_files_pattern` | `read open getattr lock ioctl` |
| `list_dirs_pattern` | `search read open getattr` |

When a denial carries exactly the permission set a pattern macro consumes, the generator prefers
the macro call over a raw allow — not as an abstraction, but as review. A reviewer reads
`manage_files_pattern(myapp_t, myapp_var_lib_t, myapp_var_lib_t)` and sees the same four lines
the macro expands into, without opening the `.if` first.

### Permissions that weaken the domain

| Verdict | (tclass, perm, scope) | Why it weakens |
|---|---|---|
| `needs_review` | `process`, `execmem`, `any` | W^X is broken |
| `needs_review` | `process`, `execstack`, `any` | executable stack |
| `needs_review` | `process`, `execheap`, `any` | executable heap |
| `needs_review` | `process`, `setexec`, `any` | child domain choice |
| `needs_review` | `process`, `setcurrent`, `any` | domain exit |
| `needs_review` | `capability`, `dac_override`, `any` | Unix ownership irrelevant |
| `needs_review` | `capability`, `dac_read_search`, `any` | Unix read irrelevant |
| `needs_review` | `capability`, `sys_admin`, `any` | near-root |
| `needs_review` | `capability`, `sys_module`, `any` | kernel load/unload |
| `needs_review` | `capability`, `sys_ptrace`, `any` | process memory read |
| `needs_review` | `capability`, `setuid`, `any` | identity swap |
| `needs_review` | `capability`, `setgid`, `any` | identity swap |
| `needs_review` | `process`, `transition`, `foreign_domain` | outside this module's code |
| `needs_review` | `process`, `dyntransition`, `foreign_domain` | outside this module's code |

Each of these is legitimate — a JVM really does need `execmem` for the bytecode loader, a debug
tool really does need `sys_ptrace`. But each of them weakens the domain in a way that is not
covered by any single denial: a single denial is the proof that you need the permission.
`--allow-needs-review` is the flag that lets the generator write one of these into the `.te`;
the reviewer reads the proof before signing off.

## Worked examples

The two fixtures that demonstrate how the generator reaches for each verdict are under
`docs/examples/fixtures/deterministic/`. Each fixture supplies an AVC line, a mock of `sepolgen`
that records whether the engine matched an interface or failed, and an `expected.json` that pins
the verdict. Running the generator against them is what the golden test asserts — *the tool
produces these verdicts for these inputs, and only these*.

### `08-interface-match` — an interface matched

The AVC names `myapp_t` searching `var_log_t` on a `dir`, `permissive=1`:

```text
avc: denied { search } for pid=1234 comm="python3" name="log" path="/var/log"
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:var_log_t:s0
  tclass=dir permissive=1
```

`var_log_t` is not module-private, but it is a generic file type the generator already knows how
to reach for. The mock sepolgen reports `behavior: "match"`, and the generator emits
`list_dirs_pattern(myapp_t)` — the `list_dirs_pattern` macro, which consumes exactly the
permissions observed in the AVC (`search read open getattr`) against the target. The expected
verdict is `interface` with target `var_log_t`:

```json
[
  {
    "verdict": "interface",
    "tgt": "var_log_t"
  }
]
```

The rule the generator emits does not name `var_log_t` directly — it names the macro, and the
macro names `var_log_t`. That is the contract of an interface: the caller names intent, the
macro names types. The reviewer's job is to read the macro body, confirm that `var_log_t` is the
right object for log access in refpolicy, and accept the allow.

### `09-direct-no-interface` — no macro matched, a direct allow is correct

The AVC names `myapp_t` reading files under `/usr/share/myapp/notes.txt` on `usr_t`:

```text
avc: denied { read open getattr } for pid=1234 comm="python3" name="notes.txt"
  path="/usr/share/myapp/notes.txt"
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:usr_t:s0
  tclass=file permissive=1
```

`usr_t` is generic — the house rule would prefer an `fc_fix` or `fc_drift` and a relabel. But
the manifest names `/usr/share/myapp` as an owned path, and the `.fc` already matches. The
sepolgen mock reports `behavior: "no_match"` — no refpolicy macro reaches for `usr_t` against
`file` with the observed permission set. With no interface match, no base-type deny blocks the
generation (the operator would pass `--allow-degraded`), and the generator classifies the verdict
as `direct`. The expected verdict is `direct` with target `usr_t`:

```json
[
  {
    "verdict": "direct",
    "tgt": "usr_t"
  }
]
```

The generated allow reads `allow myapp_t usr_t:file { read open getattr };`. It names the types
the AVC observed, and the type `usr_t` is generic — that is why `--allow-degraded` is required
in this fixture at all. The fixture demonstrates the contract that when no macro matched, a
module can reach for its own private types, or a base-type direct allow with the operator's
explicit consent.

:::: why a named interface is the line between reviewable and opaque

An interface names intent. The call site reads `list_dirs_pattern(myapp_t, var_log_t)` and
understands what the process will do — list, search, read, open, getattrs — without reading the
macro body. The caller owns no types; the publisher owns them, and the publisher's `gen_require`
block is what the reviewer reads to confirm the call. A direct allow inside your module names
types — your own types — and the rule is legible as written.

::::

:::: try a live query on your own lab

Two commands, zero state change:

```bash
# (rhel-qa or any host with policycoreutils-devel installed)
sudo sepolgen-ifgen

+# then, on the same host, query refpolicy for an allow
sesearch --allow --source payments_t --target payments_var_lib_t --class dir --perm search
```

Offline laptop: skip the live sepolgen, run the generator against the two fixtures with
`--allow-degraded` and `--explain`:

```bash
python3 cli/deterministic_gen.py --explain \
 --allow-degraded

python3 cli/deterministic_gen.py --explain \
 --allow-degraded
```

Both runs print each finding's verdict, each `expected.json` row, and each degraded banner; the
exit codes (1 when blockers remain, 0 otherwise) are the same guarantees the CI uses.

::::

## What you can do now

You can read an allow rule as a tuple, tell the difference between an interface call and a direct
allow, and reach for `sesearch` when a reviewer asks what refpolicy already does for that access.
The next chapter — file contexts and the label lifecycle — is where each allow rule becomes
reachable on disk: a rule names `shopapi_var_lib_t`, the `.fc` names `/var/lib/shopapi`,
`restorecon` writes the label, and the AVC disappears.
