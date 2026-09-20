# When Policy Says No

> Every denial you read belongs to one of three families: a rule your module is missing, a rule your domain is asked to carry, or a verdict the toolchain refuses to write. Learning the family is what lets you act instead of guessing.

Every `audit.log` line is the answer to one tuple. But when you reach for a rule, the kernel is not the only thing that decides. Three separate things say *no* on different occasions: a `neverallow` in the base policy, a runtime gap in the module you wrote, and the gate this repository encodes as a verdict. Each carries a different shape of signal, and each demands a different answer.

## The three refusals

| Refusal | Who writes it | When it fires | What you do |
|---|---|---|---|
| **Compile-time `neverallow` or constraint** | the distribution or a base module | when your module tries to grant what the base policy forbids | fix the rule or widen the allow upstream |
| **Runtime denial for a missing rule** | the kernel | when `allow` is absent from your `.te` | write the rule, or label the object |
| **Deliberate gate** | the CI / the generator | when your `.te` or `.fc` triggers a house rule | accept the verdict and adjust |

A `neverallow` or a constraint sits on top of a base policy. It typically lives in the base
policy's `policy/modules/system/` tree, or in a per-feature module such as `httpd.te` in the
reference policy sources. The language lets a policy author forbid a specific tuple across every
module compiled against that base: `neverallow myapp_t shadow_t:file { read open };`. A
`neverallow` violation is loud, but it is not a `checkmodule` error. The assertion lives in the
base policy, and `checkmodule` compiles your module alone, with no base to check it against. The
failure comes when the whole policy is assembled. That is refpolicy's `make` over a full tree, or
the policy link that `semodule -i` performs. The error names the tuple the base forbids.

A rule outside the module cannot grant what the base policy forbids. Suppose you ship a module with `allow myapp_t shadow_t:file read;`. If the targeted policy carries a `neverallow` covering that tuple, the compile will fail regardless of your intent. The module you wrote is a layer above the base. It is not a patch over the base.

The compile-time signal is therefore a *description* of a behavior: the assembled policy declares this tuple forbidden. There is no transcript in this book for every `neverallow`. Each distro carries its own set. The example above is illustrative, not a transcript of a live file. The behavior is the same: the build refuses, and the tuple names the forbidden boundary.

## Runtime denials and the rules you must write

A runtime denial is the simplest. The kernel sees a tuple, finds no matching `allow`, and emits an AVC. The fix is to add the matching allow rule, or to introduce a new label on the object so the rule becomes irrelevant. This is the path covered in Chapters 4 through 9.

A missing rule is also the path the generator walks. `dev_generate_policy.sh` reads an AVC, runs `cli/deterministic_gen.py`, and returns one of `fc_fix`, `fc_drift`, `private_port`, `interface`, `direct`, or `boolean` as a verdict. Each verdict points at the smallest change that resolves the tuple.

## The gate the repository encodes

This book ships with a CI gate, `scripts/validate_forbidden_patterns.sh`, that refuses patterns the base policy does not carry. It is not a refpolicy `neverallow`. It is a house rule. It fires on `exit 1` when the `.te` contains one of these lines.

```text
Wildcard object type in allow rule
Wildcard object class in allow rule
Fully wildcard allow rule
Forbidden allow rule targeting self:* (over-broad)
Forbidden bin_t:file execute — label app binaries with dedicated exec types in .fc
Custom types declared inside require block
Forbidden allow rule targeting high-privilege type: shadow_t
Forbidden broad var_t:file write — use dedicated application types
Missing policy_module() declaration
Domain myapp_t not referenced in selinux/myapp.te
```

The same verdicts also live in `cli/policy_rules.py`. The generator carries three lists: `FORBIDDEN_TARGET_TYPES` (`shadow_t`, `unconfined_t`, `sysadm_t`, `security_t`, `selinux_config_t`, `passwd_file_t`), `GENERIC_FILE_TYPES` (`var_t`, `var_lib_t`, `var_log_t`, `var_run_t`, `usr_t`, `etc_t`, `tmp_t`, `default_t`, `unlabeled_t`, `home_root_t`, `user_home_t`, `user_home_dir_t`), and `GENERIC_PORT_TYPES` (`unreserved_port_t`, `port_t`, `reserved_port_t`, `ephemeral_port_t`). Only the first list is a refusal. A tuple targeting a `FORBIDDEN_TARGET_TYPES` name is `forbidden` and blocks generation. The other two lists route instead. A `GENERIC_FILE_TYPES` target becomes `fc_fix` or `fc_drift` when the path can carry a label of its own, and a plain `direct` allow when it cannot. A `GENERIC_PORT_TYPES` target becomes `private_port`, which moves the port onto the application's own type through the manifest.

The generator records a `forbidden` verdict in `findings.json`, sets `generation_blocked: true` in
that same file, and exits with code 1. It prints the refusal:

```text
REFUSED: Refusing to grant myapp_t access to shadow_t. Denied paths: n/a

Wrote policy_out/findings.json (generation_blocked=true)
```

The fixture for `shadow_t` proves this exactly.

```text
[
  {
    "verdict": "forbidden",
    "tgt": "shadow_t"
  }
]
```

The AVC that produced it:

```text
type=AVC msg=audit(1710000200.000:201): avc:  denied  { read open } for  pid=1234 comm="python3" name="shadow" dev="vda4" ino=1 scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=1
```

The case meta shows the exit:

```text
{
  "exit_code": 1
}
```

A rule targeting `shadow_t` is *forbidden*. The generator refuses to write it. The gate refuses to carry it. `shadow_t` is the label the base policy gives to the authentication database itself: `/etc/shadow`, `/etc/gshadow`. An allow rule against it reaches the password hashes.

A rule targeting `var_t:file write` is refused on the same principle. `var_t` covers every file under `/var`. A `write` against `var_t` lets the domain edit any log, any spool, any state directory under `/var`. The gate names the dedicated application type as the replacement: `myapp_var_lib_t` for `/var/lib/myapp`, `myapp_log_t` for `/var/log/myapp`.

## `dontaudit` and `auditallow`

A denial covered by `dontaudit` fails the same way as any other denial. The process gets `EPERM`.
But it leaves no trace: a denial from a missing rule is recorded in `audit.log`, and a denial
covered by `dontaudit` is not. `dontaudit` does not allow anything: it suppresses the AVC record
for that tuple, and nothing else. The kernel's decision is still *denied*. What disappears is the
evidence. The base policy is full of them for exactly that reason: a browser probing for
`~/.config`, or a service checking a file it will never find. That keeps normal operation from
filling `audit.log` with failures nobody will act on.

Two commands manage the suppression. `semodule -DB` disables the entire `dontaudit` block on the host. `semodule -B` restores it. The canary role runs `-DB` at canary start, so soak does not miss denials hidden by `dontaudit`. A failed canary and the rollback path both run `-B`. The host-wide change is documented in [302-PRODUCTION_READINESS.md](docs/admin/302-PRODUCTION_READINESS.md) §206 and [207-SELINUX_BEST_PRACTICES.md](docs/policy/207-SELINUX_BEST_PRACTICES.md) §134. Running `-DB` sends you after the same application bug you chase anyway, but it shows the denials. Before you conclude that a soak found zero denial, run it.

`auditallow` is the mirror image, and it does not grant a tuple either. It makes an access that an
`allow` rule already permits emit an AVC record. `dontaudit` hides a denial. `auditallow` exposes
an allow. Neither changes the permission. Each changes the *visibility* of the decision.

The common mistake is treating a `dontaudit` silence as a fix. The access was still refused, the service still failed (or swallowed the failure and retried), and the log said nothing. The silence is not a verdict. `semodule -DB` turns it back into evidence, and `auditallow` does the same for one tuple without touching the rest of the host.

`dontaudit` is not a fix for a denial. It is a suppression of the log. A tuple outside both `allow` and `dontaudit` fails and is recorded. A `dontaudit`-covered tuple fails silently. From the log alone you cannot tell a service that works from a hidden failure.

## Policy-level `permissive` versus host-level permissive

`permissive myapp_t;` is a declaration, not a rule with a scope of its own. It puts the whole
domain on the permissive list. So the kernel records every denial for `myapp_t` as `permissive=1`
and does not block the access. The kernel still evaluates the policy and still writes the AVC.
What changes is the answer, not the visibility.

This repository carries that declaration as [`selinux/myapp_canary.te`](selinux/myapp_canary.te). That is a small overlay module: one `policy_module` line, a `require` block, and three `permissive` declarations. Its job is the flag on `myapp_t` and on `myapp_backend_t` and `init_t` for the systemd edge cases. The canary role installs it only when `semanage` is missing on the host. When `semanage` exists, the role uses `community.general.selinux_permissive` instead. That is the same declaration loaded by `semanage permissive -a myapp_t`. Enforce removes the flag either way: `semanage permissive -d {{ domain }}`, or `semodule -r` of the overlay.

Both forms have the same scope: one domain, permissive. Only the *delivery* differs, and that is
the point. The overlay is a versioned artifact. A PR reviews it, the RPM ships it, and the enforce
role removes it. `semanage permissive -a` is host-local state: it survives RPM changes, appears
nowhere in the git history, and stays until somebody removes it. Chapter 2 covers the
running-domain view. This chapter's only concern is that no permissive declaration, compiled or
runtime, is a fix for a denial.

## Boolean-guarded rules and conditional policy

A boolean is a runtime decision. `setsebool -P myapp_allow_backend_connect on` flips a value that
the policy already knows about. The rule only enforces the tuple when the boolean is true. The
syntax is a block, not a suffix on the rule:

```text
tunable_policy(`myapp_allow_backend_connect',`
    allow myapp_t myapp_backend_port_t:tcp_socket name_connect;
')
```

or, in the upstream `if` form that `tunable_policy` expands to:

```text
if (myapp_allow_backend_connect) {
    allow myapp_t myapp_backend_port_t:tcp_socket name_connect;
}
```

A boolean belongs inside one of those blocks when the tuple is a behavior the administrator wants
to control at runtime. That is a flag that can flip without recompiling the module. In a refpolicy
module the boolean is declared before it is used (`gen_tunable(myapp_allow_backend_connect, false)`),
and `tunable_policy` gates the rule against it. The `if` form above is the same rule after m4
expansion. The administrator owns the decision. A conditional rule is a deferential rule. The admin
can say yes or no without changing the binary.

[§10 Ports, Booleans and Transitions](../part2/10-ports-booleans-and-transitions.md) covers the full decision surface for booleans and transitions.

## `needs_review`: execmem

A `forbidden` verdict is a hard no. A `needs_review` verdict is a soft no. The rule is legitimate but the domain weakens. The generator records the tuple in `findings.json` and `pr_summary.md`, writes `needs_review` as the verdict, and leaves the `.te` blank unless the author passes `--allow-needs-review`.

```text
{
  "exit_code": 1,
  "stderr_substrings": [
    "needs_review",
    "execmem",
    "--allow-needs-review"
  ]
}
```

The fixture that triggers this verdict:

```text
type=AVC msg=audit(1710000300.000:301): avc:  denied  { execmem } for  pid=1234 comm="java" scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:system_r:myapp_t:s0 tclass=process permissive=1
```

```text
[
  {
    "verdict": "needs_review",
    "tgt": "myapp_t",
    "next_action": "review_then_opt_in"
  }
]
```

`execmem` is the permission to map memory as both writable and executable. Every JVM runtime uses it: the garbage collector, the JIT, the dynamic code generators, the hot-patched bytecode paths. The JVM cannot function without writable+executable memory mappings.

The generator calls it a security decision because the rule lets a domain map code into memory it can also edit. W^X is broken when the mapping exists: memory the process writes, the process executes. A single `allow myapp_t self:process execmem;` lets a code path that escapes the confined domain execute with the authority of the domain.

The verdict is a *conversation*, not a rule. The generator refuses to write the rule unless you pass `--allow-needs-review`. The exit code 1 is the generator's signal: this is a security decision, and the operator has to opt in.

Every `needs_review` verdict covers the same kind of decision. The generator lists the tuples in `cli/policy_rules.py`: `execmem`, `execstack`, `execheap`, `setexec`, `setcurrent`, `dac_override`, `dac_read_search`, `sys_admin`, `sys_module`, `sys_ptrace`, `setuid`, `setgid`, `transition` against a foreign domain, `dyntransition` against a foreign domain. Each one weakens the domain in a different way. Each one is a conversation.

## What to do when the answer is no

Three alternatives when the tuple refuses. Each one points to a different chapter.

| Alternative | Change | Chapter |
|---|---|---|
| **Rename the path** | write state to `/run` or `/var/lib/myapp` with a dedicated type | [§9 File Contexts and the Label Lifecycle](../part2/09-file-contexts-and-the-label-lifecycle.md) |
| **Drop the port** | bind to an unreserved port, run as an unprivileged user, accept the risk | [§10 Ports, Booleans and Transitions](../part2/10-ports-booleans-and-transitions.md) |
| **Accept the denial** | design around the tuple. The app runs in permissive during soak | [§5 Modes and the Cost of Off](../part1/05-modes-and-the-cost-of-off.md) |

Rename the path. If the tuple is `allow myapp_t var_t:file write;` and the gate says *forbidden*, label `/var/lib/myapp` with `myapp_var_lib_t`. The rule becomes `allow myapp_t myapp_var_lib_t:file write;`. The gate is satisfied, the domain is narrowed, and the baseline is preserved.

Drop the port. If the tuple is `allow myapp_t myapp_backend_port_t:tcp_socket name_connect;` and the generator says *private_port*, register the port at deploy with `semanage port` or the manifest's `selinux_ports`. The rule becomes `allow myapp_t myapp_backend_port_t:tcp_socket name_connect;`. The tuple now names the dedicated type, and the host-wide change is the port, not the allow.

Accept the denial. If the tuple is `allow myapp_t self:process execmem;` and the generator says *needs_review*, keep the rule blank during canary. The domain runs in permissive during soak. The runtime decision is the operator's. When you check the decision against the workload, opt in with `--allow-needs-review`.

Each alternative costs the same thing: the developer has to change the shape of the application or the shape of the domain. Each denial you cannot explain is a finding.

:::: why The repository's own verdict is the only thing stopping the bad rule from shipping
When the operator skips the PR body and runs `semodule -i` from `policy_out/`, the next stage is a denial response. The gate fires on each line in the table above. The fixture for `shadow_t` proves this exactly. A rule targeting `shadow_t` is *forbidden*. The generator refuses to write it. The gate refuses to carry it. `shadow_t` is the label the base policy gives to the authentication database itself: `/etc/shadow`, `/etc/gshadow`. An allow rule against it reaches the password hashes.
::::
:::: warn Never widen policy to make a denial disappear
A denial you cannot explain is a finding, not an obstacle. If the log is blank and the service runs, either the tuple is covered by `dontaudit` or the domain is permissive. Neither is the same as *allowed*. A rule that widens the domain to make a service survive a week is not a fix. It is a recording. Read the log before you widen the policy.
::::

::: try Run the forbidden-patterns script against a scratch copy

`scripts/validate_forbidden_patterns.sh` fires on each line in the table above. It needs the
module's `.te` *and* `.fc` in the directory it is pointed at. `POLICY_MODULE` picks the name. The
tracked `selinux/myapp.te` passes it. The clean module is the control case. So copy both files,
write the bad rules in by hand, and watch the gate refuse them:

```bash
# copy first — never edit the tracked files:
$ mkdir -p /tmp/myapp-check
$ cp selinux/myapp.te selinux/myapp.fc /tmp/myapp-check/
$ cd /tmp/myapp-check

# the clean copy passes:
$ bash /path/to/repo/scripts/validate_forbidden_patterns.sh /tmp/myapp-check
[INFO] Forbidden-pattern checks passed for myapp

# now write the rules from the table above and run it again:
$ cat >> myapp.te <<'EOF'
allow myapp_t var_t:file { write };
allow myapp_t self:* { transition };
allow myapp_t shadow_t:file read;
EOF
$ bash /path/to/repo/scripts/validate_forbidden_patterns.sh /tmp/myapp-check
[ERROR] Wildcard object class in allow rule
[ERROR] Forbidden allow rule targeting self:* (over-broad)
[ERROR] Forbidden allow rule targeting high-privilege type: shadow_t
[ERROR] Forbidden broad var_t:file write — use dedicated application types
```

Each error the script prints names a house rule. Each house rule is the only thing stopping the bad rule from shipping.

:::
## What you can do now

- Read a denied tuple and identify which of the three families it belongs to.
- Run `scripts/validate_forbidden_patterns.sh` and read each failure message as a house rule.
- Read the fixture directories under `docs/examples/fixtures/deterministic/` and recognize the `forbidden` and `needs_review` verdicts.
- Tell the difference between a `dontaudit` silence and a real allow.
- Pick the alternative: rename the path, drop the port, or accept the denial.

Each refusal carries a different kind of signal. The signal tells you what to do next.
