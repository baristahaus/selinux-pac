# When Policy Says No

> Every denial you read belongs to one of three families: a rule your module is missing, a rule your domain has been asked to carry, or a verdict the toolchain is refusing to write. Learning the family is what lets you act instead of guessing.

Every `audit.log` line is the answer to one tuple. But when you reach for a rule, the kernel is not the only thing that decides. Three separate things say *no* on different occasions: a `neverallow` in the base policy, a runtime gap in the module you wrote, and the gate this repository encodes as a verdict. Each carries a different shape of signal, and each demands a different answer.

## The three refusals

| Refusal | Who writes it | When it fires | What you do |
|---|---|---|---|
| **Compile-time `neverallow` or constraint** | the distribution or a base module | when your module tries to grant what the base policy forbids | fix the rule or widen the allow upstream |
| **Runtime denial for a missing rule** | the kernel | when `allow` is absent from your `.te` | write the rule, or label the object |
| **Deliberate gate** | the CI / the generator | when your `.te` or `.fc` triggers a house rule | accept the verdict and adjust |

A `neverallow` or a constraint sits on top of a base policy, typically in the base policy's
`policy/modules/system/` tree or a per-feature module such as `httpd.te` in the reference policy
sources. The language lets a policy author forbid a specific tuple across every module compiled
against that base: `neverallow myapp_t shadow_t:file { read open };`. A compile error from a
`neverallow` is loud — it stops `make`, and `checkmodule` refuses to continue. The error line
names the tuple that the base policy forbids.

A rule outside the module cannot grant what the base policy forbids. If you ship a module with `allow myapp_t shadow_t:file read;` and the targeted policy carries a `neverallow` covering that tuple, the compile will fail regardless of your intent. The module you wrote is a layer above the base; it is not a patch over the base.

The compile-time signal is therefore a *description* of a behaviour: the base policy declares this tuple forbidden. There is no transcript in this book for every `neverallow` — each distro carries its own set. The example above is illustrative, not a transcript of a live file. The behaviour is the same: the build refuses, and the tuple names the forbidden boundary.

## Runtime denials and the rules you must write

A runtime denial is the simplest. The kernel sees a tuple, finds no matching `allow`, and emits an AVC. The fix is to add the matching allow rule, or to introduce a new label on the object so the rule becomes irrelevant. This is the path covered in Chapters 4 through 9.

A missing rule is also the path the generator is designed to walk: `dev_generate_policy.sh` reads an AVC, runs `cli/deterministic_gen.py`, and returns one of `fc_fix`, `fc_drift`, `private_port`, `interface`, `direct`, or `boolean` as a verdict. Each verdict points at the smallest change that resolves the tuple.

## The gate the repository encodes

This book ships with a CI gate, `scripts/validate_forbidden_patterns.sh`, that refuses patterns the base policy does not carry. It is not a refpolicy `neverallow`; it is a house rule. It fires on `exit 1` when the `.te` contains one of these lines.

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

The same verdicts also live in `cli/policy_rules.py`. The generator carries `FORBIDDEN_TARGET_TYPES` — `shadow_t`, `unconfined_t`, `sysadm_t`, `security_t`, `selinux_config_t`, `passwd_file_t` — and `GENERIC_FILE_TYPES` — `var_t`, `var_lib_t`, `var_log_t`, `var_run_t`, `usr_t`, `etc_t`, `tmp_t`, `default_t`, `unlabeled_t`, `home_root_t`, `user_home_t`, `user_home_dir_t` — and `GENERIC_PORT_TYPES` — `unreserved_port_t`, `port_t`, `reserved_port_t`, `ephemeral_port_t`. Each list is a refusal: a tuple targeting any of these names is the default *forbidden*.

The generator records a `forbidden` verdict in `findings.json`, sets `generation_blocked: true` in that same file, and exits with code 1, printing the refusal:

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

The case meta confirms the exit:

```text
{
  "exit_code": 1
}
```

A rule targeting `shadow_t` is *forbidden*. The generator refuses to write it; the gate refuses to carry it. `shadow_t` is the label the base policy gives to the system authentication file; every allow rule against it widens the domain to the root account's home.

A rule targeting `var_t:file write` is refused on the same principle. `var_t` covers every file under `/var`. A `write` against `var_t` lets the domain edit any log, any spool, any state directory under `/var`. The gate names the dedicated application type as the replacement — `myapp_var_lib_t` for `/var/lib/myapp`, `myapp_log_t` for `/var/log/myapp`.

## `dontaudit` and `auditallow`

A denial covered by `dontaudit` looks identical to a denial from a missing rule — the process fails with `EPERM` and the log is blank. `dontaudit` does not allow anything: it suppresses the AVC record for that tuple, and nothing else. The kernel's decision is still *denied*; what disappears is the evidence. The base policy is full of them for exactly that reason — a browser probing for `~/.config`, a service checking a file it will never find — so that normal operation does not fill `audit.log` with failures nobody will act on.

Two commands manage the suppression. `semodule -DB` disables the entire `dontaudit` block on the host; `semodule -B` restores it. The canary role runs `-DB` at canary start so soak does not miss denials hidden by `dontaudit`; a failed canary and the rollback path both run `-B`. The host-wide change is documented in [302-PRODUCTION_READINESS.md](docs/admin/302-PRODUCTION_READINESS.md) §206 and [207-SELINUX_BEST_PRACTICES.md](docs/policy/207-SELINUX_BEST_PRACTICES.md) §134. Running `-DB` sends you after the same application bug you would have chased anyway, but shows the denials, and it is required before you conclude that a soak found zero denial.

`auditallow` is the mirror image, and it does not grant a tuple either: it makes an access that an `allow` rule already permits emit an AVC record. `dontaudit` hides a denial; `auditallow` exposes an allow. Neither changes the permission — each changes the *visibility* of the decision.

The common mistake is treating a `dontaudit` silence as a fix. The access was still refused, the service still failed (or swallowed the failure and retried), and the log said nothing. The silence is not a verdict — `semodule -DB` turns it back into evidence, and `auditallow` does the same for one tuple without touching the rest of the host.

`dontaudit` is not a fix for a denial; it is a suppression of the log. A tuple outside both `allow` and `dontaudit` fails and is recorded. A `dontaudit`-covered tuple fails silently, and from the log alone you cannot tell a service that works from a failure that is being hidden.

## Policy-level `permissive` versus host-level permissive

`permissive myapp_t;` is a declaration, not a rule with a scope of its own: it puts the whole **domain** on the permissive list, so every denial for `myapp_t` is recorded as `permissive=1` instead of being blocked. The kernel still evaluates the policy and still writes the AVC — what changes is the answer, not the visibility.

This repository carries that declaration as [`selinux/myapp_canary.te`](selinux/myapp_canary.te), a two-line overlay module whose only job is `permissive myapp_t;` (plus `myapp_backend_t` and `init_t`, for the systemd edge cases). The canary role installs it only when `semanage` is missing on the host; when `semanage` exists it uses `community.general.selinux_permissive` instead, which is the same declaration loaded by `semanage permissive -a myapp_t`. Enforce removes the flag either way — `semanage permissive -d {{ domain }}`, or `semodule -r` of the overlay.

The scope is identical in both forms — one domain, permissive — and that is the point: only the *delivery* differs. The overlay is a versioned artifact: it is reviewed in a PR, shipped in the RPM, and removed by the enforce role. `semanage permissive -a` is host-local state: it survives RPM changes, appears nowhere in the git history, and stays until somebody removes it. Chapter 2 covers the running-domain view; this chapter's only concern is that no permissive declaration — compiled or runtime — is a fix for a denial.

## Boolean-guarded rules and conditional policy

A boolean is a runtime decision: `setsebool -P myapp_allow_backend_connect on` flips a value that the policy already knows about, and the rule only enforces the tuple when the boolean is true. The syntax is a block, not a suffix on the rule:

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

A boolean belongs inside one of those blocks when the tuple is a behaviour the administrator wants to control at runtime — a flag that can flip, without recompiling the module. The administrator owns the decision. A rule that is conditional is a rule that is deferential; the admin can say yes or no without changing the binary.

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

`execmem` is the permission to map memory as both writable and executable. Every JVM runtime uses it — the garbage collector, the JIT, the dynamic code generators, the hot-patched bytecode paths. The JVM cannot function without writable+executable memory mappings.

The generator calls it a security decision because the rule lets a domain map code into memory it can also edit. W^X is broken when the mapping exists: memory the process writes, the process executes. A single `allow myapp_t self:process execmem;` lets a code path that escapes the confined domain execute with the authority of the domain.

The verdict is a *conversation*, not a rule. The generator refuses to write the rule unless you pass `--allow-needs-review`. The exit code 1 is the generator's signal: this is a security decision, and the operator has to opt in.

Every `needs_review` verdict covers the same kind of decision. The generator lists the tuples in `cli/policy_rules.py` — `execmem`, `execstack`, `execheap`, `setexec`, `setcurrent`, `dac_override`, `dac_read_search`, `sys_admin`, `sys_module`, `sys_ptrace`, `setuid`, `setgid`, `transition` against a foreign domain, `dyntransition` against a foreign domain. Each one weakens the domain in a different way. Each one is a conversation.

## What to do when the answer is no

Three alternatives when the tuple refuses. Each one points to a different chapter.

| Alternative | Change | Chapter |
|---|---|---|
| **Rename the path** | write state to `/run` or `/var/lib/myapp` with a dedicated type | [§9 File Contexts and the Label Lifecycle](../part2/09-file-contexts-and-the-label-lifecycle.md) |
| **Drop the port** | bind to an unreserved port, run as an unprivileged user, accept the risk | [§10 Ports, Booleans and Transitions](../part2/10-ports-booleans-and-transitions.md) |
| **Accept the denial** | design around the tuple; the app runs in permissive during soak | [§5 Modes and the Cost of Off](../part1/05-modes-and-the-cost-of-off.md) |

Rename the path. If the tuple is `allow myapp_t var_t:file write;` and the gate says *forbidden*, label `/var/lib/myapp` with `myapp_var_lib_t`. The rule becomes `allow myapp_t myapp_var_lib_t:file write;` — the gate is satisfied, the domain is narrowed, the baseline is preserved.

Drop the port. If the tuple is `allow myapp_t myapp_backend_port_t:tcp_socket name_connect;` and the generator says *private_port*, register the port at deploy with `semanage port` or the manifest's `selinux_ports`. The rule becomes `allow myapp_t myapp_backend_port_t:tcp_socket name_connect;` — the tuple now names the dedicated type, the host-wide change is the port, not the allow.

Accept the denial. If the tuple is `allow myapp_t self:process execmem;` and the generator says *needs_review*, keep the rule blank during canary. The domain runs in permissive during soak; the runtime decision is the operator's. When the decision is confirmed against the workload, opt in with `--allow-needs-review`.

Each alternative costs the same thing — the developer has to change the shape of the application or the shape of the domain. Each denial you cannot explain is a finding.

:::: why The repository's own verdict is the only thing stopping the bad rule from shipping
When the operator skips the PR body and runs `semodule -i` from `policy_out/`, the next stage is a denial response. The gate fires on each line in the table above; the fixture for `shadow_t` proves this exactly. A rule targeting `shadow_t` is *forbidden*. The generator refuses to write it; the gate refuses to carry it. `shadow_t` is the label the base policy gives to the system authentication file; every allow rule against it widens the domain to the root account's home.
::::
:::: warn Never widen policy to make a denial disappear
A denial you cannot explain is a finding, not an obstacle. If the log is blank and the service runs, either the tuple is covered by `dontaudit` or the domain is permissive — neither is the same as *allowed*. A rule that widens the domain to make a service survive a week is not a fix; it is a recording. Read the log before widening.
::::

::: try Run the forbidden-patterns script against a scratch copy

`scripts/validate_forbidden_patterns.sh` fires on each line in the table above. It needs the module's `.te` *and* `.fc` in the directory it is pointed at (`POLICY_MODULE` picks the name), and the tracked `selinux/myapp.te` passes it — the clean module is the control case. So copy both files, write the bad rules in by hand, and watch the gate refuse them:

```bash
# copy first — never edit the tracked files:
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
- Read the fixture directories under `docs/examples/fixtures/deterministic/` and recognise the `forbidden` and `needs_review` verdicts.
- Tell the difference between a `dontaudit` silence and a real allow.
- Pick the alternative: rename the path, drop the port, or accept the denial.

Each refusal carries a different kind of signal. The signal tells you what to do next.
