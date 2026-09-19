# The Verdict Table

> The generator does not write policy blindly. It reads each denial, classifies the access need into exactly one family of response, and emits one correct answer per family. This chapter records that classification — each verdict name, each fixture it exercises, each line the generator writes, each command the operator must run — so your team can read findings without rerunning the tool.

## How the classification works

`cli/deterministic_gen.py` runs one pipeline per AVC line: it parses the audit log, merges the per-permission entries, subtracts anything already covered by the existing `.te`, and then runs `classify()` on each uncovered `AccessNeed`. The `classify` function walks the same decision ladder for every denial, in this order:

1. Does an existing baseline macro cover it? → `baseline`.
2. Is the target a forbidden type (`shadow_t`, `unconfined_t`, `sysadm_t`, `security_t`, `passwd_file_t`)? → `forbidden`.
3. Is the target a generic file type on a path the module owns? → `fc_drift` when the `.fc` already covers the path, `fc_fix` when it does not.
4. Is the target a generic port type bound with `name_bind`? → `private_port`.
5. Is it a `node_bind` on `node_t`? → `interface` (`corenet_*_bind_generic_node`).
6. Is the need already allowed by the committed `.te`? → `baseline`.
7. Is the permission on the `NEEDS_REVIEW_RULES` list (`execmem`, `dac_override`, a foreign `process` transition)? → `needs_review`. **This is checked before the module-private type branch**, by design — the security decision outranks the convenient answer.
8. Does the target exist inside the module (a private type)? → `direct` — a refpolicy macro, or the explicit allow.
9. Does `sesearch`/boolean triage surface an applicable `setsebool`? → `boolean`.
10. Does sepolgen match a refpolicy interface? → `interface` with the macro. No match at all → `direct` with a raw allow and `engine=house_rules`.
11. Is sepolgen missing? → `toolchain_required` — unless `--allow-degraded` was passed, which turns the row into `direct` with `engine=degraded`.

The output is one `Finding` dataclass with fields `verdict`, `rendered`, `note`, `engine`, `paths`, and `next_action`. The `NEXT_ACTION` map (in `policy_rules.py`) is the only place each verdict's operator action comes from — every verdict has a prescribed response, and several verdicts deliberately share one: `fc_fix` and `fc_drift` both map to `update_fc_and_restorecon`, `direct` and `interface` both map to `update_te_allow`, and `baseline` maps to the empty string (nothing to do — the need is already covered). The **verdict name**, not the action, is what distinguishes those pairs.

## The baseline verdict

The generator emits `baseline` when the denial is already covered by a reviewed macro in the existing `.te`. No allow line is written.

**The AVC from `docs/examples/fixtures/deterministic/05-baseline-covered/avc.log`:**

```text
type=AVC msg=audit(1710000180.000:213): avc:  denied  { read open getattr }
for  pid=1234 comm="python3" name="urandom" dev="vda4" ino=1
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:random_device_t:s0
tclass=chr_file permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "baseline",
    "tgt": "random_device_t"
  }
]
```

The generator recognises the `read open getattr` set on `random_device_t` as covered by `dev_read_urand(myapp_t)` in the reviewed baseline block. `baseline` means: *nothing changed*. `cli/deterministic_gen.py` does not append any lines to the `.te`; `case.meta.json` reports `exit_code: 0`.

A second baseline case (fixture 13 — `cgroup_t` getattr) is treated identically: the type is often undeclared, the access is JVM cgroupfs telemetry, and the generator omits rather than requires an allow.

## fc_drift and fc_fix

Both verdicts address a mislabeled file. The distinction is structural:

- **`fc_fix`** means the `.fc` is *missing* a line for this path; the generator writes a `gen_context` line into the `.fc`.
- **`fc_drift`** means the `.fc` *already* covers the path with a different regex; the file on disk has drifted away from the regex, and no `.te` or `.fc` change is needed — only `restorecon`.

**`fc_fix`:** from `docs/examples/fixtures/deterministic/06-fc-missing-line/avc.log`:

```text
type=AVC msg=audit(1710000160.000:211): avc:  denied  { write } for
pid=1234 comm="python3" name="data" path="/opt/myapp/cache/data" dev="vda4" ino=99
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_lib_t:s0
tclass=file permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "fc_fix",
    "tgt": "var_lib_t"
  }
]
```

`suggest_fc_type` walks the manifest's `paths` hints in order — `log_dir` → `{app}_log_t`, `var_dir` → `{app}_var_lib_t`, `runtime_dir` → `{app}_var_run_t`, `install_root` → `{app}_exec_t` — then falls back to `extra_fc_roots` for `{app}_var_lib_t`. `/opt/myapp/cache/data` sits under `install_root`, so the generator writes `gen_context(system_u:object_r:myapp_exec_t,s0)` into the `.fc` for that path. The operator then runs `restorecon -Rv /opt/myapp/cache/data` on the host. (The artifact is in `docs/examples/fixtures/deterministic/06-fc-missing-line/_out/` — `findings.json` and the generated `myapp.fc`.)

**`fc_drift`:** from `docs/examples/fixtures/deterministic/01-mislabeled-var-lib/avc.log`:

```text
type=AVC msg=audit(1710000100.000:200): avc:  denied  { write } for
pid=1234 comm="python3" name="data.log" path="/var/lib/myapp/data.log" dev="vda4" ino=12345
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_lib_t:s0
tclass=file permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "fc_drift",
    "tgt": "var_lib_t"
  }
]
```

The `.fc` already has a `gen_context` line covering `/var/lib/myapp(/.*)?`. The generator's `existing_fc_covers` check succeeds, so the verdict is `fc_drift`: *the file on disk has drifted, restore it, do not grant access to var_lib_t*. No `.fc` line is written.

## private_port

A generic port (`unreserved_port_t`, `reserved_port_t`, `ephemeral_port_t`, `port_t`) bound with `name_bind`. A `node_bind` denial is a different verdict: it matches on `node_t` and comes back as `interface` (`corenet_tcp_bind_generic_node` / `corenet_udp_bind_generic_node`), because the fix is a refpolicy interface rather than a private port.

**From `docs/examples/fixtures/deterministic/02-port-bind/avc.log`:**

```text
type=AVC msg=audit(1710000150.000:210): avc:  denied  { name_bind } for
pid=1234 comm="python3" src=8888
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0
tclass=tcp_socket permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "private_port",
    "tgt": "unreserved_port_t",
    "next_action": "add_manifest_port",
    "port": 8888
  }
]
```

The generator writes `allow myapp_t myapp_port_t:tcp_socket name_bind;` into the `.te` and instructs the operator to add `port: 8888 / tcp / myapp_port_t` to `selinux_ports` in `config/myapp.manifest.yml`. The manifest's `selinux_ports` list drives the `seport` canary that registers the port with semanage. No `semanage port -a` on production.

## boolean

A `setsebool` decision that is *not* shipped in the policy module package. The generator checks `boolean_hints.yml` (curated overrides, consulted before the live query) and, when the curated list does not answer it, falls back to a `sesearch` query against `policy.kern` — `cli/boolean_hints.py` is the module that runs it and parses the result.

**From `docs/examples/fixtures/deterministic/04-boolean-network-connect/avc.log`:**

```text
type=AVC msg=audit(1710000200.000:217): avc:  denied  { name_connect } for
pid=1234 comm="python3"
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:http_port_t:s0
tclass=tcp_socket permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "boolean",
    "tgt": "http_port_t",
    "boolean": "httpd_can_network_connect"
  }
]
```

Same AVC, different configuration in `docs/examples/fixtures/deterministic/10-boolean-hint/`: the curated override in `config/boolean_hints.yml` is consulted first; the outcome is identical (`boolean`, `http_port_t`, `httpd_can_network_connect`). The operator runs `setsebool httpd_can_network_connect on` on the host — the policy module package never carries it.

## interface

A refpolicy interface already shipped for this exact need. The generator invokes `try_sepolgen_interface` against the host's installed interfaces; when the mock is configured, the path is exercised without needing `sepolgen-ifgen`.

**From `docs/examples/fixtures/deterministic/08-interface-match/avc.log`:**

```text
type=AVC msg=audit(1710000195.000:215): avc:  denied  { search } for
pid=1234 comm="python3" name="log" path="/var/log" dev="vda4" ino=1
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_log_t:s0
tclass=dir permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "interface",
    "tgt": "var_log_t"
  }
]
```

The generator emits `list_dirs_pattern(myapp_t)` and records `engine: sepolgen`. The operator does nothing beyond compiling the `.te`.

## direct

Two flavours:

1. **`direct`** — the target is a private type inside the module (`myapp_port_t`, `myapp_var_lib_t`, etc.). The generator writes an explicit `allow src type:tclass { perms };` (or a pattern macro when the perms qualify).
2. **`direct`** — sepolgen ran but no refpolicy interface matched; the generator writes an explicit allow anyway and marks the engine as `house_rules`.

**`direct` (private type) — from `docs/examples/fixtures/deterministic/11-private-getopt/avc.log`:**

```text
type=AVC msg=audit(1710000170.000:212): avc:  denied  { getopt } for
pid=1234 comm="python3"
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:myapp_port_t:s0
tclass=tcp_socket permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "direct",
    "tgt": "myapp_port_t"
  }
]
```

The target is `myapp_port_t`, which `private_types()` identifies as in-module. The generator emits `allow myapp_t myapp_port_t:tcp_socket getopt;`.

**`direct` (no interface) — from `docs/examples/fixtures/deterministic/09-direct-no-interface/avc.log`:**

```text
type=AVC msg=audit(1710000198.000:216): avc:  denied  { read open getattr } for
pid=1234 comm="python3" name="notes.txt" path="/usr/share/myapp/notes.txt" dev="vda4" ino=88
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:usr_t:s0
tclass=file permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "direct",
    "tgt": "usr_t"
  }
]
```

`sepolgen` ran (mock `behavior: no_match`), no interface matched. The generator writes an explicit allow — `allow myapp_t usr_t:file { read open getattr };` — and the operator performs manual review before shipping.

## toolchain_required

sepolgen is missing on the host — the generator refuses a raw allow on a base type.

**From `docs/examples/fixtures/deterministic/07-toolchain-required/avc.log`:**

```text
type=AVC msg=audit(1710000190.000:214): avc:  denied  { search } for
pid=1234 comm="python3" name="log"
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_log_t:s0
tclass=dir permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "toolchain_required",
    "tgt": "var_log_t"
  }
]
```

`case.meta.json`:

```json
{
  "exit_code": 1,
  "stderr_substrings": [
    "SEPOLGEN INTERFACE MATCHING IS NOT AVAILABLE",
    "Boolean policy check could not run"
  ]
}
```

The generator prints the banner from `emit_sepolgen_warning()` in `cli/deterministic_gen.py` and returns `1`. The operator installs `policycoreutils-devel`, runs `sepolgen-ifgen`, and reruns. Alternatively, when the boolean check *did* run and only `sepolgen` is missing, `--allow-degraded` turns the blocked row into a `direct` allow with `engine=degraded`, generation completes, and the run exits `0` — the files are written and the reviewer is expected to treat those rows as `audit2allow` output. The flag is the escape hatch for a host that has a loaded policy but no sepolgen; it is not a way to skip the interface question silently. And it cannot reach the other failure mode: when the boolean query itself could not run, `classify()` returns `toolchain_required` before it ever looks at the flag, so the exit stays `1` — that is fixture `07-toolchain-required`, whose `boolean_mock.json` reports the lookup as unavailable.

## forbidden

A target type whose allow is held to be too wide for an app domain. `FORBIDDEN_TARGET_TYPES` (in `cli/policy_rules.py`) enumerates the six types: `shadow_t`, `unconfined_t`, `sysadm_t`, `security_t`, `selinux_config_t`, `passwd_file_t`.

**From `docs/examples/fixtures/deterministic/03-shadow-read/avc.log`:**

```text
type=AVC msg=audit(1710000200.000:201): avc:  denied  { read open } for
pid=1234 comm="python3" name="shadow" dev="vda4" ino=1
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:shadow_t:s0
tclass=file permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "forbidden",
    "tgt": "shadow_t"
  }
]
```

**`case.meta.json`:**

```json
{
  "exit_code": 1
}
```

The generator refuses the allow, prints `REFUSED` on stderr, and returns `1`. No `.te` line is written. The operator must rework the import logic to use a privileged helper domain, or accept that the data is unavailable from this module.

## needs_review

A domain-weakening permission. The generator classifies each (tclass, perm) pair against `NEEDS_REVIEW_RULES` in `cli/policy_rules.py`. The verdict records what the allow does, why it weakens the domain, and what the alternatives are; the allow is *not* written to the `.te` unless the operator passes `--allow-needs-review` (or the repeatable `--allow-needs-review-perm execmem`).

**From `docs/examples/fixtures/deterministic/12-execmem-review/avc.log`:**

```text
type=AVC msg=audit(1710000300.000:301): avc:  denied  { execmem } for
pid=1234 comm="java"
scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:system_r:myapp_t:s0
tclass=process permissive=1
```

**`expected.json`:**

```json
[
  {
    "verdict": "needs_review",
    "tgt": "myapp_t",
    "next_action": "review_then_opt_in"
  }
]
```

**`case.meta.json`:**

```json
{
  "exit_code": 1,
  "stderr_substrings": [
    "needs_review",
    "execmem",
    "--allow-needs-review"
  ]
}
```

The generator emits `allow myapp_t self:process execmem;` into `findings.json` and the pr_summary — `self` is how the renderer writes a target that is the domain itself (chapter 12 quotes the same line) — and the reviewer text: *"Security decision (needs review): the AVC log showed this permission was denied. It is not a labeling miss. The proposed allow is recorded in findings.json / pr_summary.md but is not written to the .te unless you pass --allow-needs-review (or --allow-needs-review-perm)."* Then: `process:execmem allows map memory as both writable and executable. It weakens the domain because it breaks W^X: memory the process can write, it can also execute. Alternatives: this AVC showed process execmem was denied. Some JVM/runtime configurations avoid writable+executable mappings; do not assume a JVM needs execmem. Confirm empirically for this workload and its options before --allow-needs-review.`

`exit_code: 1` — this finding is a generation blocker.

## Master table

| Verdict | Fixture directory | What it teaches | Generator exits non-zero? |
| --- | --- | --- | --- |
| `baseline` | `05-baseline-covered`, `13-cgroup-omit` | a macro already covers the denial; no allow is written | no (`exit_code: 0`) |
| `fc_drift` | `01-mislabeled-var-lib` | the `.fc` covers the path — restore the label, do not grant the generic type | no |
| `fc_fix` | `06-fc-missing-line` | the `.fc` is missing; the generator writes a `gen_context` line and you restorecon | no |
| `private_port` | `02-port-bind` | `name_bind` on a generic port; add to manifest `selinux_ports`, do not `semanage` on prod | no |
| `boolean` | `04-boolean-network-connect`, `10-boolean-hint` | `setsebool` on the host, not shipped in the RPM | no |
| `interface` | `08-interface-match` | refpolicy shipped the macro; no manual allow | no |
| `direct` | `11-private-getopt`, `09-direct-no-interface` | module-private type, or sepolgen ran but no macro matched | no (explicit allow written) |
| `toolchain_required` | `07-toolchain-required` | sepolgen is missing; base-type allow blocked until `sepolgen-ifgen` is run | yes (`exit_code: 1`) |
| `forbidden` | `03-shadow-read` | target type held too wide; no allow line, rework the access | yes (`exit_code: 1`) |
| `needs_review` | `12-execmem-review` | domain-weakening permission; opt-in with `--allow-needs-review` | yes (`exit_code: 1`) |

The three non-zero exit verdicts — `forbidden`, `toolchain_required`, `needs_review` — are exactly what `generation_blockers` (lines 323–332 of `cli/deterministic_gen.py`) collects. Each one is persisted to `findings.json` with `generation_blocked: true`, a `pr_summary.md` is written, and CI treats the non-zero status as a failure. The `forbidden` finding refuses to emit the allow; the `toolchain_required` finding refuses to emit a raw allow without interface coverage; the `needs_review` finding refuses to ship a domain-weakening allow without a deliberate opt-in.

## Why exit codes matter

CI pipeline gates on the generator's `sys.exit()` return code. A `forbidden` finding must stop the pipeline because the allow was refused — shipping would be a policy regression. A `needs_review` finding must stop the pipeline because the allow was *withheld* pending human review — shipping would be a domain-weakening regression. A `toolchain_required` finding must stop the pipeline because a base-type allow is unverified — shipping a raw allow without refpolicy coverage would be a regression.

The fixture `case.meta.json` files record the expected `exit_code` for each case. They are not aspirational; the generator's `run()` function returns the same value. Reading the fixture meta before writing policy makes the CI decision legible: a green build requires every finding to be either `baseline`, `fc_fix`/`fc_drift`, `private_port`, `boolean`, `interface`, or `direct`. If a single `forbidden`, `toolchain_required`, or `needs_review` (without `--allow-needs-review`) remains, the build is red.

## How to read a finding without the tool

Each `Finding` carries exactly three human-readable pieces of information: `verdict`, `rendered`, and `note`. Learning to read those three is how you audit the generator's decision.

- **`baseline`** — the note says "covered by …" or "already allowed in existing .te" or "omit rather than require …". No `rendered` line. The operator's job is finished.
- **`fc_fix`** — the `rendered` line is a `gen_context(...)` fragment. The note names the path and the suggested type. The operator adds that line to the `.fc` and `restorecon`s.
- **`fc_drift`** — the note names the path and says "already covered by `…`"; the generator explicitly writes no output. The operator `restorecon`s.
- **`private_port`** — the `rendered` line is an allow against a private port type; the note suggests `selinux_ports` in the manifest. The operator edits the manifest, not the RPM.
- **`boolean`** — the `rendered` line is a `setsebool` invocation; the note names the boolean. The operator runs `setsebool` on the host — it is *not* shipped in the RPM.
- **`interface`** — the `rendered` line is a refpolicy macro. The operator does nothing; the policy is correct as-is.
- **`direct`** — the `rendered` line is an explicit allow against a private type, or against a base type after sepolgen ran without a match. The operator must confirm the allow matches the workload before shipping.
- **`toolchain_required`** — the note names the missing tool and says "refusing raw allow". The operator installs the tool and reruns.
- **`forbidden`** — the note says "refusing to grant … access to …". The operator refuses the allow.
- **`needs_review`** — the note says "Security decision (needs review): …". The rendered line is the explicit allow; the operator opts in with `--allow-needs-review` only after confirming the AVC.

When you read a finding, the first question is *what did the generator write into the `.te`*? If it wrote nothing, you are either looking at `baseline`, `fc_drift`, `forbidden`, or a `needs_review` that was withheld. If it wrote an explicit allow, the engine is `sepolgen` (interface), `house_rules` (direct), or `degraded` (raw allow under `--allow-degraded`). The engine field tells you whether the allow was verified against refpolicy, written against a private type, or emitted because the toolchain was unavailable.

::: try Run three fixtures with --explain

```bash title="classify three verdict families on a laptop"
cd selinux-pac

python3 cli/deterministic_gen.py --explain \
  --avc-log docs/examples/fixtures/deterministic/01-mislabeled-var-lib/avc.log \
  --manifest config/myapp.manifest.yml \
  --existing-te selinux/myapp.te \
  --existing-fc selinux/myapp.fc

python3 cli/deterministic_gen.py --explain \
  --avc-log docs/examples/fixtures/deterministic/03-shadow-read/avc.log \
  --manifest config/myapp.manifest.yml \
  --existing-te selinux/myapp.te \
  --existing-fc selinux/myapp.fc

python3 cli/deterministic_gen.py --explain \
  --avc-log docs/examples/fixtures/deterministic/12-execmem-review/avc.log \
  --manifest config/myapp.manifest.yml \
  --existing-te selinux/myapp.te \
  --existing-fc selinux/myapp.fc \
  --allow-needs-review
```

Each invocation runs in `repo root` (no SELinux required). The first prints `[    fc_drift] myapp_t → var_lib_t:file {write}` with a restorecon note and exits 0 — compare to `01-mislabeled-var-lib/expected.json`. The second prints `[   forbidden] myapp_t → shadow_t:file {open read}` and exits 1 — compare to `03-shadow-read/case.meta.json`. The third prints `[needs_review] myapp_t → myapp_t:process {execmem}` with the full reviewer note and the proposed rule `→ allow myapp_t self:process execmem;`, and exits 0 as well — the opt-in flag clears the blocker; what stays behind is the note the reviewer has to weigh. Drop `--explain` and pass `--allow-needs-review` and that same line lands in the generated `.te` under a `# Needs review` heading, the run exits 0, and the reviewer is on the hook for the decision the flag recorded.


:::

::: why Next action is the field the operator acts on
Every verdict maps to one prescribed action — `baseline` means nothing, `fc_drift` and `fc_fix` mean restorecon, `boolean` means setsebool, `private_port` means manifest-edit, `direct` and `interface` mean write-the-allow, `forbidden` means refuse, `toolchain_required` means install-the-toolchain, and `needs_review` means opt-in. The map lives in `cli/policy_rules.py`, and each finding carries the resolved value in its `next_action` field. Two verdicts may share an action — `fc_fix` and `fc_drift` differ in *whether a `.fc` line is written*, not in what the operator then runs — but no verdict is ever missing one, and `baseline`'s deliberate empty string is the one case where the field says "nothing to do".
:::
## What you can do now

- Read any `findings.json` generated by the deterministic generator and identify which verdict produced each row, without rerunning the tool.
- Spot a non-zero exit code in CI and know which of the three blockers produced it — `forbidden`, `toolchain_required`, or `needs_review` (without `--allow-needs-review`).
- Run `--explain` on the laptop, compare each verdict to its fixture's `expected.json`, and confirm the generator's decision matches your mental model before trusting the output in CI.
