# Fixture Catalogue

> Each verdict the generator knows is pinned to a golden file. If a verdict drifts,
> `make test-fixtures` fails. Every row on this page is a real directory under
> `docs/examples/fixtures/deterministic/`, read from the `expected.json` each case ships.

## The 13 deterministic cases

Each row is the fixture directory, the verdict as written in `expected.json`, the tuple the
AVC asked about, the answer the generator produces, and the chapter that teaches the
decision the verdict rewards.

| Directory | Verdict | What the AVC asked | Correct response | Chapter teaches it |
|---|---|---|---|---|
| `01-mislabeled-var-lib` | `fc_drift` | `write` on `/var/lib/myapp/data.log`, target type `var_lib_t` | `restorecon` — the path is already covered by `/var/lib/myapp(/.*)?` | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| `02-port-bind` | `private_port` | `name_bind` on port 8888, target type `unreserved_port_t` | Add a private port to the manifest; the generator suggests `semanage port -a` | [Ports, Booleans and Transitions](repo:book/part2/10-ports-booleans-and-transitions.md) |
| `03-shadow-read` | `forbidden` | `read open` on `shadow`, target type `shadow_t` | refuse — exit 1, never emit the rule | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| `04-boolean-network-connect` | `boolean` | `name_connect` to `http_port_t` | consult `sesearch` (or the boolean mock); set `httpd_can_network_connect` | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| `05-baseline-covered` | `baseline` | `read open getattr` on `random_device_t` | no allow — `dev_read_urand` macro covers the tuple | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| `06-fc-missing-line` | `fc_fix` | `write` on `/opt/myapp/cache/data`, target type `var_lib_t` | the generator adds a `.fc` line under `install_root` | [File Contexts and the Label Lifecycle](repo:book/part2/09-file-contexts-and-the-label-lifecycle.md) |
| `07-toolchain-required` | `toolchain_required` | `search` on `/var/log`, target type `var_log_t` | base-type allow blocked without `sepolgen-ifgen`; exit 1 | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |
| `08-interface-match` | `interface` | `search` on `/var/log`, target type `var_log_t` | refpolicy interface matches the tuple; emit the macro invocation | [Allow Rules and Interfaces](repo:book/part2/08-allow-rules-and-interfaces.md) |
| `09-direct-no-interface` | `direct` | `read open getattr` on `/usr/share/myapp/notes.txt`, target type `usr_t` | sepolgen ran but no macro matched; emit the raw allow | [Allow Rules and Interfaces](repo:book/part2/08-allow-rules-and-interfaces.md) |
| `10-boolean-hint` | `boolean` | `name_connect` to `http_port_t` | curated override in `config/boolean_hints.yml`; offline query | [Ports, Booleans and Transitions](repo:book/part2/10-ports-booleans-and-transitions.md) |
| `11-private-getopt` | `direct` | `getopt` on `myapp_port_t`, target type private to this module | raw allow — the type is application-private | [Designing a Domain](repo:book/part2/11-designing-a-domain.md) |
| `12-execmem-review` | `needs_review` | `execmem` on self, domain to domain, `process` class | security decision; exit 1 without `--allow-needs-review` | [Reviewing a Policy Pull Request](repo:book/part3/17-reviewing-a-policy-pull-request.md) |
| `13-cgroup-omit` | `baseline` | `getattr` on `cgroup_t`, target type `cgroup_t` | omitted — the type is often undeclared; no allow required | [When Policy Says No](repo:book/part2/12-when-policy-says-no.md) |

:::: why Each verdict is the answer to a different question
`fc_drift` means *the path is already covered*; `baseline` means *the tuple already allows*;
`forbidden` means *refuse*; `needs_review` means *security decision*; `toolchain_required`
means *the operator needs tooling before it can answer*. The generator does not invent a
verdict — each one answers the question it was asked.
::::

## Worked readings

Each case below is read the way the generator reads it: the AVC line quoted verbatim, the
tuple parsed, the verdict chosen, and the file the answer lands in.

### Case `01-mislabeled-var-lib` — `fc_drift`

The AVC line:

```text
avc:  denied  { write } for  pid=1234 comm="python3" name="data.log"
  path="/var/lib/myapp/data.log" dev="vda4" ino=12345
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:var_lib_t:s0
  tclass=file permissive=1
```

The tuple: `myapp_t → var_lib_t:file write`. The correct response is the existing `.fc`
already covers `/var/lib/myapp(/.*)?` — the file label has drifted because the path was
relabelled by something outside the packaging. The fix is `restorecon -v /var/lib/myapp/data.log`,
and the generator's output file is the **unchanged `.fc`** — no edits needed.

### Case `03-shadow-read` — `forbidden`

The AVC line:

```text
avc:  denied  { read open } for  pid=1234 comm="python3" name="shadow" dev="vda4" ino=1
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:shadow_t:s0
  tclass=file permissive=1
```

The tuple: `myapp_t → shadow_t:file read open`. The answer is **refuse**: `shadow_t` covers
every login secret on the box; giving `myapp_t` access to the whole file namespace is too
broad. The generator emits no `.te` line and exits with status 1. The fix lands in
**nothing** — the application either needs a dedicated type, or it gives up on reading
shadows.

### Case `04-boolean-network-connect` — `boolean`

The AVC line:

```text
avc:  denied  { name_connect } for  pid=1234 comm="python3"
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:http_port_t:s0
  tclass=tcp_socket permissive=1
```

The tuple: `myapp_t → http_port_t:tcp_socket name_connect`. The answer is a boolean —
`httpd_can_network_connect` already toggles this tuple for the default vendor policy. The
generator emits no `.te` line: it resolves the tuple through the **policy query** path
(`sesearch`, mocked in the fixture — the curated-hint path is fixture `10-boolean-hint`),
records `"engine": "boolean_triage"`, and proposes `setsebool -P httpd_can_network_connect on`
in `host_admin_actions`. It does not run it — the fix lands in **the host's boolean state**,
where an operator or a playbook sets it, not in `selinux/`.

## Other fixture families

Each family lives under a different header in the fixture tree; each one answers a different
category of question the book asks about.

| Family | What it pins | Where it is documented |
|---|---|---|
| **`payments` checks** | `cli/deterministic_gen.py` must not emit `myapp` artifacts for the `payments` manifest | `scripts/run_deterministic_payments_check.sh`; `config/payments.manifest.example.yml` |
| **blast radius** | `scripts/classify_policy_blast_radius.sh` classifies candidate policy deltas against base policy | `tests/fixtures/blast_radius/`; `scripts/run_blast_radius_fixtures.sh` |
| **`tune_report`** | `--tune-report` generates only host commands (no `.te`); it classifies vendor-domain denials | `docs/examples/fixtures/tune_report/`; `scripts/run_tune_report_fixtures.sh` |
| **`skip_ai`** | Offline demo fixture — `baseline/` is the "before" state, `generated/` is the "after" state, `avc.log` is the recorded audit | `docs/examples/fixtures/skip_ai/README.md`; `scripts/refresh_skip_ai_fixture.sh` |
| **smoke tests** | Every classification verdict has at least one golden fixture row; every branch test in `classify_policy_blast_radius.sh`; boolean, FC, vendor, soak gates | `scripts/smoke_test.py` |

:::: note each family answers one question
`deterministic` pins classification verdicts; `payments` pins manifest boundaries;
`blast_radius` pins allow-rule deltas; `tune_report` pins the boundary of *no policy module*;
`skip_ai` pins the demo path; `smoke_test.py` pins every test in the repository.
Each one can run the same fixture independently of the others.
::::

## What you can do now

- Pick one verdict — `fc_drift`, `baseline`, `forbidden`, `boolean`, `needs_review`, or
  `interface` — and run `make test-fixtures` to watch it pin its own answer.
- Look at `docs/examples/fixtures/deterministic/01-mislabeled-var-lib/` and read the
  `avc.log` line verbatim; every fixture directory is this readable.
- Find the family that answers the question you are asking: `tune_report` for vendor
  domains, `blast_radius` for policy deltas, `skip_ai` for the end-to-end demo.
- When you add a new verdict, add a new fixture. The same check that fails the PR today
  fails the PR tomorrow.
