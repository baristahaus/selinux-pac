# Tests as Specification

> A generator's tests assert the decision, not the implementation. The input is a log, the output is a policy. If the policy changes when nothing about the log changes, you have a regression, not a feature.

## The wrong question to ask about tests

When you add a new class to a generator, you probably ask: *does the code still compile?* That
is the first question most of us ask. It is the wrong question. A generator translates an AVC log
into a policy decision. The log is the contract: you handed the kernel's denials to the tool and
asked it to read them. The policy is the answer. If the answer changes when you hand the same log
again, you broke the contract.

The natural but wrong test is a unit test of the parser. The test checks that the regex catches
four values, that the merge produces the right frozenset, and that the net-new filter returns the
expected list. These are all true, and all irrelevant. A generator that parses perfectly but
answers every AVC the same way is still a regression.

The right test asserts the answer, the `expected.json`.

## Why golden fixtures are the right test for a generator

A generator is not a state machine that you can exhaustively branch-test. It is a decision engine with a single observable output: the policy. Every test of the decision must look like a decision: a row in a file that says *this log, this verdict*.

This is what "golden fixture" means in this codebase:

| File | Role |
|------|------|
| `avc.log` | the log: what you fed the generator |
| `expected.json` | the assertion: what the generator must produce |
| `case.meta.json` (optional) | the meta: expected exit code, stderr substrings for blocked runs |
| `sepolgen_mock.json` (optional) | a mock for `sepolgen-ifgen` so the host-state path can run on a laptop |
| `boolean_mock.json` (optional) | a mock for `sesearch` so the boolean lookup runs without a live policy |

The test does not care about whether you refactored the parser, whether the net-new filter got faster, whether the boolean branch reached `sesearch` or `boolean_hints.yml`. It cares about the decision. If your refactoring moves the decision, you update the fixture. If your refactoring preserves the decision, the fixture passes. Either way, the test speaks the same language as the review.

The fixture is the reviewable data.

## The anatomy of a fixture

A real fixture directory looks like this:

```text
docs/examples/fixtures/deterministic/01-mislabeled-var-lib/
├── avc.log
├── expected.json
```

`avc.log` holds the raw audit lines, one record per line, exactly the shape `ausearch --format raw` prints:

```text
type=AVC msg=audit(1710000100.000:200): avc:  denied  { write } for  pid=1234 comm="python3" name="data.log" path="/var/lib/myapp/data.log" dev="vda4" ino=12345 scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=1
```

`expected.json` is an array of verdict rows. Each row names the verdict and the target type:

```json
[
  {
    "verdict": "fc_drift",
    "tgt": "var_lib_t"
  }
]
```

That is all. The test reads the line, classifies, emits the verdict, and asserts the two fields match. No parser test. No unit test. A decision against a decision.

When the case needs a meta file:

```json
// case.meta.json — real contents of 03-shadow-read
{
  "exit_code": 1
}
```

When the case needs a mock (because we have no `sepolgen-ifgen` on the CI host):

```json
// sepolgen_mock.json — real contents of 08-interface-match
{
  "behavior": "match",
  "rendered": "list_dirs_pattern(myapp_t)",
  "note": "Fixture mock — refpolicy interface match without sepolgen-ifgen on host."
}
```

Both quoted verbatim. These are real payloads in the repo.

## Determinism: no network, no SELinux, no root

The fixture suite runs with the same invariant as every test in this chapter: no network, no SELinux host, no root. Each host-state lookup that touches the live policy is replaced by an in-process mock. The mocks live in the fixture directory alongside the log, and the test reads them before the run:

| Mock | Replaces | Default behavior |
|------|----------|-------------------|
| `sepolgen_mock.json` | host-side `sepolgen-ifgen` (refpolicy interface matching) | `behavior`: `match` / `no_match` |
| `boolean_mock.json` | host-side `sesearch` (boolean policy query) | `behavior`: `match` with curated `matches[]`, or `none` |
| `boolean_hints.yml` | the curated override file (offline, no live policy) | used by `boolean_hints` module, no host needed |

The mocks are not hiding the host. They keep the test portable and honest. A CI host without `selinux-policy-devel` runs the same checks as the staging box. If the decision changes, the mock does too. If the mock reports a boolean that is no longer on the box, you update the fixture. Either way the test still asserts the decision.

The test runs without `root`, without `selinux-policy-devel`, without `sesearch`. That is why the suite is runnable on a laptop. That is why the CI uses it first.

## `make check` and what each target runs

The top-level `Makefile` is the single entry point for all verification. The targets are ordered so each layer of tests covers a different surface.

| Target | What it runs |
|--------|--------------|
| `make test-fixtures` | `scripts/run_deterministic_fixtures.sh` + `run_deterministic_payments_check.sh` + `run_blast_radius_fixtures.sh` + `run_tune_report_fixtures.sh` |
| `make test-static` | `make test-forbidden` + `test-version` + `test-rpm` + `test-manifest`: shell validators that grep `selinux/` |
| `make test-smoke` | `scripts/smoke_test.py`: the Python test suite. §2 of the testing doc describes its place in the pipeline, and the file itself is the full list |
| `make test` | `deps test-fixtures test-static test-smoke`: offline health check, no SELinux host required |
| `make check` | `test lint book-check`: full repo health, offline tests, linters, book links |
| `make lint` | `lint-shell` (shellcheck) + `lint-yaml` (yamllint) + `lint-ansible` (ansible-lint) |
| `make fixtures` | aliases to `test-fixtures` only |
| `make test-blast-radius` | blast-radius fixtures (skips live `sesearch` locally) |

A green `make test` is the proof of the decision. A green `make check` is the proof of the whole repo. Neither needs a SELinux host.

The target definitions above are real. Every command quoted above is in the repo's `Makefile` today. The target lines read as follows. Only the fixture recipe is shown, and `make help` prints exactly these comments:

```make
test: deps test-fixtures test-static test-smoke ## Offline health check (no SELinux host required)
check: test lint book-check ## Full repo health: offline tests + linters + book links
fixtures: test-fixtures ## Deterministic + payments + blast-radius fixture suites only
test-fixtures: ## Golden deterministic, payments + blast-radius + tune-report fixtures
	bash scripts/run_deterministic_fixtures.sh
	bash scripts/run_deterministic_payments_check.sh
	bash scripts/run_blast_radius_fixtures.sh
	bash scripts/run_tune_report_fixtures.sh
test-static: test-forbidden test-version test-rpm test-manifest ## Shell validators (offline)
test-smoke: deps ## Python smoke_test.py (offline; no SELinux host)
```

## How each neighbouring suite protects

| Suite | Verdict exercised | Why it sits next to the others |
|-------|-------------------|-------------------------------|
| **deterministic** | every classification verdict (`fc_drift`, `private_port`, `forbidden`, `boolean`, `baseline`, `fc_fix`, `toolchain_required`, `interface`, `direct`, `needs_review`, etc.) | every decision path gets ≥1 golden row |
| **payments** | the generator must not emit `myapp.*` artifacts for the `payments` manifest | schema-level: every manifest owns its own output |
| **blast-radius** | `classify_policy_blast_radius.sh` tiering (1 / 3 / 7 days, or fail-closed JSON) | policy diff between base and candidate modules |
| **tune-report** | the `--tune-report` path classifies vendor-domain denials without writing a module | `tomcat_t` scenarios, host commands only |
| **boolean query integration** | live `sesearch` boolean discovery (optional, and it skips cleanly when the tool is absent) | the only test that talks to the policy on a host |
| **skip-AI** | sync of `generated/` against committed `selinux/` after each policy bump | the "did the AI output drift from the hand-written policy" check |

The last two are refresh-driven. `scripts/refresh_skip_ai_fixture.sh` re-copies `selinux/myapp.{te,fc}` into `docs/examples/fixtures/skip_ai/generated/` after each bump. `scripts/lib/stage_skip_ai_fixture.sh` stages `policy_out/` from those fixtures for offline demo use. The tests compare the two copies and fail on drift.

## How to add a fixture, end to end

1. **Create the directory.** `mkdir docs/examples/fixtures/deterministic/0X-<name>/`.
2. **Capture the AVC.** Paste the real audit line into `avc.log`. Real lines, not composite.
3. **Decide the verdict.** Why does this log produce this verdict? Write the reason. If you cannot justify it, do not add the fixture.
4. **Write `expected.json`.** Each row is `{ "verdict": "...", "tgt": "..." }`. If the case exits non-zero, add a `case.meta.json` with `exit_code`. If the case needs a mock, write the mock alongside the log.
5. **Run the suite.** `bash scripts/run_deterministic_fixtures.sh` or `make test-fixtures`. If it fails, read the failure.
6. **Adjust code only if the expectation is right.** A failed test is the generator answering a log differently. Either the log changed, or the rule changed. If the rule changed, the fixture passes and the code is the regression.

This is the contract: code follows the decision, not the other way around.

## What is not tested automatically

This is the honest section. Every automated test asserts a decision the machine can make. There are decisions only a human can make, and some decisions only a live host can make.

| Gap | Mitigation |
|-----|------------|
| Compiled policy on the host | `bash scripts/compile_and_validate.sh selinux` on **rhel-qa**, and it is not automated in CI |
| Real denials under `audit.log` | staging `monitor_avc.sh` runs permissive, exports AVCs, talks |
| Ansible behavior against a live host | `ansible/` playbooks, `enforce_production.yml`, `emergency_rollback.yml` |
| The book's prose | generator checks links, anchors, `repo:` references (`book-check`) |

The testing doc keeps its own list in §8. That list holds the gaps the *pipeline* cannot close on
its own, each with the manual run that covers it. The list names a real `logrotate` cron as
`logrotate_t` during a staging soak, and the RPM upgrade relabel path on a throwaway VM. It also
names fleet-wide `serial: 1` enforce against a canary host first, and AVC classification under
`semodule -DB` by hand. Read both tables before you claim a change is covered.

::: why Each row is the reviewable decision
Each `expected.json` row is a row in a file that says *this log, this verdict*, and that row is what the review reads. The test does not care about whether you refactored the parser, whether the net-new filter got faster, whether the boolean branch reached `sesearch` or `boolean_hints.yml`. It cares about the decision. If the decision changes when nothing about the log changes, you have a regression, not a feature. Each fixture row holds the reviewable data. That is why each row must carry its two fields exactly, and why each row must be preserved when the rule moves.

:::
::: try

Pick up any laptop. No SELinux, no root.

```bash
$ git clone https://github.com/<org>/selinux-pac.git
$ cd selinux-pac
$ make test-fixtures
```

The fixture suite needs `python3` and PyYAML (`pip3 install -r cli/requirements.txt`, or `make deps`). It needs no SELinux, no root, and no network once installed. `make test-fixtures` itself does not depend on `deps`, so on a bare interpreter it fails at `import yaml` before the first fixture runs. `make test` and `make check` do run `deps` first.

Every test must pass. Now add a fixture. The log must be one record per line, in the shape `ausearch` writes. The runner reads `type=AVC` lines and ignores a wrapped record:

```bash
$ mkdir docs/examples/fixtures/deterministic/99-temp-drift/
$ cat > docs/examples/fixtures/deterministic/99-temp-drift/avc.log <<'AVC'
type=AVC msg=audit(1710009999.000:900): avc:  denied  { write } for  pid=9999 comm="demo" name="x" path="/var/lib/myapp/x" dev="vda4" ino=99999 scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=1
AVC
$ cat > docs/examples/fixtures/deterministic/99-temp-drift/expected.json <<'JSON'
[
  { "verdict": "fc_drift", "tgt": "var_lib_t" }
]
JSON
$ make test-fixtures
```

It passes, because the path is already covered by the module's `.fc`. The fixture agrees with the
decision the code already makes. Now edit a parser branch. Flip the verdict the drift case
produces, run `make test-fixtures` again, and watch the same fixture fail with the row it
expected. That is the signal. Restore the branch, and the suite is green again. Then remove the
fixture.

```bash
$ rm -rf docs/examples/fixtures/deterministic/99-temp-drift/
```

That is the whole loop. The fixture is the test. The test is the decision. The decision is the specification.

:::
## What you can do now

- Assert a generator's decision against a decision: golden fixtures, not unit tests.
- Add one fixture in five minutes: log, verdict, `expected.json`, run, adjust, repeat.
- Read the mocks as part of the fixture contract. They are the host-state path, offline.
- Run the full loop locally: `make test-fixtures`, every verdict gets a row.
- Look at §8 of the testing doc. Every gap is named, and each gap has a paired mitigation.

The specification is in the fixture. The decision is in the decision. If the answer you handed the kernel still produces the same policy after your refactoring, you are done. If not, you update the fixture. Either way, the review has the same data.