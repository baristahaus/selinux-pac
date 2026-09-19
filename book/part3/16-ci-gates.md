# The Gates in CI

> Every PR that touches `selinux/` runs two static checks before a human ever opens it. The gates refuse the two mistakes the generator cannot stop: a wildcard allow that compiles but breaks a host, and a version drift that makes the RPM and the compiled module disagree.

## Why CI is here at all

A policy change arrives on a `pull_request` from a developer's laptop. The generator already shaped it: `dev_generate_policy.sh --apply` writes the `.te` and `.fc`, bumps `policy_version.txt`, and the developer has run `validate_forbidden_patterns.sh` locally.

But the developer did not compile it. That happens only on **rhel-qa**, where `selinux-policy-devel` is installed and the admin owns the host. A CI check must confirm the generator did not silently introduce the patterns the generator already warned about, and the single-source-of-truth for the policy version still lines up. Those are the only two invariants a non-host workflow is allowed to assert.

Everything else — syntax correctness, missing allows, dontaudit surprise — defers to the admin on rhel-qa.

## What CI may do and what it must never do

The workflow [`.github/workflows/selinux-policy-ci.yml`](repo:.github/workflows/selinux-policy-ci.yml) runs on `runs-on: ubuntu-latest`. The box has bash and git, no SELinux kernel, no `audit.log`, no `semodule`, no `/var/lib/selinux`, no production credentials. The boundary is:

| May | Must never |
|---|---|
| `grep` the `.te` / `.fc` against shape patterns | Load a compiled `.pp` into any policy engine |
| parse `policy_version.txt` against a SemVer regex | Inspect or read any AVC file |
| compare `policy_module(...)` in `.te` to the version line | Execute any RHEL playbook |
| report pass / fail as a status check | install, load, or remove policy modules |

The companion [`.github/workflows/demo-estate.yml`](repo:.github/workflows/demo-estate.yml) is a different story — it has a `shopapi-policy` job that runs in a **`fedora:41` container** and installs the compile toolchain (`dnf install -y selinux-policy-devel make python3`). That container *does* compile a `.pp` — but it never loads it into a running kernel. It stops at `make`, never touches `audit.log`, never touches production inventory. Note what that install list does *not* contain: `setools-console`. The compile path needs no `sesearch`, which is exactly why a missing `sesearch` is a soak-gate condition and not a CI one.

That Fedora job is the *only* place in GitHub Actions that touches the policy toolchain, and every other job stays in bash-only land. That is why a separate file owns the compile path: the policy-compile job needs a `fedora:41` container because `selinux-policy-devel` is a Fedora package; the other jobs do not.

## The two static gates

### `forbidden-patterns`

[`.github/workflows/selinux-policy-ci.yml`](repo:.github/workflows/selinux-policy-ci.yml) invokes the script exactly twice per trigger:

```bash
bash scripts/validate_forbidden_patterns.sh selinux
POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t bash scripts/validate_forbidden_patterns.sh selinux/shopapi
```

The first call covers the default `myapp` module on the repo root. The second, parametrised by `POLICY_MODULE` / `SELINUX_DOMAIN`, covers `selinux/shopapi`. Those two invocations are the whole coverage: `selinux/payments` is tracked in the repository and is *not* passed to the gate, so adding a third module means adding a third line to the job — nothing discovers `selinux/*/` on its own.

`validate_forbidden_patterns.sh` runs on any machine with bash and Python 3 — laptop, CI, rhel-qa, no SELinux host required. It returns 0 only when every test passes; each `check_fail` call prints one specific error and sets `fail=1`.

Twelve refusals in total. Seven are regex checks against the `.te` — five on the shape of an `allow` line (wildcard target, wildcard class, fully wildcard, `self:*`, and `bin_t:file … execute`), one on `^module\s+` (the old module declaration a refpolicy `.te` must not use), and one on a broad `var_t:file` write. One is a loop over the three high-privilege target types. The remaining four are structural: the `require` block (a Python check for custom types declared inside it), a `policy_module()` presence check, a check that the file mentions its own domain, and the `.fc` content check.

| # | Pattern (text) | What it refuses |
|---|---|---|
| 1 | `allow\s+\w+\s+\*:` | Wildcard object type on the target — `allow shopapi_t *:` |
| 2 | `allow\s+\w+\s+\w+:\*\s` | Wildcard object class — `allow shopapi_t var_t:*` |
| 3 | `allow\s+\w+\s+\*:\*\s+\*\s+\*` | Fully wildcard allow — every field wild |
| 4 | `allow\s+\w+\s+self:\*` | Self-broad allow — `allow shopapi_t self:*` |
| 5 | `allow\s+\w+\s+bin_t:file\s+\{[^}]*execute` | `bin_t:file execute` on an app binary; `.fc` must ship a dedicated `*_exec_t` instead |
| 6 | `^module\s+` | Bare `module … {` declaration instead of `policy_module(myapp, …)` |
| 7 | Python regex inside `require { … }` that names `myapp_` custom types | Custom types declared inside the require block — they must be in a `.if` or in `.fc` only |
| 8 | `shadow_t`, `unconfined_t`, `sysadm_t` on the target side of any allow | Targeting a high-privilege type from the new module |
| 9 | `var_t:file` with `write` on the target side | Over-broad `var_t:file` write — every system file |
| 10 | Missing `policy_module` in the file | No module declaration at all |
| 11 | Missing `${SELINUX_DOMAIN}` in the file | Domain not referenced anywhere |
| 12 | A path/type token missing from `.fc` (except `myapp_canary` for the FCOS permissive overlay) | Path or dedicated type (`*_exec_t`, `*_var_lib_t`) absent from the file-contexts file |

**How to fix a failure:** read the error line; remove the offending allow from `.te`, add the dedicated type to `.fc`, or update the module declaration. If the token is absent because the path is genuinely out of scope — such as the FCOS permissive overlay on `myapp_canary` — that branch is skipped by `MODULE_NAME != "myapp_canary"`.

### `version-consistency`

The second job invokes `scripts/validate_version_consistency.sh` once. That script is the **single source of truth** check: every policy module's version line in `policy_version.txt` must match the version embedded in `policy_module(<module>, …)` in the corresponding `.te`, and every RPM spec that ships it must read the version out of that file through `--define "modver ${VERSION}"`.

The script `source`s `scripts/lib/version.sh`, which supplies two functions: `policy_version` reads and SemVer-validates the file, and `policy_module_version_from_te` extracts the SemVer from the first `policy_module(<app>, …)` line.

Two drift directions each produce an error:

| Direction | What fails | Why it matters |
|---|---|---|
| `.te` version out-of-sync with `policy_version.txt` | `validate_version_consistency: <module>: policy_version.txt (<canonical>) != policy_module in <module>.te (<from_te>)` | The source of truth is the file. The `.te` must read from it, not carry its own copy. |
| RPM spec ignoring `%{modver}` | `validate_version_consistency: <module>: <spec_file> must use 'Version: %{modver}'` | The RPM must derive its version from the single source, not hard-code a number. |

The script iterates every `policy_version.txt` under `selinux/` (each per-application module has its own under `selinux/<module>/`); the root-level `selinux/policy_version.txt` is the default for the top-level `myapp` module. It also verifies the single `define "modver ${VERSION}"` entry in `packaging/build_rpms.sh` — if that line is missing, the whole RPM pipeline is broken.

**How to fix a failure:** align the version in `.te` to the line in `policy_version.txt`, or replace a hardcoded `Version:` in the spec with `Version: %{modver}`. Note the loop's shape: it walks the `policy_version.txt` files that exist, so a module directory with no version file is skipped, not flagged. Give every module directory a `policy_version.txt` and the check covers it from then on.

## Blast-radius tiering

Soak duration is not uniform. A module that adds one rule on a module-private type needs 1 day of soak; a rule on a refpolicy interface or a non-module target type needs 3; an entrypoint change or a direct allow on a base-policy type needs 7.

`scripts/classify_policy_blast_radius.sh BASE CANDIDATE` computes each of those three tiers from two policy files given as explicit paths — compiled `.pp` files, or `.te` files that it compiles in place — one base and one candidate. Resolving the base from `git merge-base` is the caller's job: `scripts/lib/policy_module_diff.sh --from-merge-base` does it for the PR comment, and `check_soak_ready.sh --auto-tier` takes `--base-policy` and `--candidate-policy`. The two-stage pipeline is:

1. `scripts/lib/blast_radius_collect.sh` installs each `.pp` into a fresh [`policy_isolated_store.sh`](repo:scripts/lib/policy_isolated_store.sh) prefix — a `mktemp -d` copy of `/var/lib/selinux/targeted`, never touching the live policy — and runs `sesearch --allow -s <domain>` plus `sesearch -T` on each. It filters both by the module's domains, `comm -23` diffs the allow and type lines, and produces `added_all.txt` with the new lines from the candidate.
2. `scripts/lib/blast_radius_classify.py` parses each added line. The parser carries a small fixed vocabulary: `BASE_TARGET_TYPES` (`var_t`, `etc_t`, `usr_t`, `bin_t`, `shadow_t`, `unlabeled_t`, `tmp_t`, `proc_t`, `sysfs_t`); `TYPE_RULE_PREFIXES` (`type_transition`, `type_change`, `type_member`, `role_transition`, `range_transition`); a regular expression that matches the `allow source target:tclass { perms };` form. The tier logic is `TIER_RANK = {"low": 0, "medium": 1, "high": 2}` with `TIER_DAYS = {"low": 1, "medium": 3, "high": 7}`. A rule is scored as:
   - **high** when the permission set contains `entrypoint`, when the target is one of `BASE_TARGET_TYPES`, when it is a type-transition prefix, or when it is unparseable (the parser bails on the whole set as high with `fail_closed: true`).
   - **low** when every target starts with `myapp_` — the prefix is a literal in the classifier today, so a `shopapi`-only delta lands in the medium tier and gets three soak days, not one.
   - **medium** when it touches a refpolicy interface or any other non-module target type.
3. The classifier's `main()` prints one JSON blob with `tier`, `min_days`, `reason`, a `sediff_excerpt` (first 2000 characters of the diff), and `fail_closed`. That blob is the answer `check_soak_ready.sh --auto-tier` reads.

The fixtures — under `tests/fixtures/blast_radius/` referenced from [`docs/admin/302-PRODUCTION_READINESS.md`](repo:docs/admin/302-PRODUCTION_READINESS.md) — lock the tier logic: every verdict has a golden row, and `make test-fixtures` runs them. Do not change the tier rules without updating fixtures.

## The PR comment

A policy access delta is what the admin reads before opening the `.te`. [`scripts/ci/post_pr_policy_diff_comment.sh`](repo:scripts/ci/post_pr_policy_diff_comment.sh) produces it:

```bash
bash scripts/lib/policy_module_diff.sh \
  --app-name <app> --from-merge-base --cand-dir selinux --output /tmp/diff.md --format markdown
```

The diff script [`scripts/lib/policy_module_diff.sh`](repo:scripts/lib/policy_module_diff.sh) compiles both sides (base from the git merge-base, candidate from `selinux/`), installs each compiled `.pp` into its own isolated store, runs `sesearch --allow` per domain on each, diffs the two allow dumps with `comm`, and emits a markdown file with **Rules ADDED** and **Rules REMOVED** for the app domains. It diffs *allow rules only* — the type lines are the blast-radius collector's job, in the next section.

`post_pr_policy_diff_comment.sh` wraps that output inside a markdown comment marker (`<!-- selinux-policy-module-diff -->`), calls `gh api` against `repos/<repo>/issues/<PR>/comments` to locate any existing comment bearing that marker, and either `PATCH`s it or `gh pr comment <PR>` opens a fresh one. The whole thing requires the GitHub Actions context (`GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`); it refuses to run outside.

The marker is the only durable linkage: every subsequent PR run rewrites the same comment instead of stacking new ones.

## CODEOWNERS

The [`.github/CODEOWNERS`](repo:.github/CODEOWNERS) file is deliberately narrow — there are two lines, and both point to the same reviewer:

```text
/selinux/                    @anurag-saran
/ansible/                    @anurag-saran
```

The reasoning is explicit: a SELinux policy review is not a code review. A `bin_t:file execute` line compiles; the review is "does this app binary really need the `bin_t` type, or should the manifest ship a dedicated `*_exec_t`?". The review is also "does this allow target a base-policy type — `shadow_t`, `unlabeled_t`, `bin_t`?" — and the review catches only when a human reads each allow against the manifest.

GitHub routes every review request for the policy directory and the Ansible playbook directory to the same person. No bot, no auto-approval for policy.

## The pull-request template

The PR template [`.github/PULL_REQUEST_TEMPLATE/selinux_policy_review.md`](repo:.github/PULL_REQUEST_TEMPLATE/selinux_policy_review.md) is shaped to the gates — each section tells the admin what the gate already verified and what the admin still needs to read.

| Section | Purpose | Maps to |
|---|---|---|
| **1. Application Context** | App name, target domain, policy version, staging host, test suite run, AVC line count (all auto-filled by the generator) | `version-consistency` — the version field is the same line the script reads |
| **2. Policy summary** | Plain-English narrative generated by the deterministic engine from the AVC denials; the admin reads this instead of raw `.te` | Forbidden patterns — the summary names each allow and the engine refuses the wildcard shapes |
| **2.5 Policy access delta (merge-base)** | **Rules ADDED** / **Rules REMOVED** from `policy_module_diff.sh`; this is what the admin actually looks at first | The PR comment is produced by `post_pr_policy_diff_comment.sh` |
| **3. Generated files included** | Checkboxes for `.te`, `.fc`, `policy_version.txt`, `.if` per module; each check forces the author to confirm each file exists | `validate_forbidden_patterns.sh` checks each file's presence and token completeness |
| **4. AVC evidence** | Sample lines from staging; lets the admin cross-reference the generator's output against a real denial | Semantic assertions — `validate_policy_semantics.sh` compares each allow to a real denial |
| **5. Developer self-attestation** | Developer confirms no wildcards, no high-privilege domains, the generator ran, and that the CI checks must pass before merge | `forbidden-patterns` and `version-consistency` — these *must* be green |
| **6. Security and sysadmin checklist** | A table of security checks with status (Pass / Reject) and approver initials — `No over-permissive grants`, `Custom labels enforced`, `Port assignments validated`, `Domain context verified`, `Soak period`, `Systemd-only restart`, `Prod canary host`, `Canary readiness` | Each row corresponds to a post-merge gate in the Ansible playbook pipeline |
| **7. Admin action** | Post-merge steps: compile, package, release canary, soak monitor, promote to enforce, rollback | All of the playbook orchestration |

The `labels` in the YAML header (`security`, `selinux`, `pending-admin-review`) are for triage and reporting — GitHub generates the review request from the paths a PR touches, not from labels. The template does not auto-approve.

::: note The demo-estate workflow and the Fedora container

The `demo-estate.yml` workflow is not a security gate; it is a **smoke run** of the three-app demo without a RHEL host. It:

1. dry-runs `demo_present.sh --dry-run --no-type --auto --profile customer` and `--profile technical` to confirm the narration still lines up,
2. syntax-checks the shell scripts,
3. confirms `shopapi.te` has no guessed JVM allows (`allow … (execmem|execstack|dac_override)`),
4. runs `validate_version_consistency.sh`,
5. packages the Spring Boot JAR (`mvn -q -DskipTests -f demo/shopapi/pom.xml package`),
6. compiles the `shopapi` policy inside a `fedora:41` container by installing `selinux-policy-devel` and running `compile_and_validate.sh`.

The container does not persist state between runs; each run starts with a fresh `dnf install` and ends with a built `.pp` that is never installed. It is not a production environment, not a security gate, not a substitute for `validate_policy_semantics.sh` — it is a *build*.

`selinux-policy-devel` is a Fedora package and `dnf` is the only way to install it on a GitHub-hosted Ubuntu box. Every other policy-compile run still goes to **rhel-qa**.
:::
::: try Run the gates locally

Nothing here requires a host. Take a fresh clone of `selinux-pac` on your laptop and run the gate against a real module:

```bash
$ cp -r selinux/shopapi /tmp/shopapi-gate-check
$ POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t \
    bash scripts/validate_forbidden_patterns.sh /tmp/shopapi-gate-check
[INFO] Checking forbidden patterns in /tmp/shopapi-gate-check/shopapi.te
[INFO] Forbidden-pattern checks passed for shopapi
```

The module passes, because the gate is not there to catch the module that was written carefully. Now break it deliberately — one wildcard line is enough:

```bash
$ echo 'allow shopapi_t *:file read;' >> /tmp/shopapi-gate-check/shopapi.te
$ POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t \
    bash scripts/validate_forbidden_patterns.sh /tmp/shopapi-gate-check
[INFO] Checking forbidden patterns in /tmp/shopapi-gate-check/shopapi.te
[ERROR] Wildcard object type in allow rule
```

It exits 1. Remove the line and the gate is green again:

```bash
$ sed -i '/allow shopapi_t \*:file read;/d' /tmp/shopapi-gate-check/shopapi.te
$ POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t \
    bash scripts/validate_forbidden_patterns.sh /tmp/shopapi-gate-check
[INFO] Forbidden-pattern checks passed for shopapi
```

Both runs must carry `POLICY_MODULE` and `SELINUX_DOMAIN`: without them the script looks for `myapp.te` and fails with `[ERROR] Missing /tmp/shopapi-gate-check/myapp.te`, which is a different error about a different module.

Then break the second rule — the version line, deliberately. This check reads the repository's own files, so edit the tracked module and undo it with `git` afterwards:

```bash
$ sed -i 's/policy_module(shopapi, 1\.0\.0)/policy_module(shopapi, 0.0.999)/' selinux/shopapi/shopapi.te
$ bash scripts/validate_version_consistency.sh
validate_version_consistency: payments OK (1.0.0)
validate_version_consistency: myapp OK (1.1.3)
validate_version_consistency: shopapi: /path/to/selinux-pac/selinux/shopapi/policy_version.txt (1.0.0) != policy_module in /path/to/selinux-pac/selinux/shopapi/shopapi.te (0.0.999)
validate_version_consistency: shopapi OK (1.0.0)
$ git checkout -- selinux/shopapi/shopapi.te
```

(That trailing `OK` after an error is the script's own shape — it always prints the module line and counts the error; the exit code does the gating.)

It exits 1, and the message names both files by absolute path. `git checkout` restores the real version; run the check once more and both gates pass again. Both checks are one command each, and they are the same commands CI runs.
:::

## What you can do now
- open a PR against `selinux/` and watch `forbidden-patterns` + `version-consistency` run without touching a SELinux host.
- break the wildcard-pattern rule on purpose and confirm the error message matches the table above.
- break the version-drift rule and confirm the single-source-of-truth check rejects the drift in both directions.
- read the PR comment produced by `post_pr_policy_diff_comment.sh` on a real PR to see **Rules ADDED** / **Rules REMOVED** for your module.
