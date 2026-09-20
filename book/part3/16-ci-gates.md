# The Gates in CI

> Every PR that touches `selinux/` runs two static checks before a human opens it. The gates refuse two mistakes that the generator cannot stop. The first is a wildcard allow that compiles but breaks a host. The second is a version drift that makes the RPM and the compiled module disagree.

## Why CI is here at all

A policy change arrives on a `pull_request` from a developer's laptop. The generator already shaped it: `dev_generate_policy.sh --apply` writes the `.te` and `.fc`, bumps `policy_version.txt`, and the developer ran `validate_forbidden_patterns.sh` locally.

But the developer did not compile it. That happens only on rhel-qa, where `selinux-policy-devel` is installed and the admin owns the host. A CI check must make sure that the generator did not introduce the patterns it already warned about. It must also make sure that the single source of truth for the policy version still lines up. A non-host workflow asserts only those two invariants.

The admin on rhel-qa checks everything else: syntax correctness, missing allows, and a dontaudit surprise.

## What CI may do and what it must never do

The workflow [`.github/workflows/selinux-policy-ci.yml`](repo:.github/workflows/selinux-policy-ci.yml) runs on `runs-on: ubuntu-latest`. The runner has bash and git. It has no SELinux kernel, no `audit.log`, no `semodule`, no `/var/lib/selinux`, and no production credentials. The boundary is:

| Can | Must never |
|---|---|
| `grep` the `.te` / `.fc` against shape patterns | Load a compiled `.pp` into any policy engine |
| parse `policy_version.txt` against a SemVer regex | Inspect or read any AVC file |
| compare `policy_module(...)` in `.te` to the version line | Execute any RHEL playbook |
| report pass / fail as a status check | install, load, or remove policy modules |

The companion [`.github/workflows/demo-estate.yml`](repo:.github/workflows/demo-estate.yml) tells a different story. It has a `shopapi-policy` job that runs in a `fedora:41` container and installs the compile toolchain (`dnf install -y selinux-policy-devel make python3`). That container compiles a `.pp`. It never loads it into a running kernel. It stops at `make`. It never touches `audit.log`, and it never touches the production inventory. Note what that install list does not contain: `setools-console`. The compile path needs no `sesearch`. That is why a missing `sesearch` is a soak-gate condition and not a CI one.

That Fedora job is the only place in GitHub Actions that touches the policy toolchain. Every other job stays in bash-only territory. A separate file owns the compile path for one reason: the policy-compile job needs a `fedora:41` container, because `selinux-policy-devel` is a Fedora package. The other jobs do not.

## The two static gates

### `forbidden-patterns`

[`.github/workflows/selinux-policy-ci.yml`](repo:.github/workflows/selinux-policy-ci.yml) invokes the script exactly twice per trigger:

```bash
bash scripts/validate_forbidden_patterns.sh selinux
POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t bash scripts/validate_forbidden_patterns.sh selinux/shopapi
```

The first call covers the default `myapp` module on the repo root. The second call covers `selinux/shopapi`, and `POLICY_MODULE` / `SELINUX_DOMAIN` set its names. Those two calls are the whole coverage. The repository tracks `selinux/payments`, but the job does not pass it to the gate. So a third module needs a third line in the job. Nothing discovers `selinux/*/` on its own.

`validate_forbidden_patterns.sh` runs on any machine with bash and Python 3: a laptop, a CI runner, or rhel-qa. It does not need a SELinux host. It returns 0 only when every test passes. Each `check_fail` call prints one specific error and sets `fail=1`.

The script has twelve refusals in total. Seven are regex checks against the `.te`. Five of them check the shape of an `allow` line: wildcard target, wildcard class, fully wildcard, `self:*`, and `bin_t:file … execute`. One checks a broad `var_t:file` write. One checks `^module\s+`, the old module declaration that a refpolicy `.te` must not use.

An eighth check loops over the three high-privilege target types. The remaining four are structural. One is a Python check for custom types declared inside the `require` block. One checks that `policy_module()` is present. One checks that the file mentions its own domain. The last one checks the `.fc` content.

| # | Pattern (text) | What it refuses |
|---|---|---|
| 1 | `allow\s+\w+\s+\*:` | Wildcard object type on the target, for example `allow shopapi_t *:` |
| 2 | `allow\s+\w+\s+\w+:\*\s` | Wildcard object class, for example `allow shopapi_t var_t:*` |
| 3 | `allow\s+\w+\s+\*:\*\s+\*\s+\*` | Fully wildcard allow, where every field is wild |
| 4 | `allow\s+\w+\s+self:\*` | Self-broad allow, for example `allow shopapi_t self:*` |
| 5 | `allow\s+\w+\s+bin_t:file\s+\{[^}]*execute` | `bin_t:file execute` on an app binary. The `.fc` file must ship a dedicated `*_exec_t` instead |
| 6 | `^module\s+` | Bare `module … {` declaration instead of `policy_module(myapp, …)` |
| 7 | Python regex inside `require { … }` that names `myapp_` custom types | Custom types declared inside the require block. They belong only in a `.if` or in `.fc` |
| 8 | `shadow_t`, `unconfined_t`, `sysadm_t` on the target side of any allow | Targeting a high-privilege type from the new module |
| 9 | `var_t:file` with `write` on the target side | Broad `var_t:file` write, which covers every system file |
| 10 | Missing `policy_module` in the file | No module declaration at all |
| 11 | Missing `${SELINUX_DOMAIN}` in the file | The file never mentions the domain |
| 12 | A path/type token missing from `.fc` (except `myapp_canary` for the FCOS permissive overlay) | A path or dedicated type (`*_exec_t`, `*_var_lib_t`) is absent from the file-contexts file |

**How to fix a failure:** read the error line. Then remove the offending allow from `.te`, add the dedicated type to `.fc`, or update the module declaration. `MODULE_NAME != "myapp_canary"` skips that branch, when a path is out of scope. The FCOS permissive overlay on `myapp_canary` is one such path.

### `version-consistency`

The second job runs `scripts/validate_version_consistency.sh` once. That script is the single source of truth check. Each policy module has a version line in `policy_version.txt`. That line must match the version inside `policy_module(<module>, …)` in the matching `.te`. Every RPM spec that ships the module must read the version from that file, through `--define "modver ${VERSION}"`.

The script runs `source` on `scripts/lib/version.sh`, which supplies two functions. `policy_version` reads the file and checks that it holds a SemVer. `policy_module_version_from_te` extracts the SemVer from the first `policy_module(<app>, …)` line.

Two drift directions each produce an error:

| Direction | What fails | Why it matters |
|---|---|---|
| `.te` version out-of-sync with `policy_version.txt` | `validate_version_consistency: <module>: policy_version.txt (<canonical>) != policy_module in <module>.te (<from_te>)` | The source of truth is the file. The `.te` must read from it, not carry its own copy. |
| RPM spec ignoring `%{modver}` | `validate_version_consistency: <module>: <spec_file> must use 'Version: %{modver}'` | The RPM must derive its version from the single source, not hard-code a number. |

The script iterates every `policy_version.txt` under `selinux/`. Each per-application module has its own copy under `selinux/<module>/`. The root-level `selinux/policy_version.txt` is the default for the top-level `myapp` module. The script also checks the single `define "modver ${VERSION}"` entry in `packaging/build_rpms.sh`. If that line is missing, the whole RPM pipeline is broken.

**How to fix a failure:** align the version in `.te` with the line in `policy_version.txt`, or replace a hardcoded `Version:` in the spec with `Version: %{modver}`. Note the shape of the loop. It walks the `policy_version.txt` files that exist, so the script skips a module directory with no version file instead of flagging it. Put a `policy_version.txt` in every module directory, and the check covers it from then on.

## Blast-radius tiering

Soak duration is not uniform. A module that adds one rule on a module-private type needs 1 day of soak. A rule on a refpolicy interface or on a non-module target type needs 3. An entrypoint change, or a direct allow on a base-policy type, needs 7.

`scripts/classify_policy_blast_radius.sh BASE CANDIDATE` computes each of those three tiers. It takes two policy files as explicit paths: one base and one candidate. Each path can be a compiled `.pp`, or a `.te` file that the script compiles in place. Resolving the base from `git merge-base` is the caller's job. `scripts/lib/policy_module_diff.sh --from-merge-base` does that for the PR comment. `check_soak_ready.sh --auto-tier` takes `--base-policy` and `--candidate-policy`. The pipeline has two stages:

1. `scripts/lib/blast_radius_collect.sh` installs each `.pp` into a fresh [`policy_isolated_store.sh`](repo:scripts/lib/policy_isolated_store.sh) prefix. That prefix is a `mktemp -d` copy of `/var/lib/selinux/targeted`, so the live policy does not change. The script then runs `sesearch --allow -s <domain>` and `sesearch -T` on each store. It filters both outputs by the domains of the module. `comm -23` diffs the allow lines and the type lines, and writes `added_all.txt` with the new lines from the candidate.
2. `scripts/lib/blast_radius_classify.py` parses each added line. The parser carries a small fixed vocabulary. `BASE_TARGET_TYPES` holds `var_t`, `etc_t`, `usr_t`, `bin_t`, `shadow_t`, `unlabeled_t`, `tmp_t`, `proc_t`, and `sysfs_t`. `TYPE_RULE_PREFIXES` holds `type_transition`, `type_change`, `type_member`, `role_transition`, and `range_transition`. A regular expression matches the `allow source target:tclass { perms };` form. The tier logic is `TIER_RANK = {"low": 0, "medium": 1, "high": 2}` with `TIER_DAYS = {"low": 1, "medium": 3, "high": 7}`. The score of a rule is:
   - **high** when the permission set contains `entrypoint`, or when the target is one of `BASE_TARGET_TYPES`. It is also high for a type-transition prefix, and for a line the parser cannot read. In that case the parser marks the whole set high, with `fail_closed: true`.
   - **low** when every target starts with `myapp_`. That prefix is a literal in the classifier today. So a `shopapi`-only delta lands in the medium tier, and it gets three soak days, not one.
   - **medium** when the rule touches a refpolicy interface or any other non-module target type.
3. The classifier's `main()` prints one JSON blob with `tier`, `min_days`, `reason`, a `sediff_excerpt` (first 2000 characters of the diff), and `fail_closed`. That blob is the answer `check_soak_ready.sh --auto-tier` reads.

The fixtures lock the tier logic. They live under `tests/fixtures/blast_radius/`, and [`docs/admin/302-PRODUCTION_READINESS.md`](repo:docs/admin/302-PRODUCTION_READINESS.md) references that path. Every verdict has a golden row, and `make test-fixtures` runs them. If you change the tier rules, you must update the fixtures.

## The PR comment

A policy access delta is what the admin reads before opening the `.te`. [`scripts/ci/post_pr_policy_diff_comment.sh`](repo:scripts/ci/post_pr_policy_diff_comment.sh) produces it:

```bash
bash scripts/lib/policy_module_diff.sh \
  --app-name <app> --from-merge-base --cand-dir selinux --output /tmp/diff.md --format markdown
```

The diff script [`scripts/lib/policy_module_diff.sh`](repo:scripts/lib/policy_module_diff.sh) compiles both sides: the base from the git merge-base, and the candidate from `selinux/`. It installs each compiled `.pp` into its own isolated store, and runs `sesearch --allow` per domain on each store. It diffs the two allow dumps with `comm`. It then emits a markdown file with `Rules ADDED` and `Rules REMOVED` for the app domains. The script diffs allow rules only. The next section covers the type lines, which are the job of the blast-radius collector.

`post_pr_policy_diff_comment.sh` wraps that output inside a markdown comment marker (`<!-- selinux-policy-module-diff -->`). It calls `gh api` against `repos/<repo>/issues/<PR>/comments` to find an existing comment with that marker. If one exists, the script sends a `PATCH`. If none exists, `gh pr comment <PR>` opens a fresh one. The script needs the GitHub Actions context (`GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`). Outside that context, it refuses to run.

The marker is the only durable linkage: every subsequent PR run rewrites the same comment instead of stacking new ones.

## CODEOWNERS

The [`.github/CODEOWNERS`](repo:.github/CODEOWNERS) file is deliberately narrow. It has two lines, and both point to the same reviewer:

```text
/selinux/                    @anurag-saran
/ansible/                    @anurag-saran
```

The reasoning is explicit: a SELinux policy review is not a code review. A `bin_t:file execute` line compiles, so the reviewer must answer a different question. Does this app binary really need the `bin_t` type, or must the manifest ship a dedicated `*_exec_t`? The reviewer must also ask whether the allow targets a base-policy type (`shadow_t`, `unlabeled_t`, `bin_t`). A human catches both only by reading each allow against the manifest.

GitHub routes every review request for the policy directory and the Ansible playbook directory to the same person. There is no bot, and there is no auto-approval for policy.

## The pull-request template

The PR template [`.github/PULL_REQUEST_TEMPLATE/selinux_policy_review.md`](repo:.github/PULL_REQUEST_TEMPLATE/selinux_policy_review.md) is shaped to the gates. Each section tells the admin what the gate already checked and what the admin still needs to read.

| Section | Purpose | Maps to |
|---|---|---|
| **1. Application Context** | App name, target domain, policy version, staging host, test suite run, AVC line count. The generator fills in all of these. | `version-consistency`: the version field is the same line the script reads |
| **2. Policy summary** | Plain-English narrative that the deterministic engine builds from the AVC denials. The admin reads this instead of the raw `.te`. | Forbidden patterns: the summary names each allow, and the engine refuses the wildcard shapes |
| **2.5 Policy access delta (merge-base)** | **Rules ADDED** / **Rules REMOVED** from `policy_module_diff.sh`. This is what the admin looks at first. | `post_pr_policy_diff_comment.sh` produces the PR comment |
| **3. Generated files included** | Checkboxes for `.te`, `.fc`, `policy_version.txt`, and `.if` per module. Each checkbox makes the author check that the file exists. | `validate_forbidden_patterns.sh` checks the presence and the token completeness of each file |
| **4. AVC evidence** | Sample lines from staging. The admin can compare the output of the generator with a real denial. | Semantic assertions: `validate_policy_semantics.sh` compares each allow to a real denial |
| **5. Developer self-attestation** | The developer states that the module has no wildcards and no high-privilege domains, and that the generator ran. The developer also states that the CI checks must pass before merge. | `forbidden-patterns` and `version-consistency`: both must be green |
| **6. Security and sysadmin checklist** | A table of security checks with a status (Pass / Reject) and the initials of the approver: `No over-permissive grants`, `Custom labels enforced`, `Port assignments validated`, `Domain context verified`, `Soak period`, `Systemd-only restart`, `Prod canary host`, `Canary readiness` | Each row maps to a post-merge gate in the Ansible playbook pipeline |
| **7. Admin action** | Post-merge steps: compile, package, release canary, soak monitor, promote to enforce, rollback | All of the playbook orchestration |

The `labels` in the YAML header (`security`, `selinux`, `pending-admin-review`) are for triage and reporting. GitHub generates the review request from the paths a PR touches, not from labels. The template does not auto-approve.

::: note The demo-estate workflow and the Fedora container

The `demo-estate.yml` workflow is not a security gate. It is a smoke run of the three-app demo, and it needs no RHEL host. The job does this:

1. dry-runs `demo_present.sh --dry-run --no-type --auto --profile customer` and `--profile technical` to check that the narration still lines up,
2. syntax-checks the shell scripts,
3. checks that `shopapi.te` has no guessed JVM allows (`allow … (execmem|execstack|dac_override)`),
4. runs `validate_version_consistency.sh`,
5. packages the Spring Boot JAR (`mvn -q -DskipTests -f demo/shopapi/pom.xml package`),
6. compiles the `shopapi` policy inside a `fedora:41` container by installing `selinux-policy-devel` and running `compile_and_validate.sh`.

The container keeps no state between runs. Each run starts with a fresh `dnf install` and ends with a built `.pp` that nothing installs. This is not a production environment, a security gate, or a substitute for `validate_policy_semantics.sh`. It is a build.

`selinux-policy-devel` is a Fedora package, and `dnf` is the only way to install it on a GitHub-hosted Ubuntu box. Every other policy-compile run still goes to rhel-qa.
:::
::: try Run the gates locally

Nothing here requires a host. Take a fresh clone of `selinux-pac` on your laptop. Then run the gate against a real module:

```bash
$ cp -r selinux/shopapi /tmp/shopapi-gate-check
$ POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t \
    bash scripts/validate_forbidden_patterns.sh /tmp/shopapi-gate-check
[INFO] Checking forbidden patterns in /tmp/shopapi-gate-check/shopapi.te
[INFO] Forbidden-pattern checks passed for shopapi
```

The module passes, because the gate is not there to catch a module that someone wrote carefully. Now break it on purpose. One wildcard line is enough:

```bash
$ echo 'allow shopapi_t *:file read;' >> /tmp/shopapi-gate-check/shopapi.te
$ POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t \
    bash scripts/validate_forbidden_patterns.sh /tmp/shopapi-gate-check
[INFO] Checking forbidden patterns in /tmp/shopapi-gate-check/shopapi.te
[ERROR] Wildcard object type in allow rule
```

It exits 1. Remove the line, and the gate is green again:

```bash
$ sed -i '/allow shopapi_t \*:file read;/d' /tmp/shopapi-gate-check/shopapi.te
$ POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t \
    bash scripts/validate_forbidden_patterns.sh /tmp/shopapi-gate-check
[INFO] Forbidden-pattern checks passed for shopapi
```

Both runs must set `POLICY_MODULE` and `SELINUX_DOMAIN`. Without them, the script looks for `myapp.te` and fails with `[ERROR] Missing /tmp/shopapi-gate-check/myapp.te`. That error is about a different module.

Then break the second rule on purpose: the version line. This check reads the files of the repository itself, so edit the tracked module. Undo the change with `git` afterwards:

```bash
$ sed -i 's/policy_module(shopapi, 1\.0\.0)/policy_module(shopapi, 0.0.999)/' selinux/shopapi/shopapi.te
$ bash scripts/validate_version_consistency.sh
validate_version_consistency: payments OK (1.0.0)
validate_version_consistency: myapp OK (1.1.3)
validate_version_consistency: shopapi: /path/to/selinux-pac/selinux/shopapi/policy_version.txt (1.0.0) != policy_module in /path/to/selinux-pac/selinux/shopapi/shopapi.te (0.0.999)
validate_version_consistency: shopapi OK (1.0.0)
$ git checkout -- selinux/shopapi/shopapi.te
```

(That trailing `OK` after an error is the shape of the script. It always prints the module line, and it counts the error. The exit code does the gating.)

It exits 1, and the message names both files by absolute path. `git checkout` restores the real version. Run the check once more, and both gates pass again. Each check is one command, and they are the same commands that CI runs.
:::

## What you can do now
- Open a PR against `selinux/` and watch `forbidden-patterns` + `version-consistency` run without a SELinux host.
- Break the wildcard-pattern rule on purpose, and check that the error message matches the table above.
- Break the version-drift rule and make sure that the single-source-of-truth check rejects the drift in both directions.
- Read the PR comment that `post_pr_policy_diff_comment.sh` writes on a real PR. Look for `Rules ADDED` / `Rules REMOVED` for your module.
