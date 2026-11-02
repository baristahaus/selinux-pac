# 303 — Testing

This is the testing guide. Older notes called the same page 204, then 205.

This document is the **single reference** for how this repository tests SELinux policy — from developer laptop checks through production enforce gates.

| You are… | Start here | Then |
|----------|------------|------|
| **App developer** | §1 Integration endpoints | §1.5 App manifest, §2 Local smoke tests |
| **Policy author opening a PR** | §4 CI on pull requests | §5 Shell gate scripts |
| **Admin / SRE** | §6 Staging and production gates | [`302-TECHNICAL.md`](302-TECHNICAL.md), [`401-OPERATIONS.md`](../shipping.md) |

Related: concepts in **[101](101-CONCEPTS.md)**; commands in **[102](102-COMMANDS.md)**; the hand-built lab in **[104](104-HAND-BUILT-MODULE.md)**; the customer talk in **[301](../demo.md)**; tool commands in **[201](201-TOOL-COMMANDS.md)**. **Catalog:** [`README.md`](README.md). The soak gate fails closed when `sesearch` is missing ([201](201-TOOL-COMMANDS.md#scriptsmonitor_avcsh)).

**Convention:** **Repo root** = directory with `Makefile` and `scripts/`. Offline `make check` uses deterministic goldens (`selinux/myapp/myapp.te`, `config/myapp.manifest.yml`) plus shopapi/payments modules. Live probes run on **RHEL** against **shopapi** ([302-TECHNICAL.md](302-TECHNICAL.md)).

---

## 1. Integration endpoints (shopapi)

Spring Boot **shopapi** exposes first-ship HTTP probes on port **8091**. Each path is a SELinux surface. They are exercised by:

- [`scripts/wait_for_endpoints.sh`](../../scripts/wait_for_endpoints.sh) (canary, enforce, rollback — batch readiness, no AVC narration)
- [`lab/demo_present.sh`](../../lab/demo_present.sh) / [`lab/demo_bootstrap.sh`](../../lab/demo_bootstrap.sh) on RHEL
- Manifest `http.endpoints` in [`config/shopapi.manifest.yml`](../../config/shopapi.manifest.yml)

Do **not** curl `/feature-spool` during first-ship. That path is the outage beat after enforce.

| Endpoint | SELinux surface | Primary types / rules | Typical failure without policy |
|----------|-----------------|----------------------|--------------------------------|
| `GET /health` | TCP bind + listen on **8091** | `shopapi_port_t`, `init_daemon_domain` | `name_bind` denial on port |
| `GET /state` | Write under **`/var/lib/shopapi`** | `shopapi_var_lib_t` | write to `var_lib_t` / missing `search` |
| `GET /log` | Append under **`/var/log/shopapi`** | `shopapi_log_t` | write to `var_log_t` |

**Design constraints:**

- Dedicated port type (`shopapi_port_t`), not blanket `unreserved_port_t`.
- systemd starts `/opt/shopapi/bin/shopapi` (`shopapi_exec_t`). There is no `SELinuxContext=` line.
- Offline generator tests use committed **`selinux/myapp/myapp.te`** / **`config/myapp.manifest.yml`** — that module is not a live app.

**Manual run (RHEL host after `make demo-bootstrap`):**

```bash
for path in /health /state /log; do
  echo "=== GET $path ==="
  curl -sf "http://127.0.0.1:8091${path}" | head -c 120
  echo
done

# On rhel-qa: the generator exports AVCs from audit.log
# bash scripts/dev_generate_policy.sh --apply --app-name shopapi
```

---

## 1.5 App manifest (onboarding new apps)

`config/myapp.manifest.yml` is the **offline generator fixture**. For a new application, copy [`config/payments.manifest.example.yml`](../../config/payments.manifest.example.yml) to `config/<app_name>.manifest.yml` and declare paths, systemd units, HTTP probes, and SELinux domains. See [`docs/sepac.md`](../sepac.md) for the full schema.

**Validate locally / in CI:**

```bash
bash scripts/validate_app_manifest.sh config/myapp.manifest.yml
python3 scripts/lib/app_manifest.py shell-export config/myapp.manifest.yml
```

**Consumers:** `wait_for_endpoints.sh`, `post_deploy_report.sh`, and `check_soak_ready.sh` accept `--manifest PATH` (or `APP_MANIFEST`). Ansible passes `app_manifest_path` from inventory. When no manifest file is present, `wait_for_endpoints.sh` falls back to shopapi first-ship paths (`/health` `/state` `/log` on :8091).

**Production model:** canary smoke is `http.endpoints` in the manifest, curled by `wait_for_endpoints.sh`. There is no `integration_tests.command`. Do not auto-generate business-logic tests from policy.

---

## 1.6 One command: `make check`

| | |
|--|--|
| **Where** | **Repo root** on your laptop or CI — macOS is fine |
| **Why** | Same offline suite the `offline-tests` job runs, plus linters |

`make deps` creates `.venv` and installs into it, so a host that blocks system pip still works. `make test` depends on that venv, then runs deterministic fixtures, blast-radius fixtures, tune-report fixtures, the static validators (forbidden patterns for `myapp`, `shopapi`, and `payments`, version, RPM parity, manifests), and `tests/smoke_test.py`. `make check` is `make test` plus `make lint` (linters skip when they are not installed). No SELinux host is required.

```bash
make check
make test
make help
```

---

## 2. `tests/smoke_test.py` (`make test-smoke`)

Runs offline — **no SELinux required** for most tests. The `offline-tests` job runs this file as part of `make test` on every pull request.

```bash
make test-smoke
# or:
python3 tests/smoke_test.py
```

| Test name | What it verifies |
|-----------|------------------|
| `avc_parsing` | `parse_avc_line`, dedup, domain filter |
| `perm_merge` | Duplicate AVC lines merge permissions on same src/tgt/class |
| `type_extraction_dedup` | `system_r` vs `object_r` in scontext normalize to same type |
| `subtract_existing` | Net-new detection skips permissions already in `.te` |
| `net_new_detection` | Partial overlap — only missing perms flagged net-new |
| `preprocess_stats` | Raw vs merged AVC counts |
| `structured_summary_sections` | Summary contains Net-new / Already covered sections |
| `pr_summary_headings` | `pr_summary` requires the four section headings |
| `version_bump` | SemVer bump in `policy_version.txt` |
| `version_consistency` | `validate_version_consistency.sh` passes on committed `selinux/` |
| `classify_fail_closed_json` | Corrupt blast-radius input → JSON with `fail_closed: true` |
| `assemble_pr_body` | `assemble_pr_body.sh` fills PR template (`--skip-policy-diff` in CI smoke) |
| `verify_file_contexts_skip` | `--skip-if-unavailable` exits 0 without SELinux tools |
| `check_soak_ready_gate` | Soak script fails on missing/recent marker, passes on 8-day-old marker |
| `monitor_avc_skip` | `monitor_avc.sh --skip-if-unavailable` exits 0 |
| `vendor_policy_check` | Mocked `semodule`/`rpm`/`dnf`: loaded module refuses, available-not-installed refuses, custom app proceeds; `--force "reason"` required; missing-tools skip |
| `tune_report` | Tomcat fixture: `--tune-report` emits fcontext and semanage port commands and no `.te` |
| `tune_report_skip_no_selinux` | `--tune-report` with no SELinux tools prints a skip notice and exits 0 |
| `force_reason_recorded` | `--force` reason appears in `findings.json`, `pr_summary.md`, and the PR body banner |
| `demo_present_dry_run` | `--dry-run --profile customer` prints the three-app narration; `--help` names `demo_e2e_mac.sh`; Act 2 proof commands (`git status --short selinux/`, `semodule -l`) |
| `demo_present_preflight_names_bootstrap` | `--preflight` without `--dry-run` names `make demo-bootstrap` when App A is absent; dry-run preflight names App B un-tune commands |
| `demo_e2e_scripts_dry_run` | Mac/QA/prod `--dry-run` / Darwin refuse; Mac `--help` names `demo_present.sh`; reset dry-run names App B un-tune |
| `e2e_quiet_ssh_wrap_skips_when_ssh_missing` | `e2e_install_quiet_ssh` no-ops when `ssh`/`scp` are missing or `E2E_DRY=1` |
| `app_manifest` | Validates demo + example manifests; `shell-export` emits expected keys |
| `rpm_ops_parity` | Ops RPM file list matches repo scripts |
| `ops_rpm_soak_cli_imports_alone` | `pac_cli.list` copied alone runs `soak_net_new.py --help` |
| `monitor_records_soak_stderr` | A failed soak check records that command's stderr |
| `soak_counts_every_domain_denial` | Domain denials outside the manifest paths still count |
| `soak_ignore_is_explicit` | `soak.ignore` is the only drop list, and the day JSON records it |
| `offline_fixture_sync` | Offline demo `offline/generated/` matches committed `selinux/` |
| `tracked_tree_has_no_model_client` | Tracked files do not name a removed model client |
| `deterministic_verdict_fixture_coverage` | Every classification verdict has ≥1 golden row under `tests/fixtures/deterministic/` |
| `needs_review_hits` | `execmem` / `dac_override` / foreign `process transition` match `NEEDS_REVIEW_RULES`; in-module transition does not |
| `deterministic_fixture_classify` | Each fixture: `--explain` + generation vs `expected.json`; optional `sepolgen_mock.json` |
| `fc_labeling_drift_detection` | `fc_labeling.py` redundant `.fc` line detection |

## 3. Developer local checks (before PR)

| Step | Command | Needs SELinux host? |
|------|---------|---------------------|
| CLI + smoke | `python3 tests/smoke_test.py` | No |
| Forbidden patterns | `bash scripts/validate_forbidden_patterns.sh selinux` | No |
| Compile | `bash scripts/compile_and_validate.sh selinux` | Yes — `selinux-policy-devel` on **rhel-qa** |
| Semantic assertions | `bash scripts/validate_policy_semantics.sh selinux` | Yes — rhel-qa |
| Staging + AVC export | `make demo-bootstrap` + curl shopapi `/health` `/state` `/log` | Yes (RHEL **qa**) |
| Deterministic generate | `bash scripts/dev_generate_policy.sh --apply --app-name shopapi` | Yes (RHEL **qa**) |
| **Enforce-check** | `bash scripts/dev_generate_policy.sh --apply --enforce-check --app-name shopapi` | Yes (root on RHEL **qa**) |

**`--enforce-check`** compiles the candidate `.pp`, removes permissive on the manifest domain, runs `restorecon` on the manifest paths, restarts the manifest units, runs `wait_for_endpoints.sh` (including domain-context verification), and prints recent AVCs on failure.

### 3.1 Compile on RHEL

Policy compile needs `selinux-policy-devel` (`/usr/share/selinux/devel/Makefile`). Run `bash scripts/compile_and_validate.sh selinux` on **rhel-qa**. That script also runs `validate_forbidden_patterns.sh` before compile.

## 4. CI on pull requests

For a **shareable deep dive** on the four PR jobs, the 113 smoke tests, 15 compiled bypass fixtures, and 10 generator verdicts, see **[304 — CI and test gates](304-CI-AND-TEST-GATES.md)**.

Workflow: [`.github/workflows/selinux-policy-ci.yml`](../../.github/workflows/selinux-policy-ci.yml)

The generator already ran the same forbidden-pattern check, so these jobs are expected to **pass**. They are the admin review gate, not a fail-on-purpose demo step.

| Job name | What it runs | Pass criteria |
|-----------|----------------|----------------|
| `offline-tests` | `make test` | Deterministic fixtures, blast-radius fixtures, tune-report fixtures, smoke tests, and the static validators |
| `forbidden-patterns` | `validate_forbidden_patterns.sh` on `selinux`, `selinux/shopapi`, and `selinux/payments`, then `cli/policy_audit.py` | No wildcards, no forbidden target types, no raw `bin_t` execute. `corecmd_exec_bin`, `java_exec`, or `can_exec` on `bin_t` only with `selinux_exceptions.exec_bin` in the manifest |
| `compiled-policy` | `validate_policy_semantics.sh` for `myapp`, `shopapi`, and `payments` on Stream 9, or on the `rhel9-utm` runner when `RUNNER` is set | Compiled allows match the house rules, including no `entrypoint` on a type the module does not declare, and no execute on `bin_t` (however it was written) without `selinux_exceptions.exec_bin` |
| `version-consistency` | `scripts/validate_version_consistency.sh` | `policy_version.txt` matches `policy_module()` |

Those four names are stable so branch protection can require them. `make check` on a laptop is `make test` plus linters. The Stream 9 job is the compile. A laptop without `selinux-policy-devel` does not compile.

Repo variable `RUNNER` defaults to unset, which is `ubuntu-latest` plus the Stream 9 image for the SELinux jobs (`compiled-policy`, `app-compiled-policy`, `bypass-rejected`, and `shopapi-policy-compile`). Set `RUNNER` to `rhel9-utm` to run those jobs directly on that runner.

Register the runner on a dedicated **rhel-ci** VM. Do not register it on rhel-qa or rhel-prod. On that VM, install the GitHub Actions runner as user `github-runner`, and give it the label `rhel9-utm`. The job uses `sudo` for `dnf` and for the root-only scripts (`validate_policy_semantics.sh` and `reject_compiled_bypasses.sh`). Add this exact sudoers entry:

```
github-runner ALL=(ALL) NOPASSWD: /usr/bin/dnf, /usr/bin/bash
```

Then set the repository variable `RUNNER` to `rhel9-utm`. That value selects no container. Any other value, including unset, keeps `quay.io/centos/centos:stream9`.

A public repository that uses a self-hosted runner must require approval before workflows from outside collaborators run, or the repository must be private. A pull request from a fork can otherwise run code on the VM.

`make vm-check` is the same compile list on the QA VM, not on the runner. Copy `lab/lab.env.example` to `lab/lab.env`, set `QA_HOST`, `PROD_HOST`, and `SSH_USER`, then run `make vm-check`. It syncs the checkout and prints one PASS or FAIL line per check. The last line is `host-unchanged`: `semodule -l` must not list `bypass_*` or `pac_control`.

Compiled `selinux/myapp/myapp.pp` is **not** committed to Git.

---

## 5. Shell gate scripts (staging / production)

These run on **SELinux hosts** (Ansible playbooks call them; admins can run manually). On production the copy is `/usr/libexec/selinux-policy-ops/`, not a git `scripts/` tree. The links below are the sources in this repo.

| Script | When | Pass criteria |
|--------|------|---------------|
| [`verify_file_contexts.sh`](../../scripts/verify_file_contexts.sh) | Before service restart after `semodule -i` | `matchpathcon -V`; `restorecon -Rv -n` shows no changes under data/log paths |
| [`wait_for_endpoints.sh`](../../scripts/wait_for_endpoints.sh) | After canary / enforce / rollback restart | systemd active; **MainPID domain** matches manifest; HTTP probes from manifest (demo: shopapi `/health` `/state` `/log` on :8091) |
| [`monitor_avc.sh`](../../scripts/monitor_avc.sh) | Daily during soak (`soak_monitor.yml`); canary post-deploy window | **Net-new** access needs ≤ `soak_max_net_new` (default **0**); raw count informational unless `sesearch` missing |
| [`check_soak_ready.sh`](../../scripts/check_soak_ready.sh) | Manual pre-enforce on host (Ansible: **`collect_soak_facts.sh`** / **`soak_status.yml`**) | Marker age ≥ min days; net-new or AVC count ≤ max; deploy report pass + **domain_context_verified**. Optional **`--auto-tier --base-policy PATH --candidate-policy PATH`** sets min days from blast-radius classifier (fail-closed → `soak_min_days`) |
| [`cli/soak_net_new.py`](../../cli/soak_net_new.py) | Soak exception JSON vs **installed** policy | `sesearch --allow`; `net_new_count` + `exceptions[]`; `fail_closed` without toolchain |
| [`post_deploy_report.sh`](../../scripts/post_deploy_report.sh) | End of canary / enforce / rollback | Writes deploy report JSON (path from manifest or default) |
| [`validate_app_manifest.sh`](../../scripts/validate_app_manifest.sh) | CI / onboarding | YAML schema + required fields |
| [`classify_policy_blast_radius.sh`](../../scripts/classify_policy_blast_radius.sh) | Controller soak tier recommendation | sesearch rule diff between installed modules → 1 / 3 / 7 days; **`run_blast_radius_fixtures.sh`** (`make test-fixtures`) |
| [`validate_version_consistency.sh`](../../scripts/validate_version_consistency.sh) | CI / local | SemVer SSOT across `.te`, `policy_version.txt`, RPM spec |
| [`assemble_pr_body.sh`](../../scripts/assemble_pr_body.sh) | Before opening PR | Fills PR template + merge-base policy access delta (`policy_module_diff.sh`) |

**Exit codes for `wait_for_endpoints.sh`:** `0` pass; `1` systemd; `2` HTTP; `4` domain mismatch.

---

## 6. Staging and production gates

Production control plane is **Ansible Automation Platform (AAP)** ([401-OPERATIONS.md](../shipping.md)). The three-app customer talk is [301-CUSTOMER.md](../demo.md); the two-host pipeline ([302-TECHNICAL.md](302-TECHNICAL.md)) runs the same playbooks from the Mac.

| Phase | Playbook | Key tests embedded |
|-------|----------|-------------------|
| Canary | `deploy_canary.yml` | `verify_file_contexts`, `wait_for_endpoints`, `monitor_avc` (recent window), deploy report |
| Soak | `soak_monitor.yml` / `soak_status.yml` | Daily net-new vs installed policy; read-only facts before enforce. Talk: first-ship URLs only — **clean** AVC file, then treat soak as complete |
| Enforce | `enforce_production.yml` | `collect_soak_facts.sh` (`avc_net_new_count` when `soak_use_net_new`), `semodule -B`, enforce domain, `wait_for_endpoints`, deploy report |
| Outage | shopapi `GET /feature-spool` on **:8091** under enforcing | HTTP 500 + AVC export (writes `/var/spool/shopapi/feature.log`; not in first-ship wait_for_endpoints) |
| Rollback | `emergency_rollback.yml` | permissive relief, `wait_for_endpoints`, deploy report, AVC export |

Full Ansible task order and variables: [`ansible/README.md`](../../ansible/README.md).

Admin runbook with pass/fail examples: [`401-OPERATIONS.md`](../shipping.md#soak).

---

## 7. Test layer summary

```text
Layer 1  offline-tests + forbidden-patterns + compiled-policy + version-consistency    every PR
Layer 2  make check on a laptop (make test plus linters)
Layer 3  integration probes + policy_out/avc.log      staging discovery (permissive)
Layer 4  deploy_canary + wait_for_endpoints           staging/prod canary host
Layer 5  soak_monitor + soak_status                   soak period (net-new; talk shows clean first-ship)
Layer 6  enforce_production + wait_for_endpoints      production cutover
Layer 7  emergency_rollback                           outage response
```

---

## 8. What is *not* tested automatically

| Gap | Mitigation |
|-----|------------|
| Real **logrotate** cron as `logrotate_t` | Run system logrotate on staging during soak against the app log dir from the manifest |
| **RPM upgrade** relabel path | Test `packaging/myapp-selinux.spec` on a throwaway VM |
| Fleet-wide **serial enforce** | `enforce_production.yml` uses `serial: 1` — test on canary host first |
| AVC **classification** under `semodule -DB` (noise vs real) | Manual review; optional **`check_soak_ready.sh --auto-tier`** on controller with policy pair paths |

---

## 9. Deterministic generator (offline)

| Check | Command |
|-------|---------|
| House-rule golden fixtures | `make test-fixtures` or `make test` |
| Explain a denial log | `python3 cli/deterministic_gen.py --explain …` — [201 — Generate a module](201-TOOL-COMMANDS.md#generate-a-module) |
| Full dev path | `bash scripts/dev_generate_policy.sh --skip-export` — [201 — Generate a module](201-TOOL-COMMANDS.md#generate-a-module) |
| Coverage gate | `bash scripts/verify_avc_coverage.sh` after generation |
