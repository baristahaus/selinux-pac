# Production Readiness

> Policy is correct the first time on a box no one runs. Chapter 19 showed the pipeline; this chapter covers what to do when someone actually runs it.

The pipeline end-to-end ends at `semanage permissive -d myapp_t`. The thing that happens after that is what this chapter is about — the moment the kernel starts denying again, and the decision who takes responsibility when the application does.

Every phase in that pipeline buys a specific piece of evidence. Each phase has a claim it makes about readiness, and each claim has a limit: what it can prove and what it cannot. This chapter maps those claims to the checklist an operator actually fills out before the domain flips back to enforcing.

## What "ready" means in four pieces

The readiness check is a tuple of four values, and the gate at `scripts/check_soak_ready.sh` measures three of them directly. The fourth — reversibility — is documented separately.

| Piece | What it answers | Measured by |
|-------|-----------------|-------------|
| **Evidence** | No net-new access need surfaced since canary install | `soak_monitor.yml` net-new count, or raw AVC lines when `sesearch` is unavailable |
| **Verification** | On-disk labels, running systemd units, scheduled jobs that also fire | `verify_file_contexts.sh` dry-run, `systemctl is-active`, `monitor_avc.sh` for `logrotate_t` |
| **Ownership** | Who watches a denial that slips past soak and shows up in production | The on-call admin with `emergency_rollback.yml` signed off, the app team with the deploy report JSON |
| **Reversibility** | How fast the domain can return to permissive after enforce | `emergency_rollback.yml` sets permissive first; `dnf downgrade` follows if `rollback_dnf_version` is set |

The gate at §12 of the production runbook makes all three measurable pieces a single JSON payload from `collect_soak_facts.sh`. A deploy report file at `/var/lib/myapp/selinux_deploy_report.json` — written by the canary, enforce, and rollback playbooks — carries the same four values as `status`, `endpoints_exercised`, `domain_context_verified`, and the context map. The operator reads that file before every enforce; not the other way around.

## The phases, each one's claim and each one's limit

The rollout runs through six phases. Each phase proves something; none of them proves everything.

| Phase | What it proves | What it cannot prove |
|-------|----------------|----------------------|
| **1 — Per-domain permissive canary** | `myapp_t` is installed, the host stays enforcing, `semanage permissive -l` lists it, and the app stays healthy. | The policy covers every code path the real traffic will hit — not yet. |
| **2 — Path labeling verification** | `verify_file_contexts.sh` dry-run passes; no `restorecon` would relabel anything under the data directory. | Whether a label exists for a code path the application has never exercised. |
| **3 — Systemd and cron attestation** | The systemd unit starts as the right domain and the HTTP health probe succeeds. | Every scheduler that will run the same code later — `logrotate_t`, the monitoring agent domain. |
| **4 — Daily AVC monitoring** | `soak_monitor.yml` net-new count stays zero for a full business cycle, including weekends. | Traffic never reached the new feature; that feature still passes the gate on paper. |
| **5 — Production canary host groups** | One node in the inventory (`--limit canary`) repeats phases 1–4 with production load. | Blast radius: the first node may differ from the last. The `production` group is one command away. |
| **6 — Emergency rollback** | `emergency_rollback.yml` restores permissive, exports AVCs, and the app responds again. | Re-enforcing after the same cycle takes longer than the first time; this is rehearsal, not proof. |

Each phase is a single command chain on the box — `ansible-playbook` against the `canary` group on the controller, or the matching shell script when the RPM is already installed. The operator does not skip a phase; they step through.

## Soak arithmetic

The soak minimum is a function of three values: the calendar, the policy delta, and the traffic you have not seen.

| Duration | What it buys | What shorter one risks |
|----------|--------------|------------------------|
| **7 days** (default `soak_min_days` in `ansible/roles/selinux_pac/defaults/main.yml`) | Captures the weekly cron that runs every Tuesday, logrotate that rotates Friday night, cert renewal that wakes the daemon. | The gate treats 0 days as the lab default on `rhel-qa`; production inventory sets `soak_min_days: 7`, and the enforce role refuses to run when the value is below 7. |
| **14 days** (`--min-days 14`, an operator decision) | Every scheduler in your stack has run at least twice, and a denial in the second cycle would not hide behind "first boot." | A week is one cycle; if nothing broke in cycle 1, cycle 2 is where the feature that never saw traffic quietly shows up. |
| **Weekend inclusion** | Business-hours-only monitoring can miss jobs that fire Saturday at 3 AM. | One clean week under load, a broken rollout when the job reruns on Saturday. |

The lab default of zero days is disqualified for production by the inventory itself — `ansible/roles/selinux_pac/defaults/main.yml` sets `soak_min_days: 7` and the enforce role refuses to run until the gate reports `days_elapsed >= 7`. The same script accepts `--auto-tier`, which **replaces** the configured floor with the blast-radius classifier's count instead of comparing against it: 1 day for a delta that touches only module-private types, 3 for a refpolicy or non-module target, 7 for an entrypoint or base-type change. Read the direction carefully — tiering can *lower* the floor (a medium delta on a host configured for 7 days soaks for 3), and the classifier's ceiling is the same 7 the defaults already carry, so it can never extend a soak. A longer soak is an explicit `--min-days 14`. When the classifier errors or cannot read its inputs, the script keeps the configured floor and says so.

Why a soak at all then, if permissive mode already runs the service without blocking anything? The answer is in the gate itself: `soak_max_net_new: 0` in the same defaults file — a net-new access need against installed policy is a fail condition regardless of whether the service appeared healthy. The raw AVC count is informational; duplicates from cron that fire every night would have rejected the gate before net-new was invented.

## Verification steps that are easy to skip and expensive to skip

Three checks show up most often in the failure card — each one is one command, each one is expensive if you skip it.

| Check | Why it matters | What it looks like when it fails |
|-------|----------------|----------------------------------|
| **Path labeling at deploy time** — `verify_file_contexts.sh` dry-run before `systemctl restart` | `semodule -i` installs types; existing files keep their old contexts. Restart without relabeling lets the service start as `unconfined_t` while the policy was never actually applied. | The script prints `Mislabeled paths under <dir> (restorecon would change):` followed by the `restorecon -Rv -n` lines, then `File context verification failed — run restorecon before restarting the service`. |
| **Systemd unit attestation** — `systemctl is-active` plus HTTP probe, plus domain context | A mislabeled entrypoint (`init_t`) can pass all HTTP gates with zero AVCs while the custom policy was never applied. `domain_context_verified: true` in the deploy report is the answer. | `/health` returns 200 and no AVC is written, while `ps -eZ \| grep myapp` shows the process in `init_t` or `unconfined_service_t` instead of the manifest's `<app>_t`. Zero AVCs plus a green probe is the signature: an unconfined or mislabeled domain never asks the policy a question. |
| **Daily AVC review across the scheduler domain** — `monitor_avc.sh` for `logrotate_t`, monitoring agents, `cron_t` | Root crontab runs as `cron_t`; HTTP probes on `shopapi_t` exercise the log path but never exercise `logrotate_t`. Phase 3 of [302-PRODUCTION_READINESS.md](docs/admin/302-PRODUCTION_READINESS.md) §8 requires that scheduler AVCs are captured and extended before enforce. | `net_new_count` > 0 during soak, or `net_new_count = 0` because `ausearch -ts recent` ran for ~10 minutes before logrotate rotated the logs, and the denial dropped into a new file. |

The rule in §5 of the best practices document: `ausearch --input-logs --subject myapp_t` is how the scripts query the audit trail from a cron job or a playbook. `--input-logs` tells `ausearch` to take the log location from `auditd.conf` instead of relying on stdin or the default path — it is about *where* the search reads from, not about rotation; `ausearch` walks the rotated files in the log directory either way. The false "zero AVCs" that a long soak can produce comes from a skewed clock, not from rotation, which is why the repo converts the marker's epoch with `avc_epoch_to_ts` rather than using `-ts recent`.

## Canary groups and blast radius

The inventory layout from §10 is the blast-radius classifier's own input.

```text
inventory.production.yml
├── canary group     → prod-canary-1 only (first)
└── production group → all prod hosts (canary + fleet)
```

The `canary` group is one node. The `production` group is the rest. The first run targets `canary`; the second run targets `production`. The difference between the two is one `--limit` switch on the controller.

The blast-radius classifier, `scripts/classify_policy_blast_radius.sh`, reads the base `.te`/`.fc` and the candidate, and answers three things the operator needs: which tier of soak this delta owns (`low`, `medium`, or `high`), how many days that tier requires (`1`, `3`, `7`), and the reason — including "Only module-private types changed", "Refpolicy interface or non-module type expansion detected", "Direct allow on base policy type detected", "Entrypoint permission added", and "Entrypoint or domain transition change detected" for any added `type_transition`, `type_member`, or `role_transition` rule (the classifier's fail-closed paths have their own strings). The script is gated on the fixture set under `tests/fixtures/blast_radius/`; changing tier logic without updating fixtures and passing `make test-fixtures` breaks the gate.

With `--auto-tier`, `check_soak_ready.sh` adopts the classified count as the minimum — it does not take the larger of the two. Fail-closed applies to the classifier's error paths: when it cannot run or cannot read its inputs, the gate keeps the configured floor.

The blast radius classifier already told you about the change before you run the script — that is the whole point. `allow myapp_t var_t:file write;` names a category type and is legible as dangerous. `allow myapp_t myapp_var_lib_t:dir write;` names the dedicated type and is legible as safe. The classifier reads the delta between the two.

## The sign-off checklist as a table

The checklist in §13 of the production runbook is the accountability map. Each row names the required evidence and the person who owns it.

| Row | Required evidence | Accountable person |
|-----|-------------------|--------------------|
| Staging soak 7+ days complete | `collect_soak_facts.sh` days_elapsed ≥ `soak_min_days` | Operator |
| Full business cycle is clean | `soak_monitor.yml` net-new count = 0, including weekends | Operator |
| Prod canary host deployed and soaked separately | Same gate on `--limit canary`, marker file exists, app healthy | Operator |
| Path labeling verified after last canary deploy | `verify_file_contexts.sh` `[INFO] File context verification passed for myapp` | Operator |
| Backend unit active; health and notify probes succeed | HTTP 200 on each manifest endpoint from the canary node | App team |
| PR admin review table signed off | `PULL_REQUEST_TEMPLATE/selinux_policy_review.md` checklist all checked | Admin reviewer |
| Change ticket documents window and rollback owner | `change_ticket` set in `enforce_production.yml`; `force_enforce` false | Operator |
| Rollback playbook tested or on-call briefed | `emergency_rollback.yml` run on staging or on-call briefed on the steps | Operator |
| Domain still permissive pre-enforce | `semanage permissive -l` lists `myapp_t` on target hosts | Operator |
| `setools-console` installed (sesearch required) | Playbooks fail if missing; `soak_use_net_new: true` needs the search | Operator |

The app team's attestation is in row 5: HTTP probes that pass from the canary host, and the same probes passing under enforcing after the flip. The operator's sign-off is the rest — each row is either evidence the gate has already produced, or evidence the operator has produced.

## Failure modes readiness reviews catch

A readiness review does not catch new bugs; it catches assumptions.

| Assumption | What the review catches | How it fails |
|------------|-------------------------|--------------|
| **The allow covers every code path** | Net-new count is zero, but only one code path generated AVCs during soak. | The other path never triggered a denial — not a safe policy, a quiet one. |
| **The label exists everywhere** | `verify_file_contexts.sh` passes on the build host, fails on the production node. | `/var/log/myapp/data.log` is relabeled `var_log_t` on a host where `restorecon` was never run. |
| **The port is reachable** | `semanage port` registers 8888 in `myapp_port_t`; the canary only ever hits that port. | Fleet hosts use 8899; not in the manifest; not covered. |
| **Soak passed because traffic never reached the feature** | Net-new count = 0; deploy report pass; but the feature that introduced the new allow was never queried in production. | Clean gate; the new allow sits dormant. |
| **The vendor policy already exists** | Generator refuses JWS; custom module generated anyway. | `jws6_tomcat` already loaded; custom `myapp_t` half-duplicates and overrides vendor policy. |

The gate does not require zero AVCs — it requires zero net-new. The deploy report does not require every port to have traffic — it requires every declared port to have responded. The blast-radius classifier does not certify a change; it names the tier and the operator absorbs the risk.
:::: why The soak gate is the operator's acceptance of risk
Each phase buys evidence; each phase has a limit. The policy covers every code path the real traffic will hit, the label exists on every host the code will run, the port is reachable, the traffic exercised the new feature — each of those is a claim each phase makes about readiness, and each claim has a limit. The operator fills out the checklist before the flip, and each row is either evidence the gate has already produced, or evidence the operator has produced. The deploy report is the checklist, and the accountable person is the row owner.
::::

::: note The honest case where nothing changed

Sometimes the right answer is no policy change at all. The generator refuses JWS, EAP, httpd, named, and postgresql unless you pass `--force "reason"`. When the app is unconfined because the vendor RPM was not installed — `ps -eZ | grep unconfined_java_t` shows the process, `semodule -l` shows the module loaded, and `--tune-report` prints host commands instead of a `.te` — the pipeline ends at host tuning. Enforce does not apply. The operator notes this in the change ticket and closes it without generating a module. The same pattern appears in §2.5 of the production runbook: situation maps to action, action maps to what the operator does, and `generate` is the only row that actually generates.

:::

::: try Run the soak gate against the lab

The invocation below is the host-side CLI for the same checks the enforce role makes — and the same one documented with pass/fail examples in §12 of the production runbook. The role itself runs `collect_soak_facts.sh` and evaluates its JSON; the two answer the same questions, and `check_soak_ready.sh` is the one you can run by hand. Run it on `rhel-qa`, where the checkout exists, the marker file exists, and the operator controls the clock.

```bash
cd /home/<user>/selinux-pac

bash scripts/check_soak_ready.sh \
  --domain myapp_t \
  --marker-file /var/lib/myapp/selinux_canary_deployed_at
```

The expected output, each line:

```text
[INFO] Soak: 8 day(s) elapsed (minimum 7)
[INFO] Events since canary deploy for myapp_t: 0 (maximum 0)
[INFO] Soak gate passed — safe to enforce myapp_t
```

A fail case looks like this:

```text
[ERROR] Soak period not met — wait 6 more day(s) or use force_enforce=true (break-glass only)
```

A pass with tiered minimum looks like this:

```text
[INFO] Blast-radius tier: high → minimum soak 7 day(s)
[INFO] Classifier reason: Direct allow on base policy type detected
[INFO] Soak: 7 day(s) elapsed (minimum 7)
[INFO] Events since canary deploy for myapp_t: 0 (maximum 0)
[INFO] Soak gate passed — safe to enforce myapp_t
```

Each line is the gate's reading of a tuple the operator should understand before clicking "enforce." The script does not evaluate policy; it evaluates evidence.

:::
## What you can do now

- Run `bash scripts/check_soak_ready.sh --auto-tier --base-policy selinux/myapp.te --candidate-policy policy_out/myapp.te --marker-file /var/lib/myapp/selinux_canary_deployed_at --min-days 7` against the candidate delta and read the `Blast-radius tier:` and `Classifier reason:` lines as the delta's own judgment.
- Rehearse the rollback. `emergency_rollback.yml` is not a safety net — it is the second half of the same plan.
