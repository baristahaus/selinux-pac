# Production Readiness

> Policy is correct the first time on a box no one runs. Chapter 19 showed the pipeline. This chapter covers what to do when someone actually runs it.

The pipeline end-to-end ends at `semanage permissive -d myapp_t`. This chapter covers what happens after that: the moment the kernel starts denying again, and the question of who takes responsibility when the application does.

Every phase in that pipeline buys a specific piece of evidence. Each phase makes a claim about readiness, and each claim has a limit: what it can prove and what it cannot. This chapter maps those claims to the checklist an operator fills out before the domain flips back to enforcing.

## What "ready" means in four pieces

The readiness check is a tuple of four values, and the gate at `scripts/check_soak_ready.sh` measures three of them directly. The fourth, reversibility, is documented separately.

| Piece | What it answers | Measured by |
|-------|-----------------|-------------|
| **Evidence** | No net-new access need surfaced since canary install | `soak_monitor.yml` net-new count, or raw AVC lines when `sesearch` is unavailable |
| **Verification** | On-disk labels, running systemd units, scheduled jobs that also fire | `verify_file_contexts.sh` dry-run, `systemctl is-active`, `monitor_avc.sh` for `logrotate_t` |
| **Ownership** | Who watches a denial that slips past soak and shows up in production | The on-call admin with `emergency_rollback.yml` signed off, the app team with the deploy report JSON |
| **Reversibility** | How fast the domain can return to permissive after enforce | `emergency_rollback.yml` sets permissive first. `dnf downgrade` follows if `rollback_dnf_version` is set |

The gate at §12 of the production runbook makes all three measurable pieces a single JSON payload from `collect_soak_facts.sh`. A deploy report file at `/var/lib/myapp/selinux_deploy_report.json` carries the same four values as `status`, `endpoints_exercised`, `domain_context_verified`, and the context map. The canary, enforce, and rollback playbooks write that file. The operator reads it before every enforce, not the other way around.

## The phases, each one's claim and each one's limit

The rollout runs through six phases. Each phase proves something. None of them proves everything.

| Phase | What it proves | What it cannot prove |
|-------|----------------|----------------------|
| **1. Per-domain permissive canary** | `myapp_t` is installed, the host stays enforcing, `semanage permissive -l` lists it, and the app stays healthy. | The policy covers every code path that the real traffic will hit. Not yet. |
| **2. Path labeling verification** | `verify_file_contexts.sh` dry-run passes. It reports that no `restorecon` change is pending under the data directory. | Whether a label exists for a code path the application never used. |
| **3. Systemd and cron attestation** | The systemd unit starts as the right domain, and the HTTP health probe succeeds. | Every scheduler that will run the same code later, for example `logrotate_t` or the monitoring agent domain. |
| **4. Daily AVC monitoring** | The net-new count from `soak_monitor.yml` stays zero for a full business cycle, including weekends. | Whether traffic reached the new feature. A feature that never saw traffic still passes the gate on paper. |
| **5. Production canary host groups** | One node in the inventory (`--limit canary`) repeats phases 1–4 with production load. | Blast radius. The first node can differ from the last, and the `production` group is one command away. |
| **6. Emergency rollback** | `emergency_rollback.yml` restores permissive, exports AVCs, and the app responds again. | That re-enforcing after the same cycle takes longer than the first time. This is rehearsal, not proof. |

Each phase is a single command chain on the box. That chain is `ansible-playbook` against the `canary` group on the controller. When the RPM is already installed, the matching shell script does the same job. The operator does not skip a phase. The operator steps through.

## Soak arithmetic

The soak minimum is a function of three values: the calendar, the policy delta, and the traffic you have not seen.

| Duration | What it buys | What shorter one risks |
|----------|--------------|------------------------|
| **7 days** (default `soak_min_days` in `ansible/roles/selinux_pac/defaults/main.yml`) | Captures the weekly cron that runs every Tuesday, logrotate that rotates Friday night, and the cert renewal that wakes the daemon. | The gate treats 0 days as the lab default on `rhel-qa`. The production inventory sets `soak_min_days: 7`, and the enforce role refuses to run when the value is below 7. |
| **14 days** (`--min-days 14`, an operator decision) | Every scheduler in your stack runs at least twice, and a denial in the second cycle cannot hide behind "first boot." | A week is one cycle. If nothing broke in cycle 1, cycle 2 is where the feature that never saw traffic quietly shows up. |
| **Weekend inclusion** | Business-hours-only monitoring can miss jobs that fire Saturday at 3 AM. | One clean week under load, then a broken rollout when the job reruns on Saturday. |

The inventory itself disqualifies the lab default of zero days for production. `ansible/roles/selinux_pac/defaults/main.yml` sets `soak_min_days: 7`, and the enforce role refuses to run until the gate reports `days_elapsed >= 7`. The same script accepts `--auto-tier`. That flag replaces the configured floor with the count from the blast-radius classifier, instead of comparing against it. The count is 1 day for a delta that touches only module-private types. It is 3 for a refpolicy or non-module target, and 7 for an entrypoint or base-type change. Read the direction carefully. Tiering can lower the floor: a medium delta on a host configured for 7 days soaks for 3. The ceiling of the classifier is the same 7 that the defaults already carry, so it can never extend a soak. A longer soak is an explicit `--min-days 14`. If the classifier errors or cannot read its inputs, the script keeps the configured floor and says so.

Why a soak at all, if permissive mode already runs the service without blocking anything? The answer is in the gate itself: `soak_max_net_new: 0` in the same defaults file. A net-new access need against the installed policy is a fail condition, whatever the service appeared to do. The raw AVC count is informational, not a gate. Duplicates from cron fire every night, so a raw-count gate rejects every run.

## Verification steps that are easy to skip and expensive to skip

Three checks show up most often in the failure card. Each one is one command, and each one is expensive to skip.

| Check | Why it matters | What it looks like when it fails |
|-------|----------------|----------------------------------|
| **Path labeling at deploy time**: `verify_file_contexts.sh` dry-run before `systemctl restart` | `semodule -i` installs types. Existing files keep their old contexts. A restart without relabeling lets the service start as `unconfined_t`, while the policy was never applied. | The script prints `Mislabeled paths under <dir> (restorecon would change):` followed by the `restorecon -Rv -n` lines, then `File context verification failed — run restorecon before restarting the service`. |
| **Systemd unit attestation**: `systemctl is-active` plus the HTTP probe, plus the domain context | A mislabeled entrypoint (`init_t`) can pass all HTTP gates with zero AVCs while the custom policy was never applied. `domain_context_verified: true` in the deploy report is the answer. | `/health` returns 200 and no AVC is written, while `ps -eZ \| grep myapp` shows the process in `init_t` or `unconfined_service_t` instead of the manifest's `<app>_t`. Zero AVCs plus a green probe is the signature: an unconfined or mislabeled domain never asks the policy a question. |
| **Daily AVC review across the scheduler domain**: `monitor_avc.sh` for `logrotate_t`, monitoring agents, and `cron_t` | Root crontab runs as `cron_t`. HTTP probes on `shopapi_t` exercise the log path but never exercise `logrotate_t`. Phase 3 of [302-PRODUCTION_READINESS.md](docs/admin/302-PRODUCTION_READINESS.md) §8 requires that scheduler AVCs are captured and extended before enforce. | `net_new_count` > 0 during soak, or `net_new_count = 0` because `ausearch -ts recent` ran for ~10 minutes before logrotate rotated the logs, and the denial dropped into a new file. |

The rule in §5 of the best practices document: `ausearch --input-logs --subject myapp_t` is how the scripts query the audit trail from a cron job or a playbook. `--input-logs` tells `ausearch` to take the log location from `auditd.conf`, instead of relying on stdin or the default path. It is about where the search reads from, not about rotation. `ausearch` walks the rotated files in the log directory either way. The false "zero AVCs" that a long soak can produce comes from a skewed clock, not from rotation. That is why the repo converts the epoch of the marker with `avc_epoch_to_ts` instead of using `-ts recent`.

## Canary groups and blast radius

The inventory layout from §10 is the blast-radius classifier's own input.

```text
inventory.production.yml
├── canary group     → prod-canary-1 only (first)
└── production group → all prod hosts (canary + fleet)
```

The `canary` group is one node. The `production` group is the rest. The first run targets `canary`, and the second run targets `production`. The difference between the two is one `--limit` switch on the controller.

The blast-radius classifier, `scripts/classify_policy_blast_radius.sh`, reads the base `.te`/`.fc` and the candidate. It answers three things that the operator needs. The first is which tier of soak this delta owns: `low`, `medium`, or `high`. The second is how many days that tier requires: `1`, `3`, or `7`. The third is the reason. The reasons include "Only module-private types changed", "Refpolicy interface or non-module type expansion detected", and "Direct allow on base policy type detected". The last two are "Entrypoint permission added" and "Entrypoint or domain transition change detected", the latter for any added `type_transition`, `type_member`, or `role_transition` rule. The fail-closed paths of the classifier have their own strings. The script is gated on the fixture set under `tests/fixtures/blast_radius/`. If you change the tier logic without updating the fixtures and passing `make test-fixtures`, the gate breaks.

With `--auto-tier`, `check_soak_ready.sh` adopts the classified count as the minimum. It does not take the larger of the two. Fail-closed applies to the error paths of the classifier: when it cannot run or cannot read its inputs, the gate keeps the configured floor.

The blast-radius classifier already told you about the change before you run the script. That is the whole point. `allow myapp_t var_t:file write;` names a category type and reads as dangerous. `allow myapp_t myapp_var_lib_t:dir write;` names the dedicated type and reads as safe. The classifier reads the delta between the two.

## The sign-off checklist as a table

The checklist in §13 of the production runbook is the accountability map. Each row names the required evidence and the person who owns it.

| Row | Required evidence | Accountable person |
|-----|-------------------|--------------------|
| Staging soak 7+ days complete | `collect_soak_facts.sh` days_elapsed ≥ `soak_min_days` | Operator |
| Full business cycle is clean | `soak_monitor.yml` net-new count = 0, including weekends | Operator |
| Prod canary host deployed and soaked separately | Same gate on `--limit canary`, marker file exists, app healthy | Operator |
| Path labeling verified after last canary deploy | `verify_file_contexts.sh` `[INFO] File context verification passed for myapp` | Operator |
| Backend unit active, and health and notify probes succeed | HTTP 200 on each manifest endpoint from the canary node | App team |
| PR admin review table signed off | `PULL_REQUEST_TEMPLATE/selinux_policy_review.md` checklist all checked | Admin reviewer |
| Change ticket documents window and rollback owner | `change_ticket` set in `enforce_production.yml`, and `force_enforce` false | Operator |
| Rollback playbook tested or on-call briefed | `emergency_rollback.yml` run on staging or on-call briefed on the steps | Operator |
| Domain still permissive pre-enforce | `semanage permissive -l` lists `myapp_t` on target hosts | Operator |
| `setools-console` installed (sesearch required) | The playbooks fail if it is missing, and `soak_use_net_new: true` needs the search | Operator |

Row 5 holds the attestation from the app team. It is the HTTP probes that pass from the canary host. It is also the same probes that pass under enforcing after the flip. The rest is the sign-off of the operator. Each row is either evidence the gate already produced or evidence the operator produced.

## Failure modes readiness reviews catch

A readiness review does not catch new bugs. It catches assumptions.

| Assumption | What the review catches | How it fails |
|------------|-------------------------|--------------|
| **The allow covers every code path** | Net-new count is zero, but only one code path generated AVCs during soak. | The other path never triggered a denial. That is not a safe policy, it is a quiet one. |
| **The label exists everywhere** | `verify_file_contexts.sh` passes on the build host and fails on the production node. | `/var/log/myapp/data.log` is relabeled `var_log_t` on a host where nobody ran `restorecon`. |
| **The port is reachable** | `semanage port` registers 8888 in `myapp_port_t`, and the canary only ever hits that port. | The fleet hosts use 8899. That port is not in the manifest, so it is not covered. |
| **Soak passed because traffic never reached the feature** | Net-new count = 0, and the deploy report passes, but nobody queried the feature that introduced the new allow in production. | Clean gate, and the new allow sits dormant. |
| **The vendor policy already exists** | The generator refuses JWS, and a custom module is generated anyway. | `jws6_tomcat` is already loaded, so the custom `myapp_t` half-duplicates and overrides the vendor policy. |

The gate does not require zero AVCs. It requires zero net-new. The deploy report does not require every port to have traffic. It requires every declared port to have responded. The blast-radius classifier does not certify a change. It names the tier, and the operator absorbs the risk.
::: why The soak gate is the operator's acceptance of risk
Each phase buys evidence, and each phase has a limit. The policy covers every code path that the real traffic will hit. The label exists on every host where the code will run. The port is reachable. The traffic exercised the new feature. Each of those is a claim that a phase makes about readiness, and each claim has a limit. The operator fills out the checklist before the flip. Each row is either evidence the gate has already produced, or evidence the operator has produced. The deploy report is the checklist, and the accountable person is the row owner.
::::

::: note The honest case where nothing changed

Sometimes the right answer is no policy change at all. The generator refuses JWS, EAP, httpd, named, and postgresql unless you pass `--force "reason"`. In one case the app is unconfined because the vendor RPM is not installed. There `ps -eZ | grep unconfined_java_t` shows the process, and `semodule -l` shows the module loaded. `--tune-report` then prints host commands instead of a `.te`. There the pipeline ends at host tuning. Enforce does not apply. The operator notes this in the change ticket and closes it without generating a module. The same pattern appears in §2.5 of the production runbook. Situation maps to action, and action maps to what the operator does. There `generate` is the only row that generates.

:::

::: try Run the soak gate against the lab

The invocation below is the host-side CLI for the same checks that the enforce role makes. It is the same one documented with pass and fail examples in §12 of the production runbook. The role itself runs `collect_soak_facts.sh` and evaluates its JSON. Both answer the same questions, and `check_soak_ready.sh` is the one you can run by hand. Run it on `rhel-qa`, where the checkout exists, the marker file exists, and the operator controls the clock.

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

Each line is the reading the gate makes of a tuple that the operator must understand before clicking "enforce." The script does not evaluate policy. It evaluates evidence.

:::
## What you can do now

- Run `bash scripts/check_soak_ready.sh --auto-tier --base-policy selinux/myapp.te --candidate-policy policy_out/myapp.te --marker-file /var/lib/myapp/selinux_canary_deployed_at --min-days 7` against the candidate delta and read the `Blast-radius tier:` and `Classifier reason:` lines as the delta's own judgment.
- Rehearse the rollback. `emergency_rollback.yml` is not a safety net. It is the second half of the same plan.
