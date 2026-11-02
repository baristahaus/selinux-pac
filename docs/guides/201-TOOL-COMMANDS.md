# 201 — Tool commands

> Admins use `sepac`: see [sepac.md](../sepac.md). This page documents the engine scripts and playbooks sepac runs.

[104](104-HAND-BUILT-MODULE.md) typed each SELinux command. This page is the script or playbook that runs those commands, in order. Inputs and outputs are the files the script reads and writes. "Replaces" names the 104 step numbers.

The soak gate fails closed when `sesearch` is missing. `cli/soak_net_new.py` sets `fail_closed` when it cannot read the policy. `scripts/monitor_avc.sh` then sets `avc_fail_closed` and status fail. A missing `sesearch` is not a count of zero.

## Ansible module to command

| Ansible module | Command it runs |
|----------------|-----------------|
| `community.general.seport` | `semanage port` (the canary in this repo shells `semanage port -l` and `semanage port -a` itself) |
| `community.general.selinux_permissive` | `semanage permissive -a` or `-d` |
| `ansible.posix.seboolean` | `setsebool -P` |

---

## Generate a module

## scripts/dev_generate_policy.sh

**Replaces** 104 steps 3.1 and 6.1 (the allow and the file-context line you would have typed). It does not replace `semodule -i` unless you pass `--enforce-check`.

**Inputs.** `config/<app>.manifest.yml`, the audit log or `policy_out/avc.log` with `--skip-export`, `selinux/<app>/`.

**Outputs.** `policy_out/<app>.te`, `.fc`, `findings.json`, `pr_summary.md`. `--apply` copies the `.te`, `.fc`, and `policy_version.txt` into `selinux/<app>/`.

**Commands, in order.**

1. Vendor check: `semodule -l` and `rpm -q`. A loaded vendor module stops the generate. `--tune-report` writes `policy_out/tune_report.md` and no `.te`.
2. Export: `ausearch` through `scripts/lib/avc_query.sh`, kept when the record epoch is at or after the reset marker. Writes `policy_out/avc.log`.
3. `python3 cli/deterministic_gen.py` with the manifest, the existing `.te` and `.fc`, and `--bump-version`.
4. `scripts/validate_forbidden_patterns.sh` on the output.
5. `scripts/compile_and_validate.sh`, which runs the forbidden-pattern check again and then `make -f /usr/share/selinux/devel/Makefile`.
6. `--apply` copies the three files into `selinux/<app>/`.
7. `--enforce-check` runs `semodule -i` on the practice host, then `restorecon -Rv` on the manifest paths, then restarts the manifest units. That is 104 steps 3.2–3.4 and 6.2–6.3. Production does not use this flag.

`--allow-needs-review` is what writes `execmem` after the log showed it. Bare `--force` is rejected. `--force "reason"` is the only bypass of a vendor hit, and the reason lands in the PR.

| Verdict | Meaning |
|---------|---------|
| `fc_fix` | Path is in the manifest and not in `.fc` yet |
| `fc_drift` | `.fc` already covers the path. `restorecon` only |
| `private_port` | `name_bind` on a shared port type. Use the app port type |
| `boolean` | `setsebool -P`, not a new allow |
| `interface` | A refpolicy macro matched |
| `direct` | A module-private type, or no macro fit |
| `baseline` | Already allowed. Not written again |
| `needs_review` | `execmem`, `dac_override`. Blocked unless `--allow-needs-review`. Executing `bin_t` (the system JVM) is unlocked only by `selinux_exceptions.exec_bin` in the manifest |
| `forbidden` | `shadow_t` and the patterns CI rejects |
| `toolchain_required` | Interface matching is not installed |

## scripts/compile_and_validate.sh

**Replaces** 104 steps 3.2 and 6.2.

**Inputs.** A directory with `<module>.te` and `<module>.fc`. Pass `--app NAME`.

**Outputs.** `<module>.pp` in that directory. The line `Built …/<module>.pp`.

**Commands.** `validate_forbidden_patterns.sh`, then `make -C <work> -f /usr/share/selinux/devel/Makefile <module>.pp` via `scripts/lib/compile_policy.sh`.

## scripts/validate_forbidden_patterns.sh

**Replaces** nothing in 104. It is the check the hand lab asks you to do by reading the `.te`.

**Inputs.** A policy directory. **Outputs.** Exit 0, or exit 1 naming the pattern. No SELinux command.

## scripts/validate_policy_semantics.sh

**Replaces** nothing in 104. CI after compile.

**Commands.** Builds a types-only control module, `semodule -i` into an isolated store, then `sesearch` and `seinfo` (no `--direct`; setools 4.4.4 does not have it). Attribute grants the direct search misses are rejected. A clean types-only module is accepted.

## scripts/reject_compiled_bypasses.sh

**Replaces** nothing in 104. Runs the semantics gate on each fixture. The clean fixture must exit 0. Each bypass must be rejected with its expected message.

## scripts/scaffold_sepolicy_module.sh

**Replaces** nothing for shopapi. The seed is already in git.

**Commands.** `sepolicy-generate -a <domain> -t unconfined_t`, then copy `.te`, `.fc`, and `.if` only when those files are missing.

## lab/demo_bootstrap.sh

**Replaces** 104 prep P1–P10. `--shopapi-only` skips Tomcat.

**Commands, in order.** `dnf install`, `groupadd` / `useradd`, `mkdir`, Maven package and `cp` of the jar, install the wrapper, write the unit with no `SELinuxContext=`, `compile_and_validate.sh`, `semodule -i`, `restorecon -Rv`, `semanage port`, `semanage permissive -a`, `systemctl enable --now`.

## lab/demo_present.sh

**Replaces** the talk, not a 104 lab. The customer guide is [301](../demo.md).

**Commands it prints, in act order.** Triage (`semodule -l`). Act 2 on a confined Tomcat: `semanage fcontext`, `restorecon`, `semanage port`, `getsebool`. Distro `tomcat_t` is unconfined, so probes 1 and 2 expect no denial. Act 3: generate, then on the QA host `compile_and_validate.sh`, `semodule -i`, `restorecon`, `semanage port`, curl `/health` `/state` `/log`. Act 6: `semanage permissive -d`, curl `/feature-spool` (fails), generate, `semodule -i`, `restorecon /var/spool/shopapi`, curl returns 200 with `shopapi_t` still enforcing.

## scripts/monitor_avc.sh

**Replaces** 104 steps 2.2 and 4.2 as a gate, not as a lesson.

**Inputs.** `--domain` or `--manifest`, `--paths`, `--marker-file` (an epoch), `--max-avc`.

**Outputs.** JSON with `count`, `status`, `avc_fail_closed`. Status fail when the count is over the max or ausearch failed closed.

**Commands.** `ausearch` with no formatted `-ts` date. Records whose `msg=audit(EPOCH.` is older than the marker are dropped. Then `python3 cli/soak_net_new.py`, which runs `sesearch`. If `sesearch` or the policy file is missing, `avc_fail_closed` is true and the status is fail.

## scripts/check_soak_ready.sh and scripts/check_soak_gate.sh

**Replaces** nothing you type in 104. They read the marker epoch, call `monitor_avc.sh`, and exit non-zero when the window is not clean. `check_soak_days.sh` is the day count. `collect_soak_facts.sh` prints the JSON Ansible reads. `record_soak_day.sh` stores one day's JSON. `post_deploy_report.sh` writes the deploy report.

## scripts/semodule_restore_dontaudit.sh

**Replaces** nothing in 104.

**Commands.** `semodule -B` when this app is the only soak marker. Otherwise it skips, so another app's `-DB` stays in force.

## scripts/verify_file_contexts.sh

**Replaces** the comparison in 104 step P8.

**Commands.** `matchpathcon` against the manifest paths, and a `restorecon -n` style check. Exit non-zero when a path would still change.

## lab/reset_demo_vms.sh

**Replaces** nothing in 104. Between rehearsals, from the Mac.

**Commands.** SSH to the VMs. `semodule -r` leftover shopapi modules. `semanage permissive -d`. `semanage port -d` and `semanage fcontext -d` for the App B tune. Writes an epoch into the ausearch-since marker. Does not stop `auditd` and does not delete `/var/log/audit/audit.log`.

## lab/lab_signing_setup.sh

**Replaces** nothing in 104.

**Commands.** `gpg --quick-gen-key`, `gpg --armor --export` of the public key only, write a `dnf` repo file with `gpgcheck=1`. `--print-secret` exits 1. Do not commit the private key.

## lab/setup_rhel_hosts.sh

**Inputs.** `--qa-host`, `--prod-host`. **Outputs.** `ansible/inventory.dev.yml` and `inventory.production.yml` (gitignored). **Commands.** `ansible-playbook` ping. No `semodule`.

## Other scripts

| Script | SELinux commands | Replaces |
|--------|------------------|----------|
| `selinux_pac_adopt.sh` | None. Prints the next commands for a new app | Nothing in 104 |
| `assemble_pr_body.sh` | None. Writes `policy_out/pr_body.md` | Nothing |
| `demo_open_generated_pr.sh` | `gh pr create` | Nothing |
| `demo_e2e_mac.sh` | None on the Mac. SSH and `ansible-playbook` | The two-host talk, [302](302-TECHNICAL.md) |
| `demo_e2e_rhel_qa.sh` | The generate and curl steps on QA | 104 labs 2–6 via `dev_generate_policy.sh` |
| `demo_e2e_rhel_prod.sh` | `curl`, `ausearch` filtered by epoch. No `semodule -i` | Lab 5's failure, on prod, during soak |
| `validate_version_consistency.sh` | None. Compares `policy_version.txt` to `policy_module()` | Nothing |
| `classify_policy_blast_radius.sh` | `sesearch` on the compiled policy when setools exist | Nothing |
| `wait_for_endpoints.sh` | `curl` | 104 step P10's health check |
| `verify_avc_coverage.sh` | None. Reads the `.te` and the AVC file | Nothing |

Test drivers (`smoke_test.py`, `run_deterministic_fixtures.sh`, `run_e2e_tests.sh`, `test_avc_epoch_window.sh`) do not change a host. The epoch-window test installs nothing. It writes a sample log and asserts count and status fail.

---

## Playbooks

All of these run on the controller. The host does not clone git. Production inventory sets `selinux_ops_from_package: true`, so day 0 is `dnf install` of the RPM, not `semodule -i`.

### ansible/deploy_canary.yml

**Replaces** 104 steps P7–P10 on a host that received an RPM, and adds `semodule -DB`.

**Commands, in order.** `dnf install` the ops RPM and the app policy RPM. `semodule -DB`. `semanage port -l`, then `semanage port -a` for ports the manifest names that are not listed. `community.general.selinux_permissive` (`semanage permissive -a`). `ansible.posix.seboolean` when the manifest names a boolean (`setsebool -P`). `restorecon -Rv` on the manifest paths. Restart the unit. Write the epoch marker `selinux_canary_deployed_at`. When `selinux_ops_from_package` is false, the role copies a `.pp` and runs `semodule -i` instead of `dnf`. That path is the lab, not production day 0.

### ansible/soak_monitor.yml

**Replaces** 104 steps 2.2 and 5.4 as a pass/fail.

**Commands.** `monitor_avc.sh` on the host (the copy in `/usr/libexec/selinux-policy-ops/` when the RPM is installed). Fails when the count is over the max, when ausearch fails closed, or when `sesearch` is missing. Writes `selinux_soak_last_fail.json` and `.avc` on failure. Does not `semodule -i`.

### ansible/soak_status.yml

**Replaces** nothing. Reads the marker and the daily JSON. Does not change the host.

### ansible/enforce_production.yml

**Replaces** 104 step 5.1 (`semanage permissive -d`) after the wait, not during a failed soak.

**Commands, in order.** Refuse when `soak_min_days` is under 7 on the production group. Refuse when the day count has not elapsed. Refuse when the monitor is fail-closed or the net-new count is over the max. `semodule -B` via `semodule_restore_dontaudit.sh` unless another app is soaking. `selinux_permissive` state absent. `restorecon -Rv`. Smoke curls. `skip_soak_days=true` skips only the day count and the daily history. The marker, the AVC gate, net-new, and the report still run. `force_enforce=true` skips the marker, the AVC gate, net-new, the report, the day count, and the daily history. It requires `break_glass_reason`, and that reason is written in the deploy report.

### ansible/emergency_rollback.yml

**Replaces** the return to log-only after lab 6, as an outage response.

**Commands.** `semanage permissive -a`. `semodule -B` unless another marker exists. `restorecon -Rv`. `getenforce` stays Enforcing.

### ansible/reset_host_state.yml

**Commands.** `semodule -B`, then `semanage permissive -d`. The module stays. The demo wipe is `reset_demo_vms.sh`.

### ansible/generate_emergency_patch.yml

**Commands.** None on the production host. On the controller checkout it runs `dev_generate_policy.sh`. Output is `policy_out/` for a pull request. No `semodule -i`.

---

## What a pull request must not contain

| Do not write | Why |
|--------------|-----|
| A custom module for JWS, EAP, httpd, named, or postgresql | Vendor or base policy already confines them |
| `execmem` or `dac_override` without the review flag | Domain-weakening |
| `allow … unreserved_port_t:tcp_socket name_bind` | Binds every high port |
| `allow … bin_t:file execute` | Label an app program with the app exec type. The system JVM is `bin_t` on RHEL 9: `corecmd_exec_bin` with a reviewed `selinux_exceptions.exec_bin` |
| `allow … *:*` | Unbounded |
| `chcon` in a playbook | Lost on the next `restorecon` |
| `setenforce 0` | Host-wide. Use `semanage permissive -a` |
| `audit2allow` pasted in | Wildcards and the wrong class |
| `semodule -i` on prod | Day 0 is the RPM. A 400-priority install overrides priority 200 |

## Add an application

Customer policy lives in the application repo. Generate on rhel-qa. Prod never clones git.

```bash
cp config/payments.manifest.example.yml config/payments.manifest.yml
bash scripts/validate_app_manifest.sh config/payments.manifest.example.yml
bash scripts/scaffold_sepolicy_module.sh payments payments_t
bash scripts/compile_and_validate.sh selinux/payments --app payments
```

`payments.if` publishes `payments_read_public_state` and `payments_domtrans`. An app repo calls `.github/workflows/selinux-policy-app.yml` and passes `tools_repo` and `tools_ref`. Copying `selinux-policy-ci.yml` into the app repo does not work.

## Algorithms

| Idea | One line |
|------|----------|
| AVC merge | Group lines by source, target, and class. Union the permissions |
| Net-new | Permissions in the log minus permissions `sesearch` already shows |
| Soak gate | Days since the canary, zero net-new, and not fail-closed. Missing `sesearch` is fail-closed |
| Blast radius | New allows classified low, medium, or high. Errors stay at 7 days |
| Version | `policy_version.txt` matches `policy_module()` |

Next: [202 — tool lab](202-TOOL-LAB.md).
