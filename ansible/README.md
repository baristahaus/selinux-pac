# Ansible Playbooks

> Admins run these through sepac: `sepac canary`, `sepac soak`, `sepac enforce`, `sepac rollback` ([docs/shipping.md](../docs/shipping.md)). This page documents the playbooks themselves.

Ansible orchestrates the **admin deploy lifecycle** for SELinux policy on RHEL 9 hosts. It does **not** install the application for the first time — use [`lab/demo_bootstrap.sh`](../lab/demo_bootstrap.sh) for the shopapi demo.

**AAP job templates and soak workflow:** [`ansible/aap/`](aap/README.md) and [`docs/shipping.md`](../docs/shipping.md). Denied file/port after ship: [`docs/shipping.md#a-denial-after-ship`](../docs/shipping.md#a-denial-after-ship).

**Where commands run:**

| What | Where |
|------|--------|
| `ansible-playbook …` | **Controller** (AAP execution node or laptop) with SSH to inventory hosts |
| `semanage`, `semodule`, soak scripts on hosts | **Target RHEL/Stream machines** in inventory |
| `compile_and_validate.sh` before deploy | **RHEL** with `selinux-policy-devel` (typically rhel-qa) |

**Doc index:** [docs/guides/README.md](../docs/guides/README.md).

| Playbook | Purpose |
|----------|---------|
| [`deploy_canary.yml`](deploy_canary.yml) | Install policy, permissive soak start, smoke tests |
| [`soak_monitor.yml`](soak_monitor.yml) | Daily / on-demand AVC + net-new threshold check |
| [`soak_status.yml`](soak_status.yml) | Read-only soak facts before enforce |
| [`enforce_production.yml`](enforce_production.yml) | Soak gate, remove permissive, enforce smoke |
| [`emergency_rollback.yml`](emergency_rollback.yml) | Permissive first; optional `dnf downgrade` |
| [`reset_host_state.yml`](reset_host_state.yml) | `semodule -B` + clear permissive (no module change) |
| [`generate_emergency_patch.yml`](generate_emergency_patch.yml) | Controller + git checkout only — `policy_out/` for a PR, not host install |

Playbooks delegate to role [`roles/selinux_pac/`](roles/selinux_pac/). The old `myapp_selinux` role is gone — do not restore it. Target scripts live in RPM **`selinux-policy-ops`** at **`/usr/libexec/selinux-policy-ops`** (inventory: `selinux_ops_dir`). Checkout (no ops RPM) sets `selinux_ops_from_package: false` and points `selinux_ops_dir` at the **target** checkout `scripts/` tree (not `playbook_dir` on a laptop).

**Ship guide:** [`docs/shipping.md`](../docs/shipping.md). Two-host lab: [`docs/guides/302-TECHNICAL.md`](../docs/guides/302-TECHNICAL.md). Testing matrix: [`docs/guides/303-TESTING.md`](../docs/guides/303-TESTING.md). Compile on **RHEL** with `selinux-policy-devel`.

---

## Prerequisites

### Host requirements

- **RHEL 9** with **SELinux enforcing**
- Application already installed (`/opt/myapp`, systemd units, `myapp` user)
- `auditd` running (for AVC gates)
- `policycoreutils`, `policycoreutils-python-utils` (`semanage`, `restorecon`, `ausearch`)

### Controller requirements

```bash
pip install ansible
ansible-galaxy collection install -r ansible/requirements.yml
```

Collections: `community.general` (`selinux_permissive`), `ansible.posix` (`seboolean`). Ports use `semanage port -a`, not `seport`.

### Inventory

| File | Use |
|------|-----|
| [`inventory.dev.example.yml`](inventory.dev.example.yml) | **RHEL QA box** (SSH from controller) — generate with `setup_rhel_hosts.sh` (filename `inventory.dev.yml` is legacy) |
| [`inventory.production.example.yml`](inventory.production.example.yml) | **RHEL prod box** (canary + production groups) |
| [`inventory.staging.example.yml`](inventory.staging.example.yml) | Ansible **on** the staging host (`connection: local`) |
| [`inventory.example.yml`](inventory.example.yml) | Local / single-host **backup** (Ansible on the box) |

---

## Policy artifacts and RPMs

Build the module before deploy (`.pp` is not committed). RPM version is taken from **`selinux/myapp/policy_version.txt`** when you run [`packaging/build_rpms.sh`](../packaging/build_rpms.sh) (`myapp-selinux-<version>-*.rpm`).

```bash
bash scripts/compile_and_validate.sh selinux
```

**Two RHEL boxes (preferred):** [`docs/guides/302-TECHNICAL.md`](../docs/guides/302-TECHNICAL.md) — `bash lab/setup_rhel_hosts.sh write --qa-host … --prod-host …`.

**Laptop / AAP → rhel-qa:** `policy_artifact_dir` and `policy_pp_src` are the controller checkout (compiled `.pp` is copied over). `selinux_ops_dir` and `app_manifest_path` are paths **on rhel-qa** after you clone the repo (`/home/ansible/selinux-pac/...`). Do not set those two from `playbook_dir` — that expands to a Mac/AAP path the guest does not have.

```bash
ansible-playbook -i ansible/inventory.dev.yml ansible/deploy_canary.yml
```

**Production (no git on target):** install RPMs built from [`packaging/build_rpms.sh`](../packaging/build_rpms.sh) (`selinux-policy-ops`, `myapp-selinux-<version>`). Inventory sets `selinux_ops_from_package: true`, `app_manifest_path: /etc/myapp/selinux-manifest.yml`, and leaves `policy_pp_src` empty when the module comes only from the RPM.

---

## Shared variables

Set in inventory `vars` or pass with `-e`. Role defaults live in [`roles/selinux_pac/defaults/main.yml`](roles/selinux_pac/defaults/main.yml).

| Variable | Typical value | Description |
|----------|---------------|-------------|
| `app_name` | `myapp` | Module name prefix |
| `domain` | `myapp_t` | Application SELinux domain |
| `install_root` | `/opt/myapp` | Application tree |
| `var_dir` | `/var/lib/myapp` | State directory (`StateDirectory`) |
| `log_dir` | `/var/log/myapp` | Log directory (`LogsDirectory`) — **must be set in inventory** (not a self-referential play var) |
| `runtime_dir` | `/run/myapp` | Runtime dir (`RuntimeDirectory`) |
| `service_name` | `myapp.service` | Primary systemd unit |
| `policy_version` | _(from `policy_artifact_dir/policy_version.txt` or `../selinux/myapp/policy_version.txt`)_ | SemVer for RPM name and deploy report |
| `selinux_ops_dir` | `/usr/libexec/selinux-policy-ops` | **Target** path to ops scripts (lab: `/home/<user>/selinux-pac/scripts`) |
| `selinux_ops_from_package` | `true` / `false` | When `true`, role runs `dnf install selinux-policy-ops` (+ app RPM) |
| `policy_artifact_dir` | controller repo or `dist/` | **Controller only** — never used in remote `command` paths |
| `policy_pp_src` | `…/selinux/myapp/myapp.pp` | **Controller only** — copied to `policy_staging_path` on target; empty when RPM-only |
| `policy_staging_path` | `/var/lib/selinux-policy-staging/myapp.pp` | Target path for `semodule -i` |
| `app_manifest_path` | `/etc/myapp/selinux-manifest.yml` (prod) or `/home/<user>/selinux-pac/config/*.manifest.yml` (lab) | **Target** path passed to `--manifest` ops scripts; role **loads ports, units, paths**. Not `playbook_dir` |
| `http_probe_host` | `127.0.0.1` or canary VIP | Curl target; **not** the bind port (ports stay in `selinux_ports`) |
| `soak_marker_file` | `/var/lib/selinux-policy-ops/{{ app_name }}/selinux_canary_deployed_at` | Epoch file for soak clock (root-owned, outside the app var dir) |
| `soak_min_days` | `7` | Minimum soak days (enforce gate) |
| `soak_max_avc` | `0` | Max raw AVCs since marker (used when net-new fail-closed) |
| `soak_max_net_new` | `0` | Max **net-new** access needs vs installed policy |
| `soak_use_net_new` | `true` | Prefer net-new gate in `enforce.yml` |
| `soak_notify_webhook` | *(empty)* | Optional POST URL when soak monitor fails (AAP notification templates are preferred) |
| `canary_max_avc` | `0` | Max recent AVCs right after canary deploy |
| `skip_soak_days` | `false` | Skip only the day count and daily history. Marker, AVC gate, net-new, and the report still run |
| `force_enforce` | `false` | Skip every soak gate (break-glass); **requires** `change_ticket` and `break_glass_reason` |
| `change_ticket` | `CHG123` | **Required** on enforce (AAP survey) |
| `rollback_dnf_version` | *(unset)* | e.g. `1.1.1-1` → `dnf downgrade myapp-selinux-…` on emergency rollback |

**Deprecated (do not use on production targets):** `project_root`, `policy_pp_path`, `policy-history/`, `rollback_target_version`.

**Optional blast-radius soak tier (`check_soak_ready.sh` on controller):** pass **`--auto-tier`** with **`--base-policy`** and **`--candidate-policy`** (paths to `.te`/`.pp` for previous vs candidate module). The script calls [`classify_policy_blast_radius.sh`](../scripts/classify_policy_blast_radius.sh) (sesearch rule diff, not `sediff`). On classifier error or `fail_closed` JSON, minimum soak stays at **`soak_min_days`** (default 7) — never shortens the gate on failure. Tier logic is gated by **`make test-fixtures`** ([`tests/fixtures/blast_radius/`](../tests/fixtures/blast_radius/)).

**Ansible enforce role** uses **`collect_soak_facts.sh`** with `soak_min_days` plus **`avc_net_new_count`**. `sesearch` (`setools-console`) is required on canary/prod.

**Deprecated:** hardcoding `policy_version` in inventory — the role loads **`policy_version.txt`** from `policy_artifact_dir` (e.g. `policy_out/`) or **`selinux/myapp/policy_version.txt`** beside it.

---

## Directory ownership (who creates what)

| Path | Created by | SELinux labels from |
|------|------------|---------------------|
| `/opt/myapp` | App install / admin | Policy module `.fc` + `restorecon` |
| `/var/lib/myapp`, `/var/log/myapp` | Ansible `file` task before canary/enforce (systemd `StateDirectory`/`LogsDirectory` also apply at service start) | Policy module `.fc` |
| `/run/myapp` | systemd at service start | Policy module `.fc`; `restorecon` **after** restart |
| Ops scripts | **`selinux-policy-ops` RPM** | N/A |
| App manifest | **`myapp-selinux` RPM** → `/etc/myapp/selinux-manifest.yml` | N/A |

---

## `deploy_canary.yml`

**When:** After policy merge — staging auto-deploy on `main`, or prod canary host before fleet.

**Goal:** Install module, start **permissive soak**, verify labeling and endpoints, record soak marker.

Implements role phase **`canary`** ([`roles/selinux_pac/tasks/canary.yml`](roles/selinux_pac/tasks/canary.yml)).

### Task order (summary)

| # | Task | Notes |
|---|------|-------|
| 1 | Install ops + app RPM (optional) | When `selinux_ops_from_package` |
| 2 | Stage `.pp` from controller → `semodule -i` | When `policy_pp_src` set |
| 3 | `semodule -DB` | Host-wide dontaudit off for soak |
| 4 | Register `selinux_ports` | `semanage port -a` only when the port is free. If `semanage port -l` already assigns it to a different type, the canary fails. It does not run `semanage port -m`. |
| 5 | Permissive domain | `semanage permissive` on the app domain only. Canary fails if `semanage` is missing. It does not install a permissive overlay. |
| 6 | `selinux_booleans` | `ansible.posix.seboolean` before the service starts. Empty list is a no-op. |
| 7 | Ensure `var_dir` + `log_dir`; `restorecon` (no pre-restart `/run/myapp`) | |
| 8 | `{{ selinux_ops_dir }}/verify_file_contexts.sh` | On production this is `/usr/libexec/selinux-policy-ops/verify_file_contexts.sh`. |
| 9 | Soak marker; restart services; `restorecon` on `runtime_dir` | The policy RPM `%post` must not restart the service before this. |
| 10 | `wait_for_endpoints.sh`, `monitor_avc.sh`, `post_deploy_report.sh` | All under `selinux_ops_dir` |
| **rescue** | `semodule -B` unless another app is still soaking, then fail | |

### Example

```bash
bash scripts/compile_and_validate.sh selinux
ansible-playbook -i ansible/inventory.production.yml ansible/deploy_canary.yml \
  --limit canary
```

(Production inventory uses RPMs; staging/example passes `policy_pp_src` — see inventory files.)

Preferred admin UI: [401-OPERATIONS.md](../docs/shipping.md). PR review CI: [`.github/workflows/selinux-policy-ci.yml`](../.github/workflows/selinux-policy-ci.yml) (`offline-tests`, `forbidden-patterns`, `compiled-policy`, `version-consistency`).

---

## `enforce_production.yml`

**When:** After soak gates pass (**`soak_min_days`**, default 7, plus **net-new** unless fail-closed).

**Goal:** Remove permissive flag, run app under **enforcing** `myapp_t`, verify endpoints.

Role phase **`enforce`**. Uses **`serial: 1`**.

### Task order (summary)

| # | Task | Notes |
|---|------|-------|
| 1 | `collect_soak_facts.sh` → assert days / net-new / report | Skipped when `force_enforce=true`; raw AVC if `avc_fail_closed` |
| 2 | `semodule -B` | Restore dontaudit before production |
| 3 | Remove permissive; verify enforcing | |
| 4 | Dirs + `restorecon`; verify contexts; restart; runtime `restorecon` | |
| 5 | `wait_for_endpoints.sh` + enforce deploy report | |
| **rescue** | Permissive + restart + endpoint wait + fail | |

### Example

```bash
ansible-playbook -i ansible/inventory.production.yml ansible/enforce_production.yml \
  --limit production \
  -e change_ticket=CHG123

# Break-glass only (ticket still required):
ansible-playbook ... enforce_production.yml -e "force_enforce=true" -e change_ticket=CHG123
```

---

## `soak_monitor.yml` / `soak_status.yml`

**When:** Daily during soak (`soak_monitor`); immediately before enforce (`soak_status`).

| Playbook | Effect |
|----------|--------|
| `soak_monitor.yml` | Runs `monitor_avc.sh --format json` with `--max-avc`, `--max-net-new`, and `--fail-dir`; **fails** if `status=fail` with a PR-shaped `next_step` |
| `soak_status.yml` | Read-only `collect_soak_facts.sh` summary (no state change) |

Schedule **Soak monitor** in AAP on the canary group. See [401-OPERATIONS.md](../docs/shipping.md).

---

## `emergency_rollback.yml`

**When:** Enforce caused outage, or admin needs immediate permissive relief.

Role phase **`rollback`**. **Permissive first** (stock modules / `semanage`); optional **`dnf downgrade`**; then `semodule -B`, restorecon, restarts, AVC export. Optional ops scripts if RPM installed.

Run [`generate_emergency_patch.yml`](generate_emergency_patch.yml) on the **controller git checkout** after fetching `/tmp/emergency_avc.log` or `selinux_soak_last_fail.avc`. Output is `policy_out/` for a PR — never `semodule -i` on prod. See [401-OPERATIONS.md#a-denial-after-ship](../docs/shipping.md#a-denial-after-ship).

### Example

```bash
ansible-playbook -i ansible/inventory.production.yml ansible/emergency_rollback.yml \
  --limit canary \
  -e "rollback_dnf_version=1.1.1-1"
```

---

## `reset_host_state.yml`

After an **interrupted canary** (host left on `semodule -DB` or permissive): `semodule -B` + clear permissive — **does not** change the installed policy module.

To wipe leftover **demo** policy on both VMs and start [302-TECHNICAL.md](../docs/guides/302-TECHNICAL.md) over: `bash lab/reset_demo_vms.sh` on the Mac (shopapi JVM stays).

---

## GitHub Actions (PR review)

Same playbooks as AAP for ship — [401-OPERATIONS.md](../docs/shipping.md) is the admin UI. GitHub only runs policy best-practices on the PR:

Workflow: [`.github/workflows/selinux-policy-ci.yml`](../.github/workflows/selinux-policy-ci.yml)

| Job | Script |
|-----|--------|
| `offline-tests` | `make test` |
| `forbidden-patterns` | `validate_forbidden_patterns.sh` on `selinux`, `selinux/shopapi`, and `selinux/payments` (generator already ran this) |
| `compiled-policy` | `validate_policy_semantics.sh` for myapp, shopapi, and payments on Stream 9 |
| `version-consistency` | `validate_version_consistency.sh` |

Canary / enforce / rollback are AAP (or `ansible-playbook` from the Mac), not GitHub runners.

---

## Ops scripts (target)

Installed by **`selinux-policy-ops`** RPM (or checkout when `selinux_ops_from_package: false`):

| Script | Role phase |
|--------|------------|
| `verify_file_contexts.sh` | canary, enforce |
| `wait_for_endpoints.sh` | canary, enforce, rollback (optional) |
| `monitor_avc.sh` | canary, **soak_monitor** |
| `collect_soak_facts.sh` | enforce, **soak_status** |
| `lib/soak_net_new.py` | called by `monitor_avc.sh` / `collect_soak_facts.sh` |
| `check_soak_ready.sh` | optional host CLI (also in ops RPM) |
| `post_deploy_report.sh` | canary, enforce, rollback (optional) |

**Controller / CI only:** `compile_and_validate.sh`, `classify_policy_blast_radius.sh`, `cli/deterministic_gen.py`, `scripts/selinux_pac_adopt.sh`.

Parity guard: [`scripts/validate_rpm_ops_parity.sh`](../scripts/validate_rpm_ops_parity.sh) (`make test-rpm`).

---

## Verification checklist (sign-off)

| Check | How |
|-------|-----|
| Canary without rescue | Clean RHEL 9 host: `ansible-playbook … deploy_canary.yml` → **Report canary status** (no `rescue`) |
| Developer PR handoff | `bash scripts/dev_generate_policy.sh --apply --open-pr` → branch pushed, PR opens |
| No repo on prod target | SSH host with RPMs only + production inventory; canary/enforce complete |
| Packaging drift | `bash scripts/validate_rpm_ops_parity.sh` (CI) |
| Policy compile | `bash scripts/compile_and_validate.sh selinux` |

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `policy_pp_src` missing (lab) | Run `compile_and_validate.sh`; pass `-e policy_pp_src=…` |
| Recursive template error on `log_dir` | Set `log_dir` in inventory only — not `log_dir: "{{ log_dir \| default… }}"` in play vars |
| Canary fails on AVC count | `ausearch --subject myapp_t -m AVC -ts recent` |
| `wait_for_endpoints` exit **4** | `ps -eZ \| grep myapp` — domain mismatch |
| Enforce rescue | Deploy report at `/var/lib/selinux-policy-ops/{{ app_name }}/selinux_deploy_report.json` |
| Host noisy after failed canary | Run `reset_host_state.yml` or `semodule -B` + clear permissive |

See [`401-OPERATIONS.md`](../docs/shipping.md#when-something-fails).
