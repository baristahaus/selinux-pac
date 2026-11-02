# sepac reference

`sepac COMMAND APP [options]`. `APP` is the only required argument. Everything else about the app (its domain, unit, paths, port, endpoints, policy directory) comes from its [manifest](#the-manifest), `config/APP.manifest.yml`.

Two kinds of host run sepac:

- **The QA host** has a git checkout of the policy repo, the app installed, and `selinux-policy-devel`. Policy is written and tried here.
- **Where Ansible runs** (a laptop, or an AAP execution node) ships it: build, publish, canary, soak, enforce, rollback.

Managed hosts (staging, production) have sepac too, from the Ansible role. There, the read-only commands work (`status`, `denials`, `capture --no-restart`, `doctor`), and `generate`, `check` and `load` refuse.

## Options for every command

| Option | Meaning |
|--------|---------|
| `--dry-run` | Print the commands sepac would run. Change nothing. Works before or after the command name. |
| `-v` | Print each underlying command before running it |
| `--tree DIR` | The policy tree (`config/`, `selinux/`, `ansible/`). Default: the git checkout you are in, then `tree=` in `/etc/selinux-pac/sepac.conf` |
| `--manifest PATH` | Use this manifest instead of looking one up |
| `--version` | The RPM version, or `git describe` in a checkout |

sepac escalates with `sudo` per step when it needs root. Type `sepac …`, not `sudo sepac …`. It exits with the underlying tool's exit code; `2` means invalid input, and `1` means a guardrail refused.

`sepac completion bash` prints the tab-completion script (the RPM installs it). `man sepac` is the same reference in short form.

## On the QA host

### init

```bash
sepac init orders --port 9090 [--unit orders.service]
```

Writes `config/orders.manifest.yml` from a template, scaffolds `selinux/orders/` with `sepolicy-generate` (from `policycoreutils-devel`), and writes `policy_version.txt`. Existing files are kept. Review every value in the manifest before the first `capture`: paths, unit, port and the endpoints to call.

### doctor

Checks that this host has what sepac needs: `getenforce`, `ausearch`, `sesearch`, and on a controller `ansible-playbook`.

### triage

```bash
sepac triage tomcat
sepac triage shopapi
```

Answers one question before anyone writes policy: does Red Hat already ship it? sepac looks at the loaded modules, the installed and available SELinux packages, and the running process, then prints a `TRIAGE` line and one line of advice.

| Situation | What it means | What to do |
|-----------|---------------|------------|
| `none` | No Red Hat policy for this app (Spring Boot, Node, your own code) | `sepac generate APP` |
| `loaded` | A Red Hat module confines it (`jws6_tomcat`, `apache`, `bind`, `postgresql`) | `sepac tune APP`. Do not write a module. |
| `loaded_unconfined` | A module is loaded but its domain is unconfined. Distro Tomcat is `tomcat_t`, which RHEL ships unconfined. | Install the vendor's confining package (`jws6-tomcat-selinux`). Generate only with `--force "reason"`. |
| `package_installed` | The vendor SELinux RPM is installed, the module is not loaded | Enable it |
| `package_available` | The vendor SELinux RPM is in the repos | Install it (`jws6-tomcat-selinux`, `eap7-selinux`, `eap8-selinux`) |
| `unconfined` | Tomcat or JBoss running as `unconfined_service_t` | Install the vendor package |
| `base_policy` | The base policy covers it (httpd, named, postgresql) | `sepac tune APP` |

Apps without a manifest (Tomcat, in the demo) work here: the unit defaults to `APP.service`.

### tune

```bash
sepac tune tomcat
```

For an app Red Hat already confines: classifies its denials and prints the host fixes, the `semanage fcontext` plus `restorecon`, `semanage port -a` and `setsebool -P` lines, for you to review and run. It never writes a module. The report is also saved as `policy_out/tune_report.md`.

### capture

```bash
sepac capture shopapi --full-audit
sepac capture shopapi --no-restart --url /feature-spool
```

Collects the evidence `generate` works from:

1. With `--full-audit`, turns dontaudit rules off for the run (`semodule -DB`), so denials the policy normally hides are logged too, and puts them back afterwards, even on failure. It leaves them off if another app is still soaking on this host.
2. Restarts the unit (skip with `--no-restart`) and waits for it to answer.
3. Calls every endpoint in the manifest, plus each `--url`, and prints the HTTP status.
4. Summarises the app's denials since it started: how many, whether they were blocked or only logged, which ones the manifest lists as expected (`soak.ignore`), and the new access needs.

```text
Restarted shopapi.service (answering after 6s)
GET /health             200
GET /state              200
GET /log                200
GET /feature-spool      500
shopapi_t: 3 denials (enforcing: blocked)
  expected, listed in the manifest's soak.ignore: cgroup_t dir, passwd_file_t file
  new: 1 access need
    { open } on var_spool_t file  /var/spool/shopapi/feature.log
  Next: sepac generate shopapi
```

On a managed host, only `--no-restart` is allowed.

### denials

```bash
sepac denials shopapi [--since recent|boot|today|this-hour] [--enforced] [--why] [--last N]
```

The app's raw AVC records: only lines whose source type is the app's domain. Without a manifest, any domain whose name contains the app (`tomcat` matches `tomcat_t` and `jws6_tomcat_t`). `--enforced` keeps blocked ones (`permissive=0`). `--why` runs them through `audit2why`. The default window is the last 10 minutes.

### generate

```bash
sepac generate shopapi
sepac generate shopapi --approve execmem --apply
```

Turns every denial for the app's domains since boot into the smallest policy that covers it. The result goes to `policy_out/` with the version bumped, and sepac prints the diff against `selinux/APP/`. `--apply` copies it into `selinux/APP/`, ready for a pull request.

Each access need gets one verdict:

| Verdict | What sepac writes |
|---------|-------------------|
| interface | A Red Hat interface call (`kernel_read_system_state(shopapi_t)`), not the raw rules behind it |
| label fix | A line in `.fc` for a file under the app's own paths, so `restorecon` gives it the app's type. It does not grant access to a generic type such as `var_spool_t`. |
| port | The app's own port type, applied with `semanage port -a` |
| boolean | Nothing in the `.te`: the boolean goes in the manifest's `selinux_booleans` |
| baseline | Nothing: already covered, or deliberately left out (the JVM reading cgroup files) |
| needs review | Nothing yet, and generation stops: `execmem`, `dac_override` and similar weaken the domain. A reviewer re-runs with `--approve PERM` for each one. |
| forbidden | Nothing, ever: shadow, `/etc/passwd`, `security_t`, `selinux_config_t`, `unconfined_t`. `--approve` does not unlock these. |
| reviewed exception | `corecmd_exec_bin` for the system JVM, only when the manifest records `selinux_exceptions.exec_bin` with a reason. On RHEL 9 the JVM is `bin_t`. |

When generation stops for review, sepac prints the exact command to run afterwards:

```text
Blocked for review: execmem. After review: sepac generate shopapi --approve execmem --apply
```

`--skip-export` reuses `policy_out/avc.log`, for example a denial export copied from production. `--force "reason"` overrides the vendor-policy check; the reason is recorded for the pull request.

### check

```bash
sepac check shopapi
```

The gate every policy pull request runs:

1. The manifest is valid.
2. No forbidden pattern in the `.te`: wildcards, forbidden targets, a raw `execute` on `bin_t`, broad writes on generic types.
3. The module compiles against this host's `selinux-policy-devel`.
4. Semantic checks: the module is loaded into a throwaway copy of the policy store and compared with an empty control domain. It must not gain `setenforce`, `load_policy`, shadow access, `sys_admin` or `sys_module`, must not be permissive or unconfined, and must not relabel `/etc/shadow`.

Without `selinux-policy-devel` (a laptop, a controller), steps 1 and 2 run and sepac prints `SKIP compile and semantics`. It never reports them as passed.

### load

```bash
sepac load shopapi
sepac load shopapi --enforcing
sepac load shopapi --permissive
```

Tries the module on the QA host:

1. Loads the build of `selinux/APP/`. It uses `policy_out/APP.pp` only when that was built from the same `.te` and `.fc`, and compiles otherwise. When the loaded module is already identical, it skips the reload.
2. Runs `restorecon -Rv` on the manifest's paths, and prints each file it relabels.
3. Adds each manifest port with `semanage port -a`. A port that another application type owns is refused.
4. `--enforcing` takes the domain off the permissive list; `--permissive` puts it on.

`load` refuses unless `/etc/selinux-pac/role` says `qa` or `dev`. This guards against mistakes; it is not a security control.

### status

```text
Host     Enforcing
Module   shopapi 1.0.2, priority 400, matches the repo build
Domain   shopapi_t enforcing
Process  shopapi.service system_u:system_r:shopapi_t:s0
Labels   ok
Denials  0 in the last 10 minutes
```

On a managed host, the module is compared with the one the `APP-selinux` RPM installed.

## Where Ansible runs

These wrap the playbooks in `ansible/`. `--env` picks `ansible/inventory.ENV.yml`; the inventory names the app. `--limit` is passed through.

| Command | Playbook | Notes |
|---------|----------|-------|
| `sepac build [--allow-dirty]` | `packaging/build_rpms.sh` | Refuses a dirty tree unless `--allow-dirty` |
| `sepac publish [--env-file F]` | `packaging/publish_internal.sh` | Signs and publishes; loads signing settings from `F` |
| `sepac canary --env E` | `deploy_canary.yml` | Installs the RPM, puts only the app's domain on the permissive list, starts the soak clock |
| `sepac soak --env E [--status]` | `soak_monitor.yml` / `soak_status.yml` | Daily gate: fails on net-new access against the installed policy. `--status` only reads. |
| `sepac enforce --env E --ticket T` | `enforce_production.yml` | Needs the soak gate, or `--break-glass "reason"`. `--skip-soak-days` skips only the day count. |
| `sepac rollback --env E` | `emergency_rollback.yml` | Domain back to permissive, optional RPM downgrade. The host stays Enforcing. |

[shipping.md](shipping.md) walks through them.

## The manifest

`config/APP.manifest.yml` is the one file sepac reads for an app. Commit it next to `selinux/APP/`. Keep bind ports the same in every environment; change only the probe host per environment (`http.host`, or `http_probe_host` in the inventory).

```yaml
app_name: shopapi
domain: shopapi_t
paths:
  install_root: /opt/shopapi
  var_dir: /var/lib/shopapi
  log_dir: /var/log/shopapi
  runtime_dir: /run/shopapi
  extra_fc_roots: [/var/spool/shopapi]
services:
  primary: {unit: shopapi.service, domain: shopapi_t}
http:
  host: 127.0.0.1
  port: 8091
  endpoints: [/health, /state, /log]
selinux_ports:
  - {port: 8091, proto: tcp, type: shopapi_port_t}
selinux_exceptions:
  exec_bin: >-
    The wrapper execs the system JVM. On RHEL 9 that file is bin_t, so no
    narrower type exists. corecmd_exec_bin is what Red Hat's tomcat policy uses.
soak:
  ignore:
    - {tclass: file, target_type: passwd_file_t}
policy:
  module_dir: selinux/shopapi
```

| Key | Required | Meaning |
|-----|----------|---------|
| `app_name`, `domain` | yes | Module name and the process domain (`shopapi` → `shopapi_t`) |
| `paths.install_root`, `paths.var_dir` | yes | Install tree and state directory. `log_dir` and `runtime_dir` are recommended. |
| `paths.extra_fc_roots` | no | Paths outside the usual four that the `.fc` may claim later (the demo's spool) |
| `services.primary.unit` | yes | The systemd unit `capture` restarts and `status` inspects. `services.backend` is a second unit. |
| `http.port`, `http.endpoints` | yes | The bind port, and the paths `capture` and the canary call (GET, expect 200) |
| `selinux_ports` | recommended | Port → type, added with `semanage port -a` by `load` and the canary |
| `selinux_booleans` | no | `{name, state, persistent}`. The canary applies them before the service starts. `tomcat_can_network_connect` does not exist and is rejected; `httpd_can_network_connect` is rejected on a Tomcat domain. |
| `selinux_exceptions` | no | Reviewed exceptions, each with a written reason of 20+ characters. `exec_bin` is the only key. |
| `soak.ignore` | no | Denials that are expected and are not allows: refused targets, deliberately omitted housekeeping. `capture` and the soak gate list them separately. |
| `policy.module_dir` | no | Default `selinux/APP` |
| `deploy.soak_marker_file`, `deploy.deploy_report_file` | no | Default under `/var/lib/selinux-policy-ops/APP/` |

The playbooks, the host scripts and the generator all read this file. An app repo's CI validates it with the reusable workflow ([shipping.md](shipping.md#policy-ci-for-an-app-repo)).

## Files on each host

| File | Written by | Read by |
|------|------------|---------|
| `/etc/selinux-pac/role` | The Ansible role (from `selinux_pac_host_role`); `make demo-bootstrap` on the demo host | `load` (needs `qa` or `dev`), `generate`, `check` and `capture` (refuse or restrict on `production`) |
| `/etc/selinux-pac/apps/APP.manifest.yml` | The Ansible role | sepac on managed hosts, which have no checkout |
| `/etc/selinux-pac/sepac.conf` | You | `tree=/path/to/policy/checkout` |
| `policy_out/` | `generate` | `load`, the pull request (`pr_body.md`, `findings.json`) |
| `/var/lib/selinux-policy-ops/APP/` | The canary and soak playbooks | `soak`, `enforce`: the marker, daily results, the last failure |
