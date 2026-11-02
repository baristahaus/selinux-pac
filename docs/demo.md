# The sepac demo

One RHEL host, one script, two profiles. The core story takes about 15 minutes.
If there is more time, Part 5 shows a production-style policy failure, rollback,
and recovery — another 8 minutes. Every step on screen is a `sepac` command.

**LAST_VERIFIED:** 2026-10-19 for the previous version of this script. Rehearse once on the QA VM before a customer sees it.

```bash
bash lab/demo_present.sh --dry-run            # any laptop: commands + sample output
bash lab/demo_present.sh --preflight          # on the RHEL host, before the audience
bash lab/demo_present.sh                      # the core demo (parts 1-4)
bash lab/demo_present.sh --profile full       # with the prod failure beat (parts 1-5)
```

| Profile | Parts | Time | Story |
|---------|-------|------|-------|
| `customer` (default) | 1–4 | ~15 min | Red Hat's policy first → tune → write from evidence → enforce |
| `full` | 1–5 | ~22 min | + a new feature is blocked, rolled back, fixed, enforced |
| `technical` | 1, 3, 5 | ~18 min | Skip triage/tune, jump to write + failure |

| Part | On screen | The point |
|------|-----------|-----------|
| 1 Triage | `sepac triage tomcat`, `sepac triage shopapi` | Red Hat's policy first. Only shopapi needs new policy. |
| 2 Tune | `sepac denials tomcat --why` (JWS: `sepac tune tomcat`) | Vendor-confined apps get host fixes, never a module |
| 3 Write | `sepac status`, `capture`, `generate` twice, `check`, `load` | Policy from evidence; `execmem` needs a reviewer; `/etc/passwd` is refused; the CI gate |
| 4 Enforce | `sepac load --enforcing`, `capture`, `status` | Enforce it. Known endpoints work. The host stays Enforcing. |
| 5 Prod fail | `capture --url /feature-spool` → 500, `--permissive`, `generate`, `load --enforcing` | A new feature is blocked, rolled back, fixed from evidence, enforced again |

The three-host version (Mac + rhel-qa + rhel-prod, about 45 minutes) shows the
full shipping lifecycle live: build → canary → soak → enforce, with a real outage
and rollback. See [guides/302-TECHNICAL.md](guides/302-TECHNICAL.md).

## The three apps

| App | Story | What sepac says |
|-----|-------|-----------------|
| **App A** | A standard Tomcat on port 8080 | Red Hat ships Tomcat policy. Do not write a module. |
| **App B** | A second Tomcat someone inherited: port 8090 (8080 was taken), data dropped in `/opt/appdata` labelled `user_home_t`, an outbound call to a payment gateway | The same domain as App A. Fix the host (port, label, boolean) where a denial is real; still no module. |
| **shopapi** | A Spring Boot service your team wrote, started by systemd | No Red Hat policy. The only app that gets one. |

App A and App B both run as `tomcat_t`: a second Tomcat instance does not get its own type.

**Which Tomcat the host has matters.** The bootstrap installs the Tomcat that ships with RHEL. Its type, `tomcat_t`, exists and is unconfined, so `sepac triage` says `loaded_unconfined` and part 2 shows no denials. Say that out loud: it is the honest result, and it is exactly why triage runs first. JBoss Web Server's `jws6_tomcat_t` does confine; on a JWS host part 2 shows the three denials and `sepac tune` prints the fixes. shopapi is confined on either host.

## Before the meeting

On the Mac, when the VM ran the demo before. It puts the types-only shopapi seed back and removes App B's port and label fixes.

```bash
bash lab/reset_demo_vms.sh --dev-only
```

On the RHEL host, from the repo root. The bootstrap installs App A, App B and shopapi (with its types-only seed, permissive), and writes `/etc/selinux-pac/role` as `qa`. It is safe to run again.

```bash
sudo bash lab/demo_bootstrap.sh
bash lab/demo_present.sh --preflight         # want: Preflight PASSED
bash lab/demo_present.sh                     # the core demo
bash lab/demo_present.sh --profile full      # with prod failure
```

On a laptop with no RHEL, `bash lab/demo_present.sh --dry-run` types every command with a sample of the good output and runs nothing. `--variant jws` shows the JWS host.

| Option | Meaning |
|--------|---------|
| `--profile customer` | Parts 1–4 (default) |
| `--profile full` | Parts 1–5 (with prod failure) |
| `--profile technical` | Parts 1, 3, 5 |
| `--acts LIST` | Comma-separated part numbers (overrides `--profile`) |
| `--preflight` | The pass/fail table, then exit |
| `--no-step` | Run each command as soon as it is typed |
| `--auto`, `--no-type` | No Enter at all; instant typing (CI) |

Each command is typed under a one-line caption and waits for **Enter** before it runs. You explain; the screen stays quiet. **Enter** at the end of a part moves to the next one.

## Part 1 — Triage

```bash
sepac triage tomcat
sepac triage shopapi
```

Say: before anyone writes policy, ask whether Red Hat already ships it. For Tomcat it does: a module is loaded. On this host the domain is unconfined (`situation=loaded_unconfined`), and sepac's advice is to install the vendor's confining package, not to write a second module. For shopapi there is nothing (`situation=none`): it is the only app we will write policy for.

## Part 2 — Inherited Tomcat: tune, don't write

```bash
for p in '' data.jsp gateway.jsp; do curl -s -o /dev/null -w "%{http_code} /inherited/$p\n" http://127.0.0.1:8090/inherited/$p; done
sepac denials tomcat --why
```

The first line is App B's traffic: the port, the data directory, the payment call. Then: what did SELinux block, and why? On this host, nothing. Distro `tomcat_t` does not confine, so there is nothing to fix and no policy to write.

On a JWS host the denials are real: `name_bind` on port 8090, a read on `user_home_t`, an outbound connect. `sepac tune tomcat` prints the fix for each. The script applies them (`semanage port -a`, `semanage fcontext` plus `restorecon`, the boolean `audit2why` named) and calls the three URLs again. Three host fixes, zero policy modules.

## Part 3 — shopapi: write policy from evidence

```bash
sepac status shopapi
```

shopapi runs as `shopapi_t` from a module that declares only its types, and the domain is permissive: SELinux logs what it would block and blocks nothing. The host is Enforcing.

```bash
sepac capture shopapi --full-audit
```

The evidence. sepac turns dontaudit rules off, restarts shopapi, calls every endpoint in its manifest (`/health`, `/state`, `/log`; not `/feature-spool`), puts dontaudit back, and summarises: dozens of denials, logged and not blocked, from a few distinct access needs.

```bash
sudo ausearch -m avc -ts boot | grep shopapi_t | audit2allow | grep -E 'passwd_file_t|execmem|bin_t'
```

The old way, for contrast. `audit2allow` turns every denial into an allow: read `/etc/passwd`, run anything labelled `bin_t`, writable and executable memory. Nobody reviewed any of it.

```bash
sepac generate shopapi
```

sepac works from the same evidence and stops: `execmem` lets the JVM write memory and then execute it, which is how injected code runs. It writes nothing, records the proposed rule and why, and prints the command a reviewer runs after deciding.

```bash
sepac generate shopapi --approve execmem --apply
```

The reviewer approves that one permission by name. Point out in the output: `/etc/passwd` is still **REFUSED**; running the JVM (`bin_t`) is accepted only because the manifest records a reviewed reason; most rules are Red Hat interfaces such as `kernel_read_system_state`, not raw allows; `AVC coverage OK` means every denial was handled.

```bash
sepac check shopapi
```

The same gate CI runs on the pull request: forbidden patterns, compile, and the semantic check against a throwaway copy of the policy store (no `setenforce`, no shadow, nothing beyond an empty control domain).

```bash
sepac load shopapi
```

Loaded on QA. Production never gets `semodule -i`; it gets the signed RPM.

## Part 4 — Enforce it

```bash
sepac load shopapi --enforcing
```

shopapi_t comes off the permissive list. The module is unchanged, so sepac skips the reload.

```bash
sepac capture shopapi --no-restart
```

Every known endpoint answers 200 under enforcement: the policy from Part 3 covers them. No denials.

```bash
sepac status shopapi
```

Host Enforcing, module matching the repo build, domain enforcing, labels ok.

Say: what runs next is `sepac build`, `sepac canary`, `sepac soak`, `sepac enforce`, `sepac rollback`. The two-host demo shows them live.

## Part 5 — A new feature hits production (optional)

*Show this part with `--profile full`. It adds about 8 minutes.*

A developer ships `/feature-spool`, which writes to `/var/spool/shopapi`. The policy has never seen that path.

```bash
sepac capture shopapi --no-restart --url /feature-spool
```

`/feature-spool` returns 500. Capture shows the denial: `{ open }` on `var_spool_t` for `/var/spool/shopapi/feature.log`. Confinement doing its job.

```bash
sepac load shopapi --permissive
```

Rollback: `shopapi_t` goes back to permissive so the service runs again. The host is still Enforcing. In production this would be `sepac rollback --env production`.

```bash
sepac capture shopapi --no-restart --url /feature-spool
```

`/feature-spool` returns 200 (permissive). The denial is logged, not blocked.

```bash
sepac generate shopapi --apply
```

Fix: the spool path becomes `shopapi_var_lib_t` — a **label**, not a wider rule. Allowing the generic `var_spool_t` would open every other program's spool.

```bash
sepac load shopapi --enforcing
```

Loads the fix, relabels `/var/spool/shopapi`, enforces.

```bash
sepac capture shopapi --no-restart --url /feature-spool
sepac status shopapi
```

200 everywhere. Host Enforcing, domain enforcing, labels ok. The host never left Enforcing.

## If something goes wrong

| What you see | Do |
|--------------|----|
| Preflight: `host role` FAIL | `echo qa \| sudo tee /etc/selinux-pac/role`, or re-run the bootstrap |
| Preflight: `shopapi_t is not permissive` | The VM ran the demo before: `bash lab/reset_demo_vms.sh --dev-only` |
| Preflight: App B port, label or boolean FAIL | Same reset. Part 2 would have nothing to show. |
| `sepac generate shopapi` in part 3 does not stop | Something already approved `execmem`: reset, and check `selinux/shopapi/shopapi.te` is the types-only seed |
| A yellow `exit N` under a command | The demo keeps going. Read the output; the next command usually explains it. |
