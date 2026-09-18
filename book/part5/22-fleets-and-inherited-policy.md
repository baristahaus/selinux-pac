# Fleets and Inherited Policy

> One host runs many applications, and each one wears its own domain. The problem is not running them — it is knowing who owns the policy for each one.

A host stops being a single-application machine the moment it picks up a second. Tomcat already ships policy for the JWS you inherit from a colleague, but your Spring Boot sidecar has never had a module. The Java process and the Python gateway each share a domain — `jws6_tomcat_t`, `unconfined_java_t`, or whatever label they inherited — and each denial is a different kind of surprise. This chapter is about placing ownership on every app, and about the pipeline that keeps each one honest as the fleet grows.

## The three situations for policy on one host

Every service on a host sits in exactly one of three situations. The situation decides who writes the module, what you may change, and where evidence comes from.

| Situation | Who owns policy | What you may change | Where evidence comes from |
|-----------|-----------------|---------------------|---------------------------|
| **Vendor** (JWS / EAP / httpd / named / postgresql) | the distribution or the vendor RPM | host commands (`semanage` / `setsebool` / `seport`); **no** `.te` | `ausearch` against the *vendor* domain; `--tune-report` prints the host commands, never a module |
| **Inherited** (Tomcat you inherited at /opt/appdata, port 8090, outbound gateway) | you are allowed to tune, but you still run on a shared vendor domain | host commands plus a label on your own paths; **no** vendor-module rewrite | `ausearch` against your own content and port — same vendor domain as the original install |
| **New** (Spring Boot / shopapi / your app) | you write the module from observed AVCs | full module; the generator refuses to generate until pre-flight classifies `none` | `ausearch` from a freshly confined domain; the generator applies `config/boolean_hints.yml` and `sesearch` before writing a direct allow |

App A is vendor-enforcing Tomcat. App B is Tomcat you inherited, running as the same `jws6_tomcat_t`, but its content lands at `/opt/appdata` and it speaks on port 8090. shopapi is the new thing — no vendor module, generate proceeds. **The same Tomcat domain covers both App A and App B**; if you need isolation, reach for containers or separate instances.

## The pre-flight and why a second copy is worse

Before `dev_generate_policy.sh` writes policy, it calls `check_vendor_policy()`. This is `scripts/lib/vendor_policy_check.sh`. It classifies the app into six situations, and only `none` proceeds to generation.

| Situation | `action` | Generator | What you do |
|-----------|----------|-----------|-------------|
| `loaded` | tune | exit non-zero | Vendor module in `semodule -l`; run `--tune-report`. Do not generate. |
| `package_installed` | enable | exit non-zero | Vendor SELinux RPM installed but module unloaded; install it. |
| `package_available` | install | exit non-zero | Vendor RPM in dnf cache; `dnf install` it. |
| `unconfined` | install | exit non-zero | Process is `unconfined_java_t` / `unconfined_service_t`; enable the module. |
| `base_policy` | tune | exit non-zero | `httpd`/`named`/`postgresql` covered by targeted policy; `--tune-report`. |
| `none` | generate | continues | No vendor/base module covers this app. |

The pre-flight is local: `semodule -l`, `rpm -qa`, `dnf --cacheonly`. No network call. `--force "reason"` bypasses when the app genuinely differs from the vendor one; bare `--force` is rejected, and the bypassed situation is recorded in `policy_out/findings.json`.

A second copy of a vendor module is worse than a missing rule because it gives you two sources of truth. The RPM update breaks you silently; you are reading a `jws6-tomcat-selinux` you wrote in your own repo; the vendor patch is invisible until it stops working. `vendor_policy_check.sh` catches the loaded situation; `--tune-report` gives you `semanage` commands for the vendor domain, never a `.te`.

## Adopting a new application

The pipeline onboards each new service through one script, one manifest, and one first generate cycle. `scripts/selinux_pac_adopt.sh` is the first command you run after the box is standing.

```bash
bash scripts/selinux_pac_adopt.sh doctor
bash scripts/selinux_pac_adopt.sh init <app_name>
```

`doctor` checks prerequisites (`getenforce`, `ausearch`, `sesearch`, `ansible-playbook`). `init <app_name>` emits six steps. The subcommands take one of two options:

| Option | Meaning |
|--------|---------|
| `--manifest PATH` | Manifest path; defaults to `config/<app_name>.manifest.yml` |
| `-h` / `--help` | usage screen |

The flow is:

1. **Copy the manifest template.** `cp config/payments.manifest.example.yml config/<app_name>.manifest.yml`. The template declares `app_name`, `domain`, `paths.install_root`, `paths.var_dir`, `paths.log_dir`, `paths.runtime_dir`, `services.primary.unit`, `http.host`, `http.port`, `http.endpoints`, `selinux_ports`, and optional `integration_tests.command`, `policy.module_dir`, and deploy marker/report file names. **Bind ports** go in the committed manifest; **probe hosts** change per environment.
2. **Scaffold policy.** `bash scripts/scaffold_sepolicy_module.sh <app_name> <app_name>_t` runs `sepolicy-generate` and drops starter `.te`, `.if`, and `.fc` into `selinux/<app_name>/`. It does not overwrite reviewed policy already in git.
3. **Validate the manifest.** `bash scripts/validate_app_manifest.sh config/<app_name>.manifest.yml`. This is what CI and Ansible rely on.
4. **Compile.** `POLICY_MODULE=<app_name> bash scripts/compile_and_validate.sh selinux/<app_name>`. Produces `<app_name>.pp` for `semodule -i`.
5. **Two-host lab.** `bash scripts/setup_rhel_hosts.sh write --qa-host … --prod-host …`.
6. **Canary on QA** via `ansible-playbook -i ansible/inventory.dev.yml ansible/deploy_canary.yml -e app_name=<app_name> …`.
7. **Prod canary / soak / enforce** with `-i ansible/inventory.production.yml`.

Every consumer — `cli/deterministic_gen.py`, `cli/soak_net_new.py`, the Ansible role, `validate_app_manifest.sh` — reads the manifest for paths, ports, domain, and probes. **Nothing silently assumes `myapp`**.

## Many domains on one host

A fleet is not one app per host — it is one host per app. Each app holds its own domain, its own `.te`, its own manifest, and its own soak. Per-domain permissive stays per domain: `semanage permissive -a shopapi_t` is independent of `semanage permissive -a jws6_tomcat_t`. The canary is per host group and per domain rather than per release — it answers "is this install time or net new?" at the domain level, which is why `cli/soak_net_new.py` reads the domain out of the manifest.

::: why The unit of risk is the domain, not the application artefact
Two apps sharing a domain share their fate. shopapi and App B both run on `jws6_tomcat_t`; a regression in the vendor policy for that domain affects both. When you add a service, own the domain — do not let it inherit a shared label whose policy was tuned only for the first owner.
:::

::: try Run the pre-flight and the adopt script on a laptop
Nothing here commits state. On macOS or any laptop:

```bash
bash scripts/demo_present.sh --dry-run --profile customer
bash scripts/selinux_pac_adopt.sh doctor
bash scripts/selinux_pac_adopt.sh init <app_name> --manifest /tmp/<app_name>.manifest.yml
```

Both exit without writing policy. The output is narration plus the expected host commands; no module, no JVM, no podman. On a real RHEL box, `--dry-run` is replaced by `--preflight` and a live `check_vendor_policy()` run.
:::

## Shared resources between applications

A port, a directory, or a socket two services both need is where fleet maintenance hurts most. The correct answer is always a narrow interface (refpolicy `.if`) or an explicit allow against a **named type** you own. The wrong answer is a generic shared type — `var_t`, `tmp_t`, or `etc_t` — because it lets any process read or write the resource, and because it decouples the access from the domain that actually asked.

| Shared resource | Correct answer | Wrong answer |
|-----------------|----------------|--------------|
| A private TCP port both services bind to | each module owns its own `_port_t`; `semanage port -a` registers each type | `http_port_t` or a generic port type that covers every process |
| A directory both apps write to | each app declares `_var_lib_t`; callers reach in via their own `_domain` allow | `var_lib_t` or `tmp_t` as a shared scratchpad |
| A Unix socket one service exposes to the other | an explicit `unix_stream_socket` allow against a private `_sock_t`; or a refpolicy interface the caller `gen_require`s | a generic `sock_file_t` with no domain binding |

A private type is the boundary that lets you audit every caller against every caller. `allow <caller>_t <caller>_var_lib_t:dir write;` tells you exactly who is allowed. `allow shopapi_t var_lib_t:dir write;` tells you nothing. The same applies to interfaces: each module calls the interface it wrote for itself; no one calls the interface they inherited from the first install.

::: note Interfaces are not a generic allow
Calling a refpolicy `.if` is the same as calling an explicit allow. The interface names a target type and a class; the audit review is identical. Read the `.if` and you read the allow.
:::

## Registers of applications

`config/registered_apps.example.yml` is the registry every soak loop reads against. Each entry names an `app_name` and the manifest it points to. Future tooling (`soak_exceptions_all.sh`, AAP loops) uses it to find which apps are soaking in which tiers without searching the filesystem.

```yaml
apps:
  - app_name: myapp
    manifest: config/myapp.manifest.yml
  - app_name: payments
    manifest: config/payments.manifest.example.yml
```

This is what keeps onboarding mechanical. When you onboard a new service, add the registry entry alongside the manifest. When you promote the manifest, you know the registry will update too. The registry does not gate anything — it names what is already standing.

## Scaling the pipeline

Adding a new app to the pipeline touches five things. Four of them are configuration; one is an artifact that already shipped.

| Change | What changes | What does not change |
|--------|--------------|----------------------|
| Manifest (`config/<app>.manifest.yml`) | new entry; bind ports, units, probes, domains | the format — every manifest consumes the same keys |
| Generator pre-flight | runs again for the new service; vendor/base classification | the six-situation table — the same situations apply |
| Policy CI | `forbidden-patterns`, `version-consistency` run on the new `selinux/<app>/` | the CI shape — each app gets the same gates |
| RPM set | one new `<app>-selinux` RPM per service | the packaging pipeline — `packaging/build_rpms.sh` and AAP |
| Inventory | `ansible/inventory.dev.yml` / `inventory.production.yml` grow a host entry | the Ansible role schema — `selinux_pac` loads the same manifest keys |

`policy_version.txt` under `selinux/<app>/` is each app's policy NVR. It is **not** shared with selinux-pac's tag; each service's module carries its own. The RPM build reads `policy_version.txt`, the manifest, and the module directory — everything else is configuration that stays the same.

## What you can do now

- Place each service on one of the three situations and read the ownership table.
- Run the vendor pre-flight before every generate: `check_vendor_policy()` classifies six situations; only `none` proceeds.
- Onboard each new service with `selinux_pac_adopt.sh doctor` and `init`, every consumer reading the manifest.
- Own every named type for shared resources; read the `.if` as the allow it is.
- Add each service to the registry and to each CI gate, RPM, and inventory with one line of configuration.
