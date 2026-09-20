# Fleets and Inherited Policy

> One host runs many applications, and each one wears its own domain. The problem is not running them. It is knowing who owns the policy for each one.

A host stops being a single-application machine the moment it picks up a second. Tomcat already ships policy for the JWS you inherit from a colleague, but your Spring Boot sidecar has never had a module. The Java process and the Python gateway each share a domain: `jws6_tomcat_t`, `unconfined_java_t`, or whatever label they inherited. Each denial is a different kind of surprise. This chapter is about placing ownership on every app, and about the pipeline that keeps each one honest as the fleet grows.

## The three situations for policy on one host

Every service on a host sits in exactly one of three situations. The situation decides who writes the module, what you can change, and where the evidence comes from.

| Situation | Who owns policy | What you can change | Where the evidence comes from |
|-----------|-----------------|---------------------|---------------------------|
| **Vendor** (JWS / EAP / httpd / named / postgresql) | the distribution or the vendor RPM | host commands (`semanage` / `setsebool` / `seport`). There is no `.te`. | `ausearch` against the vendor domain. `--tune-report` prints the host commands, never a module |
| **Inherited** (Tomcat you inherited at /opt/appdata, port 8090, outbound gateway) | you are allowed to tune, but you still run on a shared vendor domain | host commands plus a label on your own paths. Do not rewrite the vendor module. | `ausearch` against your own content and port, on the same vendor domain as the original install |
| **New** (Spring Boot / shopapi / your app) | you write the module from observed AVCs | the full module. The generator refuses to generate until the pre-flight classifies `none`. | `ausearch` from a freshly confined domain. The generator applies `config/boolean_hints.yml` and `sesearch` before it writes a direct allow |

App A is vendor-enforcing Tomcat. App B is Tomcat you inherited, running as the same `jws6_tomcat_t`, but its content lands at `/opt/appdata` and it speaks on port 8090. shopapi is the new thing: no vendor module, so generation proceeds. The same Tomcat domain covers both App A and App B. If you need isolation, use containers or separate instances.

## The pre-flight and why a second copy is worse

Before `dev_generate_policy.sh` writes policy, it calls `check_vendor_policy()`. This is `scripts/lib/vendor_policy_check.sh`. It classifies the app into six situations, and only `none` proceeds to generation.

| Situation | `action` | Generator | What you do |
|-----------|----------|-----------|-------------|
| `loaded` | tune | exit non-zero | A vendor module is in `semodule -l`. Run `--tune-report`. Do not generate. |
| `package_installed` | enable | exit non-zero | The vendor SELinux RPM is installed, but the module is unloaded. Install it. |
| `package_available` | install | exit non-zero | The vendor RPM is in the dnf cache. Install it with `dnf install`. |
| `unconfined` | install | exit non-zero | The process is `unconfined_java_t` / `unconfined_service_t`. Enable the module. |
| `base_policy` | tune | exit non-zero | `httpd`/`named`/`postgresql` are covered by targeted policy. Run `--tune-report`. |
| `none` | generate | continues | No vendor/base module covers this app. |

The pre-flight is local: `semodule -l`, `rpm -qa`, `dnf --cacheonly`. It makes no network call. If the app really differs from the vendor one, `--force "reason"` bypasses the check. A bare `--force` is rejected, and the bypass is recorded in `policy_out/findings.json`.

A second copy of a vendor module is worse than a missing rule, because it gives you two sources of truth. The RPM update breaks you without a signal. You read a `jws6-tomcat-selinux` that you wrote in your own repo. The vendor patch stays invisible until it stops working. `vendor_policy_check.sh` catches the loaded situation. `--tune-report` gives you `semanage` commands for the vendor domain, never a `.te`.

## Adopting a new application

The pipeline onboards each new service through one script, one manifest, and one first generate cycle. `scripts/selinux_pac_adopt.sh` is the first command you run after the box is standing.

```bash
bash scripts/selinux_pac_adopt.sh doctor
bash scripts/selinux_pac_adopt.sh init <app_name>
```

`doctor` checks prerequisites (`getenforce`, `ausearch`, `sesearch`, `ansible-playbook`). `init <app_name>` emits seven steps (manifest, scaffold, validate, compile, two-host lab, canary on QA, prod canary/soak/enforce). The subcommands take one of two options:

| Option | Meaning |
|--------|---------|
| `--manifest PATH` | Manifest path. It defaults to `config/<app_name>.manifest.yml` |
| `-h` / `--help` | usage screen |

The flow is:

1. **Copy the manifest template.** `cp config/payments.manifest.example.yml config/<app_name>.manifest.yml`. The template declares the required keys: `app_name`, `domain`, `paths.install_root`, `paths.var_dir`, `paths.log_dir`, `paths.runtime_dir`, and `services.primary.unit`. It also declares `http.host`, `http.port`, `http.endpoints`, and `selinux_ports`. The optional keys are `integration_tests.command`, `policy.module_dir`, and the deploy marker and report file names. Bind ports go in the committed manifest. Probe hosts change per environment.
2. **Scaffold policy.** `bash scripts/scaffold_sepolicy_module.sh <app_name> <app_name>_t` runs `sepolicy-generate` and drops starter `.te`, `.if`, and `.fc` into `selinux/<app_name>/`. It does not overwrite reviewed policy already in git.
3. **Validate the manifest.** `bash scripts/validate_app_manifest.sh config/<app_name>.manifest.yml`. This is what CI and Ansible rely on.
4. **Compile.** `POLICY_MODULE=<app_name> bash scripts/compile_and_validate.sh selinux/<app_name>`. Produces `<app_name>.pp` for `semodule -i`.
5. **Two-host lab.** `bash scripts/setup_rhel_hosts.sh write --qa-host … --prod-host …`.
6. **Canary on QA** via `ansible-playbook -i ansible/inventory.dev.yml ansible/deploy_canary.yml -e app_name=<app_name> …`.
7. **Prod canary / soak / enforce** with `-i ansible/inventory.production.yml`.

Every consumer reads the manifest for paths, ports, domain, and probes: `cli/deterministic_gen.py`, `cli/soak_net_new.py`, the Ansible role, and `validate_app_manifest.sh`. Nothing silently assumes `myapp`.

## Many domains on one host

A fleet is not one app per host. It is one host per app. Each app holds its own domain, its own `.te`, its own manifest, and its own soak. Per-domain permissive stays per domain: `semanage permissive -a shopapi_t` is independent of `semanage permissive -a jws6_tomcat_t`. The canary is per host group and per domain, not per release. It answers "is this install time or net new?" at the domain level, and that is why `cli/soak_net_new.py` reads the domain out of the manifest.

::: why The unit of risk is the domain, not the application artifact
Two apps that share a domain share their fate. App A and App B both run on `jws6_tomcat_t`, so a regression in the vendor policy for that domain affects both. shopapi is the opposite case. It owns `shopapi_t`, and the whole chapter is about keeping it that way. When you add a service, own the domain. Do not let it inherit a shared label whose policy was tuned only for the first owner.
:::

::: try Run the pre-flight and the adopt script on a laptop
Nothing here commits state. On macOS or any laptop:

```bash
bash scripts/demo_present.sh --dry-run --profile customer
bash scripts/selinux_pac_adopt.sh doctor
bash scripts/selinux_pac_adopt.sh init <app_name> --manifest /tmp/<app_name>.manifest.yml
```

Both exit without writing policy. The output is narration plus the expected host commands. There is no module, no JVM, and no podman. Those are the laptop forms. On a real RHEL host, the demo replaces `--dry-run` with `--preflight`. That pass checks the host and exits, over `getenforce`, the unit, the label of App A, and its ports. `dev_generate_policy.sh` then runs `check_vendor_policy()` live before it writes anything.
:::

## Shared resources between applications

A port, a directory, or a socket that two services both need is where fleet maintenance hurts most. The correct answer is always a narrow interface (refpolicy `.if`) or an explicit allow against a named type you own. The wrong answer is a generic shared type: `var_t`, `tmp_t`, or `etc_t`. It is wrong because any process can then read or write the resource. It is also wrong because it decouples the access from the domain that really asked for it.

| Shared resource | Correct answer | Wrong answer |
|-----------------|----------------|--------------|
| A private TCP port both services bind to | each module owns its own `_port_t`, and `semanage port -a` registers each type | `http_port_t` or a generic port type that covers every process |
| A directory both apps write to | each app declares `_var_lib_t`, and callers reach in through their own `_domain` allow | `var_lib_t` or `tmp_t` as a shared scratchpad |
| A Unix socket that one service exposes to the other | an explicit `unix_stream_socket` allow against a private `_sock_t`, or a refpolicy interface that the caller `gen_require`s | a generic `sock_file_t` with no domain binding |

A private type is the boundary that lets you audit every caller against every caller. `allow <caller>_t <caller>_var_lib_t:dir write;` tells you exactly who is allowed. `allow shopapi_t var_lib_t:dir write;` tells you nothing. The same rule applies to interfaces: each module calls the interface that it wrote for itself. Nobody calls an interface inherited from the first install.

::: note Interfaces are not a generic allow
Calling a refpolicy `.if` is the same as calling an explicit allow. The interface names a target type and a class. The audit review is identical. If you read the `.if`, you read the allow.
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

This is what keeps onboarding mechanical. When you onboard a new service, add the registry entry alongside the manifest. When you promote the manifest, you know the registry will update too. The registry does not gate anything. It names what is already standing.

## Scaling the pipeline

Adding a new app to the pipeline touches five things. Four of them are configuration, and one is an artifact that already shipped.

| Change | What changes | What does not change |
|--------|--------------|----------------------|
| Manifest (`config/<app>.manifest.yml`) | a new entry: bind ports, units, probes, domains | the format. Every manifest consumes the same keys |
| Generator pre-flight | it runs again for the new service, with the vendor/base classification | the six-situation table. The same situations apply |
| Policy CI | one added line per app in `.github/workflows/selinux-policy-ci.yml`: `POLICY_MODULE=<app> SELINUX_DOMAIN=<app>_t bash scripts/validate_forbidden_patterns.sh selinux/<app>` | the gate script and its twelve refusals. The workflow does not discover module directories by itself |
| RPM set | one new `<app>-selinux` RPM per service | the packaging pipeline: `packaging/build_rpms.sh` and AAP |
| Inventory | `ansible/inventory.dev.yml` / `inventory.production.yml` grow a host entry | the Ansible role schema. `selinux_pac` loads the same manifest keys |

`policy_version.txt` under `selinux/<app>/` is the policy NVR of each app. It is not shared with the tag of selinux-pac. The module of each service carries its own. The RPM build reads `policy_version.txt`, the manifest, and the module directory. Everything else is configuration that stays the same.

## What you can do now

- Place each service on one of the three situations and read the ownership table.
- Run the vendor pre-flight before every generate. `check_vendor_policy()` classifies six situations, and only `none` proceeds.
- Onboard each new service with `selinux_pac_adopt.sh doctor` and `init`. Every consumer then reads the manifest.
- Own every named type for shared resources. Read the `.if` as the allow it is.
- Add each service to the registry and to each CI gate, RPM, and inventory with one line of configuration.
