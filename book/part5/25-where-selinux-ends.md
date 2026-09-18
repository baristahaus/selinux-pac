# Where SELinux Ends

> Every denial you read before Chapter 25 belongs to the layer it crosses. Chapter 25 lists the layers each owns, the failure each catches, and the failure each lets slip past. The book stops here.

## The layered picture

On a modern RHEL host, every operation crosses several independent decision layers before it lands. Each layer owns one question: this question is the only question that layer answers, and a failure of any other layer shows as something each layer does not see.

| Layer | Decision it owns | A failure it catches that the others miss |
|-------|------------------|-------------------------------------------|
| Classical Unix (DAC) | does this **user** own or belong to this **file**? | an admin running as `root` writes to a world-owned file that a developer would never have touched |
| Linux capabilities | does this **process** hold the required **capability bit**? | a process with no `CAP_NET_BIND_SERVICE` can still `bind()` on port 8080 without tripping DAC |
| SELinux | may this **domain** do this **permission** to this **type**? | `root` writes to a file whose label the policy forbids the domain to touch |
| seccomp / systemd hardening | does the unit already refuse the **syscall**? | a process with every allow the policy needs still cannot open `/dev/rtc` because `SystemCallFilter` already dropped the call |
| systemd hardening | does the unit already refuse the **privilege escalation**? | a process with all policy allows still cannot `execmem` because `CapabilityBoundingSet` already forbade it |
| Firewall / network policy | is this **network flow** permitted? | a policy-allowing process still cannot exfiltrate data because the flow is off-net |
| TLS / transport | is this **message** authenticated and integrity-checked? | a policy-allowing process still cannot be spoofed because the receiver verified the signature |
| Application authentication | is this **request** authorised against the user's identity? | a policy-allowing request still cannot be `GET /admin` because the app refused the token |
| Integrity / measurement | is this **object** unchanged from baseline? | a policy-allowing process still cannot `read` a file that has been modified off-line |

Each row is its own question, and each row's denial is the only denial the row sees — everything else the row is asked about, the row does not see.

:::: why The failure mode of this book's approach
Defence in depth means no single layer is asked to be sufficient; the failure mode of this book's approach is treating SELinux as the only control that matters — the policy allows, the application executes, the file is read, and we have not yet asked whether it was correct. The other layers cover each of those gaps.
::::

## What SELinux does not look at

The decision tuple is the whole model; there are five questions the tuple leaves deliberately out of scope.

| Question | Where it comes from | Why it is out of scope |
|----------|--------------------|------------------------|
| what is the **content** of the file or request? | the application semantics | the policy asks about *permission*, not *correctness* |
| is the **write** correct, or would a different write do? | the application state | the policy grants `write`, the application decides what it writes |
| is a **socket peer** trustworthy? | the application's transport-level trust | the policy decides whether the domain *initiates* the connection, not whether the peer is trusted |
| is an **authenticated user** authorised? | the application's authentication | the user has logged in; the domain has the allows; what they do is the application's responsibility |
| what are the **arguments** to the syscall beyond the mediated class and permission? | the VFS / socket layer | the LSM hook asks the tuple; the syscall's arguments are not visible to the policy |

A `write` is a `write` regardless of what it contains; a `name_bind` is a `name_bind` regardless of which port; a `connect` is a `connect` regardless of which peer. The policy's job is to own those four values; everything else is owned by a different layer. That is what "mandatory" means: the policy does not consult the semantics, only the tuple.

## A Linux capability vs a SELinux `capability`

Both exist. They are different mechanisms. Each lets the layer above it do something the user below it could not do.

| | Linux capability (bit) | SELinux `capability` class (rule) |
|---|---|---|
| Where it is | the process's capability set (`task_struct->cap_inh`, `cap_permitted`) | the loaded policy's `allow <domain> <domain>:capability { … };` |
| Set by | `setcap` / systemd `AmbientCapabilities=` / kernel | `.te`, `allow` |
| Decided by | the bit is set, the call passes | the rule exists, the tuple matches |
| Drops to | `CapabilityBoundingSet=` / `NoNewPrivileges=` / unit hardening | `audit2allow` removal / policy review |

A concrete example: **binding a privileged port**.

A process that wants to `bind()` to TCP port 443 needs three things. The kernel checks the capability bit: the process must hold `CAP_NET_BIND_SERVICE` in its permitted set. SELinux checks the policy: the domain must own `allow <domain> <domain>:capability net_bind_service;` and `allow <domain> <domain>:tcp_socket name_bind;` (because the socket itself is labelled). If a systemd unit carries `AmbientCapabilities=CAP_NET_BIND_SERVICE`, the kernel bit is set; if the unit also sets `CapabilityBoundingSet=~cap_net_bind_service`, the kernel bit is dropped, and the domain needs no policy allows. Dropping the capability is often the better fix: the process stops asking for it, SELinux never has to say `allow`.

::: why Always drop the capability before adding the allow
Before you add `allow myapp_t myapp_t:capability net_bind_service;` to the module, check whether the systemd unit still needs it. `CapabilityBoundingSet=~cap_net_bind_service` or `AmbientCapabilities=` is the fix; the policy allow is the symptom. The review in Part III catches both.
:::

## seccomp and systemd hardening

`SystemCallFilter=` and `NoNewPrivileges=` complement a policy module in one direction: the unit already refuses the operations that the policy would have to allow. A unit that drops privileges needs fewer allows, because the unit owns the denial; the policy covers only what the unit did not already refuse.

A unit with `SystemCallFilter=~@clock @debug @mount @raw_io @signal @cpu @module @filesystem @network @user` refuses every syscall the policy would need to allow; a unit with `ProtectSystem=strict` refuses every directory the policy would need to label. Read the unit before writing allows — [§3 of *Designing a Domain*](../part2/11-designing-a-domain.md) explains the trade-off, and the repo's `init_daemon_domain` interface stands for each block of review it expands to.

When both are in play, who removes which denial? The unit's denial lands first: if `SystemCallFilter` refuses the call, the kernel does not reach SELinux. If SELinux refuses the tuple, the unit's denial is already silent — the policy allows, the unit allows, the call completes. Each layer owns the call the next layer does not see. That is why `systemctl cat <unit>` before `sesearch` is the single most expensive command in the playbook.

:::: try Inspect your host's hardening surface
Nothing changes state; each command surfaces one directive.

```bash
# Each directive that reduces the policy surface for sshd:
$ systemctl cat sshd.service | grep -E '^(NoNewPrivileges|SystemCallFilter|CapabilityBoundingSet|ProtectSystem|ProtectHome|PrivateTmp)='

# Each directive that reduces the policy surface for any unit you own:
$ grep -hE '^(NoNewPrivileges|SystemCallFilter|CapabilityBoundingSet|ProtectSystem|ProtectHome|PrivateTmp|RuntimeDirectory|StateDirectory|LogsDirectory)=' /etc/systemd/system/*.service /lib/systemd/system/*.service
```

Each line you find is the reason the policy needs fewer allows. The unit tells the policy what paths exist and what access the process already lost.

*Directives documented in `systemd.exec(5)` and `systemd.service(5)`.*
::::

## AppArmor and SMACK

AppArmor is path-based: the profile lists paths (`/usr/sbin/apache2`, `/etc/apache2/*`) and the kernel asks each operation against those paths. The profile reads like a file listing and ships on Debian and Ubuntu distributions as the default LSM. AppArmor is good at: environments where a single binary has a single profile, and the sysad remembers each path.

SMACK is a minimal LSM: one attribute per process and per file, and the attribute is the only decision. The kernel ships it; Mobile Nethack and Sailfish OS use it as the default. SMACK is good at: environments where trust is binary — a process and a file each carry one attribute, and that attribute is the only decision.

This book teaches SELinux for RHEL because RHEL ships with SELinux as the default, the policy module model is code, the review-gate model in Part III is built around it, and the type-based isolation fits the distribution's threat model. AppArmor and SMACK are each the right design for a different distribution; the choice is the distribution, not the algorithm.

## Policy modules are code

A policy module has an author, a version, a review, a supply chain. `selinux/policy_version.txt` is the version; `selinux/myapp.te` is the author; the PR is the review; `myapp-selinux-1.4.0-1.rpm` is the supply chain. A module that is too wide is a vulnerability — every rule that is wider than the tuple is a rule that is not reviewed. A module that is never reviewed is an unknown — the `allow shopapi_t var_t:file write;` that no one ever read.

The review gates in Part III — `forbidden-patterns`, `version-consistency`, `validate_policy_semantics.sh`, `validate_forbidden_patterns.sh` — each owns one of those properties. Each gate's refusal is the only failure the gate catches; each gate's pass is the only claim the gate makes. A module that passes every gate is not a module that is correct; it is a module that is not *found* to be incorrect — every module that is correct passes every gate, and every module that is incorrect fails at least one.

::: note The review gates are the delivery
A policy module that is written, compiled, reviewed and packaged is not "policy". It is code that has a version, an author, and a review. A module that is installed in production is every bit as important as the application it protects.
:::

## Three AVCs, three owning layers

Each AVC is a tuple. The tuple names the layer that owns the failure. The failure you fix depends on that layer.

### Scenario 1 — application behaviour

```text
avc: denied { write } for pid=4123 comm="report" name="audit"
  scontext=system_u:system_r:report_t:s0
  tcontext=system_u:object_r:auditd_log_t:s0
  tclass=file permissive=0
```

The domain wants to write to the host's `auditd` log. The owning layer is the **application**: the report process is writing to a file that the policy already labels as `auditd_log_t`, but the policy does not allow `report_t` to write there. Fix: check whether the application really needs to write to `auditd_log_t` — or whether the operator is writing to the wrong destination.

### Scenario 2 — unit hardening

```text
avc: denied { connect } for pid=891 comm="myapp" scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:system_r:backend_t:s0 tclass=tcp_socket permissive=0
```

The domain tries to `connect` to `backend_t` on a TCP socket. The owning layer is the **systemd unit**: the unit's `SystemCallFilter` refuses `@network`, so the call never reaches SELinux — the `connect` would fail even with a policy allow. Fix: relax `SystemCallFilter` to allow the connection, or label the call path as `@db` and let `@network` remain closed.

### Scenario 3 — authentication

```text
avc: denied { name_connect } for pid=2048 comm="shopapi" daddr=10.0.0.5 dport=443 scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0
```

The domain connects to `10.0.0.5` on TCP 443. The owning layer is the **firewall**: the policy allows `name_connect`, the unit allows the call, but the firewall refuses the flow. Fix: add the host to the allow-list on the firewall, or confirm that the call is the right one.

Each scenario names the layer. Each layer owns the fix.

## What you can do now

- read any AVC and say which layer owns the failure
- list every layer that still has a decision about the operation
- inspect a unit and name each directive that reduces the policy surface
- tell the difference between a Linux capability and a SELinux `capability` allow
- read a policy module as code: author, version, review, supply chain
- decide that the review gates are the delivery, not the development
- draw the line: "SELinux is not the only control that matters — the failure mode of this book's approach is treating SELinux as the only control that matters"
