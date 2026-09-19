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

A process that wants to `bind()` to TCP port 443 needs three things. The kernel checks the capability bit: the process must hold `CAP_NET_BIND_SERVICE` in its permitted set. SELinux checks the policy: the domain must own `allow <domain> <domain>:capability net_bind_service;` and `allow <domain> <domain>:tcp_socket name_bind;` (because the socket itself is labelled). If a systemd unit carries `AmbientCapabilities=CAP_NET_BIND_SERVICE`, the kernel bit is set; if the unit instead sets `CapabilityBoundingSet=~cap_net_bind_service`, the bit is gone — the process can no longer bind 443 at all, and no policy allow is needed because the request itself is gone. Dropping the capability is often the better fix: the process stops asking for it, and SELinux never has to say `allow`.

::: why Always drop the capability before adding the allow
Before you add `allow myapp_t myapp_t:capability net_bind_service;` to the module, check whether the systemd unit still needs it. `CapabilityBoundingSet=~cap_net_bind_service` or `AmbientCapabilities=` is the fix; the policy allow is the symptom. The review in Part III catches both.
:::

## seccomp and systemd hardening

`SystemCallFilter=` and `NoNewPrivileges=` complement a policy module in one direction: the unit already refuses the operations that the policy would have to allow. A unit that drops privileges needs fewer allows, because the unit owns the denial; the policy covers only what the unit did not already refuse.

A unit with `SystemCallFilter=~@clock @debug @mount @raw-io @signal @cpu-emulation @module @file-system @network-io @privileged` refuses every syscall the policy would need to allow; a unit with `ProtectSystem=strict` refuses every directory the policy would need to label. Read the unit before writing allows — [§3 of *Designing a Domain*](../part2/11-designing-a-domain.md) explains the trade-off, and the repo's `init_daemon_domain` interface stands for each block of review it expands to.

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

SMACK is a minimal LSM: one attribute per process and per file, and the attribute is the only decision. The kernel ships it; Tizen and Sailfish OS use it as the default. SMACK is good at: environments where trust is binary — a process and a file each carry one attribute, and that attribute is the only decision.

This book teaches SELinux for RHEL because RHEL ships with SELinux as the default, the policy module model is code, the review-gate model in Part III is built around it, and the type-based isolation fits the distribution's threat model. AppArmor and SMACK are each the right design for a different distribution; the choice is the distribution, not the algorithm.

## Policy modules are code

A policy module has an author, a version, a review, a supply chain. `selinux/policy_version.txt` is the version; `selinux/myapp.te` is the author; the PR is the review; `myapp-selinux-1.4.0-1.rpm` is the supply chain. A module that is too wide is a vulnerability — every rule that is wider than the tuple is a rule that is not reviewed. A module that is never reviewed is an unknown — the `allow shopapi_t var_t:file write;` that no one ever read.

The review gates in Part III — `forbidden-patterns`, `version-consistency`, `validate_policy_semantics.sh`, `validate_forbidden_patterns.sh` — each owns one of those properties. Each gate's refusal is the only failure the gate catches; each gate's pass is the only claim the gate makes. A module that passes every gate is not a module that is correct; it is a module that is not *found* to be incorrect — every module that is correct passes every gate, and every module that is incorrect fails at least one.

::: note The review gates are the delivery
A policy module that is written, compiled, reviewed and packaged is not "policy". It is code that has a version, an author, and a review. A module that is installed in production is every bit as important as the application it protects.
:::

## Three failures, three owning layers

Each layer leaves its own evidence. Read the evidence and the owning layer names itself — the fix belongs to that layer, not to the one you were paged about.

### Scenario 1 — the policy, and then the application

```text
avc: denied { write } for pid=4123 comm="report" name="audit"
  scontext=system_u:system_r:report_t:s0
  tcontext=system_u:object_r:auditd_log_t:s0
  tclass=file permissive=0
```

An AVC exists, so the kernel decision that said no was SELinux's: `report_t` has no allow to write `auditd_log_t`. The **policy** owns the denial — and the application owns the question behind it: does the report process really have to write into the host's audit log, or is the destination wrong? Fix the destination and no allow is needed; add `allow report_t auditd_log_t:file write;` and the write is permitted forever. The denial is the policy's; the correct fix is often the application's.

### Scenario 2 — unit hardening (no AVC)

```text
$ ausearch -m avc -ts recent
<no matches>

$ journalctl -u myapp -n 1 --no-pager
myapp[891]: connect to 10.0.0.5:5432 failed: Operation not permitted

$ systemctl cat myapp | grep -E 'SystemCallFilter|SystemCallErrorNumber'
SystemCallFilter=~@clock @debug @network-io @privileged
SystemCallErrorNumber=EPERM
```

The call fails with `EPERM` and **audit.log holds nothing** — SELinux never saw it, because the kernel did not reach the LSM. `SystemCallFilter=~@network-io` dropped the syscall first, so the owning layer is the **systemd unit**. Note the second line: without `SystemCallErrorNumber=EPERM` the filter kills the process with `SIGSYS` instead of handing back an errno — the journal then shows a core dump, not this message. Fix either way: remove `@network-io` from the deny list for a unit that needs the network, or drop the network need — do not go looking for an allow that cannot exist.

### Scenario 3 — the firewall (no AVC)

```text
$ curl -sS -m 5 https://10.0.0.5/health
curl: (7) Failed to connect to 10.0.0.5 port 34567: No route to host

$ ausearch -m avc -ts recent
<no matches>

$ sesearch -A -s shopapi_t -c tcp_socket -p name_connect | head -n 1
allow shopapi_t unreserved_port_t:tcp_socket name_connect;
```

The policy allows `name_connect` to the port type — to *every* port the policy leaves unlabelled, not just this one — so no AVC was written; the unit has no syscall filter; and the packet never leaves. `No route to host` is a `REJECT` rule answering; a `DROP` shows as a timeout instead. The owning layer is the **firewall**. Fix: add the peer to the allow-list on the firewall — or, if that coarse port-type grant is uncomfortable, narrow it to the application's own port type in the manifest — and confirm that the call is the right one in the first place.

Each scenario names the layer. Each layer owns the fix.

## What you can do now

- read any failure — an AVC, an `EPERM` with an empty audit log, a refused flow — and say which layer owns it
- list every layer that still has a decision about the operation
- inspect a unit and name each directive that reduces the policy surface
- tell the difference between a Linux capability and a SELinux `capability` allow
- read a policy module as code: author, version, review, supply chain
- decide that the review gates are the delivery, not the development
- draw the line: "SELinux is not the only control that matters — the failure mode of this book's approach is treating SELinux as the only control that matters"
