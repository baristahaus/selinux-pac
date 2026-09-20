# Where SELinux Ends

> Every denial you read before Chapter 25 belongs to the layer it crosses. Chapter 25 lists the layers each owns, the failure each catches, and the failure each lets slip past. The book stops here.

## The layered picture

On a modern RHEL host, every operation crosses several independent decision layers before it lands. Each layer owns one question. That question is the only question that layer answers. A failure of any other layer shows as something that layer does not see.

| Layer | Decision it owns | A failure it catches that the others miss |
|-------|------------------|-------------------------------------------|
| Classical Unix (DAC) | does this user own or belong to this file? | an admin running as `root` writes to a world-owned file that no developer touched |
| Linux capabilities | does this process hold the required capability bit? | a process with no `CAP_NET_BIND_SERVICE` can still `bind()` on port 8080 without tripping DAC |
| SELinux | can this domain do this permission to this type? | `root` writes to a file whose label the policy forbids the domain to touch |
| seccomp / systemd hardening | does the unit already refuse the syscall? | a process with every allow the policy needs still cannot open `/dev/rtc`, because `SystemCallFilter` already dropped the call |
| systemd hardening | does the unit already refuse the privilege escalation? | a process with all policy allows still cannot `execmem`, because `CapabilityBoundingSet` already forbade it |
| Firewall / network policy | is this network flow permitted? | a policy-allowing process still cannot exfiltrate data, because the flow is off-net |
| TLS / transport | is this message authenticated and integrity-checked? | a policy-allowing process still cannot be spoofed, because the receiver checked the signature |
| Application authentication | is this request authorized against the identity of the user? | a policy-allowing request still cannot be `GET /admin`, because the app refused the token |
| Integrity / measurement | is this object unchanged from the baseline? | a policy-allowing process still cannot `read` a file that someone modified off-line |

Each row is its own question, and the denial of that row is the only denial the row sees. The row does not see anything else it is asked about.

:::: why The failure mode of this book's approach
Defense in depth means no single layer is asked to be sufficient. The failure mode of this book's approach is to treat SELinux as the only control that matters. Then the policy allows, the application executes, the file is read, and nobody has asked whether it was correct. The other layers cover each of those gaps.
::::

## What SELinux does not look at

The decision tuple is the whole model. There are five questions that the tuple leaves deliberately out of scope.

| Question | Where it comes from | Why it is out of scope |
|----------|--------------------|------------------------|
| what is the content of the file or request? | the application semantics | the policy asks about permission, not correctness |
| is the write correct, or is a different write the right one? | the application state | the policy grants `write`, and the application decides what it writes |
| is a socket peer trustworthy? | the transport-level trust of the application | the policy decides whether the domain initiates the connection, not whether the peer is trusted |
| is an authenticated user authorized? | the authentication of the application | the user has logged in, and the domain has the allows. What the user does is the responsibility of the application. |
| what are the arguments to the syscall beyond the mediated class and permission? | the VFS / socket layer | the LSM hook asks the tuple, and the arguments of the syscall are not visible to the policy |

A `write` is a `write` whatever it contains. A `name_bind` is a `name_bind` whatever the port. A `connect` is a `connect` whatever the peer. The job of the policy is to own those four values. A different layer owns everything else. That is what "mandatory" means: the policy does not consult the semantics, only the tuple.

## A Linux capability vs a SELinux `capability`

Both exist. They are different mechanisms. Each lets the layer above it do something the user below it cannot do.

| | Linux capability (bit) | SELinux `capability` class (rule) |
|---|---|---|
| Where it is | the process's capability set (`task_struct->cap_inh`, `cap_permitted`) | the loaded policy's `allow <domain> <domain>:capability { … };` |
| Set by | `setcap` / systemd `AmbientCapabilities=` / kernel | `.te`, `allow` |
| Decided by | the bit is set, the call passes | the rule exists, the tuple matches |
| Drops to | `CapabilityBoundingSet=` / `NoNewPrivileges=` / unit hardening | `audit2allow` removal / policy review |

A concrete example: binding a privileged port.

A process that wants to `bind()` to TCP port 443 needs three things. The kernel checks the capability bit: the process must hold `CAP_NET_BIND_SERVICE` in its permitted set. SELinux checks the policy: the domain must own `allow <domain> <domain>:capability net_bind_service;` and `allow <domain> <domain>:tcp_socket name_bind;` (because the socket itself is labeled). If a systemd unit carries `AmbientCapabilities=CAP_NET_BIND_SERVICE`, the kernel sets the bit. If the unit instead sets `CapabilityBoundingSet=~cap_net_bind_service`, the bit is gone. The process can no longer bind 443 at all, and it needs no policy allow, because the request itself is gone. Dropping the capability is often the better fix: the process stops asking for it, and SELinux never has to say `allow`.

::: why Always drop the capability before adding the allow
Before you add `allow myapp_t myapp_t:capability net_bind_service;` to the module, check whether the systemd unit still needs it. `CapabilityBoundingSet=~cap_net_bind_service` or `AmbientCapabilities=` is the fix. The policy allow is the symptom. The review in Part III catches both.
:::

## seccomp and systemd hardening

`SystemCallFilter=` and `NoNewPrivileges=` complement a policy module in one direction: the unit already refuses the operations that the policy needs to allow. A unit that drops privileges needs fewer allows, because the unit owns the denial. The policy covers only what the unit did not already refuse.

A unit with `SystemCallFilter=~@clock @debug @mount @raw-io @signal @cpu-emulation @module @file-system @network-io @privileged` refuses every syscall that the policy needs to allow. A unit with `ProtectSystem=strict` refuses every directory that the policy needs to label. Read the unit before you write allows. [§3 of *Designing a Domain*](../part2/11-designing-a-domain.md) explains the trade-off. The `init_daemon_domain` interface in the repo stands for each block of review that it expands to.

When both are in play, who removes which denial? The denial of the unit lands first: if `SystemCallFilter` refuses the call, the kernel does not reach SELinux. If SELinux refuses the tuple, the denial of the unit is already silent. The policy allows, the unit allows, and the call completes. Each layer owns the call that the next layer does not see. That is why `systemctl cat <unit>` before `sesearch` is the single most expensive command in the playbook.

:::: try Inspect your host's hardening surface
Nothing changes state. Each command surfaces one directive.

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

SMACK is a minimal LSM: one attribute per process and per file, and the attribute is the only decision. The kernel ships it, and Tizen and Sailfish OS use it as the default. SMACK is good at: environments where trust is binary. A process and a file each carry one attribute, and that attribute is the only decision.

This book teaches SELinux for RHEL for four reasons. RHEL ships with SELinux as the default. The policy module model is code. The review-gate model in Part III is built around that model. And the type-based isolation fits the threat model of the distribution. AppArmor and SMACK are each the right design for a different distribution. The choice is the distribution, not the algorithm.

## Policy modules are code

A policy module has an author, a version, a review, and a supply chain. `selinux/policy_version.txt` is the version, `selinux/myapp.te` is the author, the PR is the review, and `myapp-selinux-1.4.0-1.rpm` is the supply chain. A module that is too wide is a vulnerability: every rule that is wider than the tuple is a rule that nobody reviewed. A module that is never reviewed is an unknown: the `allow shopapi_t var_t:file write;` that nobody ever read.

The review gates in Part III each own one of those properties: `forbidden-patterns`, `version-consistency`, `validate_policy_semantics.sh`, and `validate_forbidden_patterns.sh`. The refusal of each gate is the only failure that gate catches, and the pass of each gate is the only claim that gate makes. A module that passes every gate is not a module that is correct. It is a module that was not *found* to be incorrect. Every module that is correct passes every gate, and every module that is incorrect fails at least one.

::: note The review gates are the delivery
A policy module that is written, compiled, reviewed and packaged is not "policy". It is code that has a version, an author, and a review. A module that is installed in production is every bit as important as the application it protects.
:::

## Three failures, three owning layers

Each layer leaves its own evidence. Read the evidence, and the owning layer names itself. The fix belongs to that layer, not to the one you were paged about.

### Scenario 1 — the policy, and then the application

```text
avc: denied { write } for pid=4123 comm="report" name="audit"
  scontext=system_u:system_r:report_t:s0
  tcontext=system_u:object_r:auditd_log_t:s0
  tclass=file permissive=0
```

An AVC exists, so the kernel decision that said no was SELinux's: `report_t` has no allow to write `auditd_log_t`. The policy owns the denial, and the application owns the question behind it. Does the report process really have to write into the audit log of the host? Or is the destination wrong? Fix the destination, and no allow is needed. Add `allow report_t auditd_log_t:file write;` and the write is permitted forever. The denial is the policy's, and the correct fix is often the application's.

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

The call fails with `EPERM`, and audit.log holds nothing. SELinux never saw it, because the kernel did not reach the LSM. `SystemCallFilter=~@network-io` dropped the syscall first, so the owning layer is the systemd unit. Note the second line. Without `SystemCallErrorNumber=EPERM`, the filter kills the process with `SIGSYS` instead of handing back an errno. The journal then shows a core dump, not this message. Fix it either way: remove `@network-io` from the deny list for a unit that needs the network, or drop the network need. Do not go looking for an allow that cannot exist.

### Scenario 3 — the firewall (no AVC)

```text
$ curl -sS -m 5 https://10.0.0.5/health
curl: (7) Failed to connect to 10.0.0.5 port 34567: No route to host

$ ausearch -m avc -ts recent
<no matches>

$ sesearch -A -s shopapi_t -c tcp_socket -p name_connect | head -n 1
allow shopapi_t unreserved_port_t:tcp_socket name_connect;
```

The policy allows `name_connect` to the port type, and that type is every port the policy leaves unlabeled, not just this one. So no AVC was written, the unit has no syscall filter, and the packet never leaves. `No route to host` is a `REJECT` rule answering. A `DROP` shows as a timeout instead. The owning layer is the firewall. Fix it: add the peer to the allow-list on the firewall. If that coarse port-type grant worries you, narrow it in the manifest to the own port type of the application. Then check that the call is the right one in the first place.

Each scenario names the layer. Each layer owns the fix.

## What you can do now

- Read any failure (an AVC, an `EPERM` with an empty audit log, or a refused flow) and say which layer owns it.
- List every layer that still has a decision about the operation.
- Inspect a unit and name each directive that reduces the policy surface.
- Tell the difference between a Linux capability and a SELinux `capability` allow.
- Read a policy module as code: author, version, review, supply chain.
- Decide that the review gates are the delivery, not the development.
- Draw the line: "SELinux is not the only control that matters. The failure mode of this book's approach is treating SELinux as the only control that matters."
