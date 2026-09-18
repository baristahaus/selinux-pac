# Ports, Booleans and Transitions

> Port types, port assignments, booleans and the exec-time transition are the four mechanisms an
> application policy reaches for before a service can run. Each lives somewhere different — the
> policy module, the host, the committed manifest — and each is a place where environments
> quietly drift apart.

## Why a bind is denied

Every time a process opens a socket, the kernel does not ask the process about its identity. It asks the socket about its target type.

The socket inherits the type of the port it binds to. Bind on port 8888 is a `name_bind` on `tcp_socket` against `unreserved_port_t` — a generic, unlabelled type — and the policy denies because a rule against a generic port type is a rule you cannot defend.

A shared port type covers the whole world. `allow myapp_t unreserved_port_t:tcp_socket name_bind;` would open every TCP port in the system to every process in `myapp_t`. The kernel does not trust that kind of blanket trust, and neither should the operator.

The right answer, therefore, is not to widen a rule. The right answer is to label the port.

```text
avc:  denied  { name_bind } for  pid=1234 comm="python3" src=8888
  scontext=system_u:system_r:myapp_t:s0
  tcontext=system_u:object_r:unreserved_port_t:s0
  tclass=tcp_socket permissive=1
```

That AVC is the same tuple from the deterministic fixture under `docs/examples/fixtures/deterministic/02-port-bind/`. The generator classifies it as:

```json
{"verdict": "private_port", "tgt": "unreserved_port_t", "next_action": "add_manifest_port", "port": 8888}
```

The fix is not a rule. It is a port assignment.

## Named port types

SELinux ships with two kinds of port types. The first is `http_port_t` — the shared type for all HTTP traffic, used by `httpd_t` and many other services. The second is each application's private port type — `myapp_port_t`, `shopapi_port_t`, and so on.

A private port type is a declaration, written with the refpolicy macro `corenet_port` in `.te` and persisted to the running policy by `semanage`.

```text
type myapp_port_t;
corenet_port(myapp_port_t)
```

The macro teaches the policy the type. The host command teaches it the number.

```bash
$ semanage port -a -t myapp_port_t -p tcp 8888
$ semanage port -m -t myapp_port_t -p tcp 8889
$ semanage port -d -t myapp_port_t -p tcp 8889
$ semanage port -l | grep myapp_port_t
myapp_port_t                         tcp     8888
```

`-a` adds the number, `-m` mutates it, `-d` drops it. `-l` lists everything — a useful audit you run before every policy review.

## The port assignment lives in the manifest

The port number is not a decision the host makes. It is a decision the manifest makes, and the manifest decides twice: for the number, and for the type.

```yaml
selinux_ports:
  - port: 8888
    proto: tcp
    type: myapp_port_t
  - port: 8889
    proto: tcp
    type: myapp_backend_port_t
```

That YAML is the source of truth. Every port the application will touch — `http.port`, `http.backend.port`, any private endpoint — names a number, a protocol, and the private type it should carry. The same block appears in `config/shopapi.manifest.yml` for the live Spring Boot demo, where the port is 8091 and the type is `shopapi_port_t`.

The template that turns the manifest into policy is a single Jinja file, `ansible/roles/selinux_pac/templates/ports_from_manifest.cil.j2`:

```jinja
; Generated from app manifest selinux_ports (FCOS / hosts without semanage).
{% for item in selinux_ports_list %}
(portcon {{ item.proto | default('tcp') }} {{ item.port }} (system_u object_r {{ item.type }} ((s0) (s0))))
{% endfor %}
```

Each row in `selinux_ports` becomes one `portcon` line. The port assignment is compiled alongside the `.te`, reviewed alongside the `.te`, and shipped alongside the `.te`. If it were typed on the host, it would not share the same review. That is why the ports block is committed.

## Privileged ports

A port below 1024 is privileged. `net_bind_service` is a capability, and the process needs it.

```bash
$ getcap /opt/myapp/bin/python3
# or:
$ setcap cap_net_bind_service+eip /opt/myapp/bin/python3
```

The capability is a different decision from the label. A private port type lets you deny every other process on your box from calling your port; the capability lets every root on your box call it. That is why every service that does not need a privileged port should pick an unprivileged one.

`8888` and `8889` in the manifest are already unprivileged. `80` would not be. Name the port that way in the manifest before you name it as a type.

## Booleans

A boolean is a host-level flag that stands in for a rule. `setsebool -P myapp_t 1` turns the flag on permanently across reboots — `-P` is the difference between a hot fix and a policy decision.

Every boolean starts its life in `semanage boolean -l`, and the administrator reads them with `getsebool -a`. The command prints every boolean on the host, each line carrying a name, a human description, and the current state. Production inventory starts there.

```bash
$ getsebool -a | head
abrt_anon_write (off)  ->  off
httpd_can_network_connect_db (off)  ->  off
httpd_can_network_connect (off)  ->  off
…
```

The decision rule is simple. A boolean is right when the access is a policy choice the administrator owns. A boolean is wrong when it just hides a missing rule.

`httpd_can_network_connect` lets HTTP traffic leave the box. The operator agrees that this happens on every production host that runs the application — the boolean is a choice the operator makes, not a gap in the policy. The operator is responsible for the outbound HTTP. Toggle it.

The inverse is a boolean that lets a process reach a type it should not reach. That boolean is hiding a rule that should exist — and the operator is not responsible for the reach, because the rule did not make it reachable.

The deterministic generator consults the boolean before writing a rule. The curated overrides in `config/boolean_hints.yml` are applied first; then `cli/boolean_hints.py` queries the loaded targeted policy with `sesearch --allow --bool …`. Every match is listed sorted; none is auto-selected when several apply.

```yaml
# config/boolean_hints.yml — curated overrides consulted before policy query.
hints:
  - boolean: httpd_can_network_connect
    note: >-
      Site policy: prefer toggling this boolean over a permanent allow on
      http_port_t for outbound HTTP connects.
    match:
      tgt_type: http_port_t
      tclass: tcp_socket
      perms: [name_connect]
```

The `match` block is what the tool matches against: the target type, the class, the permissions. When the AVC carries those three values, the override wins before the query. When neither the override nor the query can run, generation refuses a silent direct allow. That is the same contract as Chapter 204 — the host command is the final answer, not the `.te`.

The two boolean fixtures report identical verdicts against `http_port_t` and `httpd_can_network_connect`.

```json
// docs/examples/fixtures/deterministic/04-boolean-network-connect/expected.json
{"verdict": "boolean", "tgt": "http_port_t", "boolean": "httpd_can_network_connect"}

// docs/examples/fixtures/deterministic/10-boolean-hint/expected.json
{"verdict": "boolean", "tgt": "http_port_t", "boolean": "httpd_can_network_connect"}
```

Both denials in the fixtures are `name_connect` against `http_port_t` from `myapp_t`. The override matches, the policy query matches, the verdict is `boolean`. The host command is `setsebool httpd_can_network_connect on` — and it is not a rule, it is a policy choice the operator takes.

## Transitions

An exec-time domain transition is the `type_transition` rule on `process`. It lets a process start under a new domain when it runs the right binary.

```text
type_transition init_t myapp_exec_t:process myapp_t;
```

Full detail lives in Chapter 11. For now, two facts:

- The transition owns the process domain once it is running. The new domain is the one that gets the AVC.
- The label on the entrypoint — `entrypoint` on `file` — is what triggers the transition. Without it, the kernel falls back to the binary's on-disk label, which is the default domain.

The port-related transition idea is the inverse: a socket that calls a port carries that port's type. A connect to `myapp_port_t` is a `name_connect` against a named type, not a generic one. That is why the private port type exists on the outbound side too — every direction of socket traffic carries the type of the port it touches.

On the MLS side, the two remaining fields of the label are `user` and `role`. `system_u` and `system_r` are the usual defaults for daemons; `user_u` and `user_r` are for interactive shells. The four-leaf clover — `user, role, type, sensitivity` — is what `ls -Z` shows. MLS is what controls cross-domain writes; MCS is what controls untrusted container workloads on shared hosts. Both are out of scope for Chapter 11 — every line about them here would be a promise I cannot keep without the full chapter.

## The four tokens

Each of these mechanisms sits somewhere different, carries a different review, and answers to a different owner.

| Mechanism | What it controls | Where it lives | Review impact |
|-----------|-----------------|----------------|---------------|
| Label (`type`) | every access to every object of that type | `.te`, compiled into the policy | adds a new type; every allow that names it is auditable |
| Port assignment (`portcon`) | which number each type carries on the host | manifest YAML + Ansible template, or `semanage` on the host | the number is the review; the type is the contract |
| Boolean | one flag on one host, one decision | `semanage boolean -l`; `-P` persists across reboot | the operator agrees; the flag is the audit |
| Transition | which domain a process becomes on exec | `type_transition init_t … :process …` in `.te` | the binary is the trigger; the domain is the consequence |

A label, a port assignment, a boolean, and a transition each answer a different question the kernel asks. The table is the difference between a hot fix and a policy decision.

:::: why Ports and booleans must not drift between environments
Both are one of the two things that must not drift between environments — which is why both are committed.

A port assignment typed on the host, remembered by a person, and unreviewed in the manifest, is one of the two things that drifts first. The host is rebuilt; the type is forgotten; the operator patches with `allow … unreserved_port_t`. The same failure is a boolean typed on the host, documented on a runbook, and unreviewed in `boolean_hints.yml`. The next operator turns it on or off without reading the override. Both are exactly the failure this chapter is trying to prevent.
::::

## Try

The two commands that do not change state on `rhel-qa`.

```bash
$ semanage port -l | head
$ getsebool -a | head
```

Then read the ports block in the manifest.

```bash
$ head -30 config/myapp.manifest.yml | grep -A 10 selinux_ports
```

Offline, against the deterministic generator with the real flags from `cli/deterministic_gen.py`. The invocation reads the file:

```bash
python3 cli/deterministic_gen.py --explain \
  --avc-log docs/examples/fixtures/deterministic/02-port-bind/avc.log \
  --manifest config/myapp.manifest.yml \
  --existing-te selinux/myapp.te \
  --existing-fc selinux/myapp.fc
```

Run it. The output for `02-port-bind` is the same `private_port` verdict you just read. Run it again for `04-boolean-network-connect` — you will see the same boolean verdict, same override, same `httpd_can_network_connect`. The generator does not choose the answer; it writes the same answer you would write.

## What you can do now

The four mechanisms are each one decision the kernel asks and each one decision the operator answers.

- **Labels** carry every access to every object of that type. You review them when you write the `.te`.
- **Port assignments** carry the number the type is allowed to reach on the host. You review them when you commit the manifest.
- **Booleans** carry one host-level flag, one policy choice. You review them when you commit the override.
- **Transitions** carry the exec-time domain. You review them when you write the rule.

Each of them is a decision you own. Each of them is a decision you can lose — unless it is committed.

Next chapter: Chapter 11 designs a domain, every decision it makes, and why the transition is the single most important rule in the module.
