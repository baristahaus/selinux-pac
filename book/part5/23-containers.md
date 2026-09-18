# Containers, Namespaces and MCS

> Every container you run lands inside a policy domain — `container_t` — and each one walks
> out of that domain with its own categories. Namespaces isolate memory, but SELinux isolates
> identity; this chapter is about the label that makes a second container a stranger to the
> first.

## Why a container changes the policy picture

A container is a set of Linux namespaces — PID, mount, network, UTS, IPC, user, cgroup — and
each namespace isolates one dimension of the process. Namespaces do not touch the SELinux
labels the kernel assigns to every process and file. Two containers on the same host still
share the same *domain* by default — they both run inside the generic container domain,
`container_t` — so by the host's policy they are the same thing. That would let one container
read every file the other touches, because `container_t` is the same type on every side of
every access check.

The fix is categories. Each container is issued a unique MCS category pair — `s0:c123,c456`
for the first, `s0:c234,c345` for the second, and so on. The *level* field of the label is
still `s0`, but the category list is what separates two processes that share a domain. Names
that fit neatly inside this chapter do not need a classified sensitivity field at all; what
the categories do is give every container a unique key the policy will read per tuple.

This is how RHEL ships the container domain by default. Every process that Podman,
systemd-nspawn or CRI-O starts carries the type field `container_t` and a level that is
unique to that container's run. The reference that names it is the RHEL Using SELinux
chapter on container policy — the `container_t` type is the default domain for every container
on the host, and `udica` can generate a custom policy for a container so it runs under its
own type instead of sharing `container_t` with every other container on the box
([Using SELinux, Chapter 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/using_selinux/creating-selinux-policies-for-containers_using-selinux)).

## Reading those labels

The whole picture is legible from the host's CLI. Two commands give you every field.

```bash title="Process labels on the host"
# ps -eZ | head -n 5
LABEL                               PID USER     COMMAND
system_u:system_r:system_r:s0-s0:c0.c1023     1 root   /usr/lib/systemd/systemd
system_u:system_r:container_runtime_t:s0-s0:c0.c1023  8812 root   podman run ...
unconfined_u:unconfined_r:unconfined_r:s0-s0:c0.c1023   8834 root   bash
```

The third field is still the type — that is the enforcement decision. The `s0:c123,c456`
level is the per-container key. Every `ps -eZ` line on a host running containers will carry
an `s0:c…` tail that is unique to that container's session; that is how the host tells them
apart.

The corresponding look for files — Chapter 3 covers this exactly — is:

```bash title="File labels on the host"
# ls -Z /var/lib/containers/storage | head -n 5
-rw-------. root root system_u:object_r:container_file_t:s0-s0:c0.c1023 storage.tar
```

Every file that Podman created inside its working directory also carries an `s0:c…` level,
because every file inside a container is issued the same category list as the container's
process. That is why the categories are the isolation: a file owned by container A and a
process owned by container B are locked each other out at the kernel decision, even when
both hold the same type field.

## Volume relabelling: `:z` versus `:Z`

Bind mounts reach the host file system. By default the SELinux label on the host path
walks straight into the container alongside the bytes — and that label is what the process
inside the container will actually have to ask about. If the host path is
`unconfined_u:object_r:home_root_t:s0` and the process inside is
`system_u:system_r:container_t:s0:c123,c456`, the policy will look at the two types and the
two levels and answer *no*.

Podman's `:z` and `:Z` options change that answer by rewriting the label on the host path.
The two flags do not mean the same thing, and they share a single documented purpose:
*to relabel the file objects on the mounted volume*
([podman-run, `--volume`](https://docs.podman.io/en/v5.0.1/markdown/podman-run.1.html)).

| Suffix | What it does | When it is wrong |
|---|---|---|
| **`:z`** | relabels every file under the host path with the container's category list, *for every container* that mounts it read-write | a path also used by a host service (the service will fail once its label is a container's) |
| **`:Z`** | relabels every file under the host path for *this one container only*, leaving the label on the path compatible with host use | a directory shared with a host service that was not told about the container |

The first row — `:z` — is the simplest cutover: the mount becomes readable by every
container that takes the same category list. The second row — `:Z` — is the one that
looks right for shared storage but breaks the shared host service the path also serves.
The `podman-run` reference warns explicitly about both: *do not relabel system files and
directories; relabeling system content might cause other confined services on the machine
to fail*.

The correct alternative when a path is already used by a host service is to label the path
with a dedicated type, run `restorecon`, then mount `host:/host:/containers_var_lib_t:z`
against the path you now control. The result is a relabel of something you own.

## Options that widen the boundary

There are three options Podman offers that widen the boundary, and each of them is a
decision worth writing down.

| Option | What it is for | Why it is a decision |
|---|---|---|
| `--security-opt label=type:<type_t>` | run the container under a *custom* process type (e.g. the module produced by `udica`) | the host's container domain no longer applies; an audit reads the new type and must decide whether that type's rules still hold |
| `--security-opt label=disable` | turn off label separation between containers (e.g. a sidecar that must share another container's files) | *both* containers share the same level; every file each container wrote is visible to every other container on the same host |
| `--privileged` | full root-equivalent capabilities inside the container | the process inside the container is also `unconfined_t` on the host's policy — every check the chapter is about goes away |

Each is the deliberate answer to a real question — a sidecar needs to reach a file,
or an operator needs to mount `/dev` — and each is the answer to *which* check goes away.
They are not mistakes; they are the kind of decision a review should record.

The Podman reference for each is the same `--security-opt` page:
`label=type:TYPE` sets the process type, `label=level:LEVEL` sets the level,
and `label=disable` turns off label separation
([podman-run `--security-opt`](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)).

:::: warn Turn-off decisions stay in the log
`label=disable` and `--privileged` turn off the confinement this chapter is about.
Record the reason in the change ticket, the runbook and the inventory. An audit reading
the ticket later should be able to point at the row that says *why the key was removed*.
::::

## Kubernetes and CRI-O

Kubernetes reaches the container runtime with a `securityContext` block on each Pod.
The field that carries SELinux is `seLinuxOptions`, and it carries two values: the *type*
and the *level*. The runtime — CRI-O on RHEL-based distributions, containerd on the rest —
receives those values and passes them to the kernel when it starts each container.

| Field | What it controls | Where it lives |
|---|---|---|
| `spec.securityContext.seLinuxOptions.type` | the process type for every container in the Pod | `securityContext` on the Pod |
| `spec.securityContext.seLinuxOptions.level` | the category list for every container in the Pod | `securityContext` on the Pod |

The Kubernetes documentation notes that on the *Restricted* Pod Security Standard, setting
`spec.securityContext.seLinuxOptions.type` is the restricted field — only the platform
operator may pick the type for a workload; users supply the level. That means the *type*
is almost always the platform's `container_t`, and the *level* is the per-Pod category
([Configure a Security Context, Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context)).

The runtime's default is usually the right answer: every container on the node receives a
unique level from the scheduler, each Pod's namespace is still a stranger to every other
Pod on the node, even when all Pods share the same type.

## The consequence for policy authoring

A service in a container is not covered by the host's application module. The host module
names types like `shopapi_t` and paths like `shopapi_var_lib_t`; those types apply only
to the `shopapi_t` process running under systemd on the host. A `container_t` process
does not inherit that allow chain — every request it makes against a host file is answered
by the generic container policy.

That is the shape of "policy as code" for containers: policy for the runtime — the
`container_t` allows that ship with every container image — plus, where a container needs
something specific, a custom type for the container image. `udica` reads the image's
metadata and writes that custom type's allow chain, and the container then runs under the
new type rather than `container_t`. The operator owns the new type's review, just as they
own the host application's review.

Chapter 1 showed the outage: *a container on the build host masks a denial on the build
host*; *because the container hides it, staging is permissive*. That is the same trap
revisited on the container path. On the build host the container runs as `container_t` and
every request it makes against host paths is covered by the generic container policy — the
path change that breaks the systemd unit on production is still a path change against a
directory the generic policy covers. The confinement that actually applies is the one on
the host where the production service runs as `shopapi_t` — and that domain's policy never
saw the new path. The point is plain: *a container masks a denial only when you read that
denial as the production denial*. The production host is still Enforcing, and the production
host's domain is still the one that decides.

## A table of mechanisms

| Mechanism | What it isolates | What it costs | When to use it |
|---|---|---|---|
| `container_t` | the runtime's default domain for every container on the host | every container shares the same type — only categories separate them | default; accept it as long as the per-container level is unique |
| MCS categories (`s0:c123,c456`) | each container's files and processes as a stranger to every other container on the host | each container takes a per-run category list that the policy has to know about | every container on every host, automatically |
| `:z` on a bind mount | every file under the host path is readable by every container that shares the category list | the host path's label is rewritten for all containers; a host service that also uses the path will inherit the new label | a directory used by only one workload |
| `:Z` on a bind mount | the host path is readable by *this one* container only, leaving the host service's label alone | the host path's label is rewritten for only this container; if the path is shared between containers the second one will fail | a directory shared with a host service, with a single workload consuming it |
| `--security-opt label=type:<type_t>` | a custom process type that bypasses the generic `container_t` policy | you now own the allow chain for that type; every access the type makes is your audit | a container with a need to reach a specific type — usually via `udica` |
| `--security-opt label=disable` | both containers share the same level — each can read the other's files | every file each container wrote is visible to every other container on the host | a sidecar pattern that must share another container's file tree |
| `--privileged` | full root-equivalent capabilities inside the container, and the host policy sees `unconfined_t` | every check the chapter is about goes away | an operator need that no less-powerful option satisfies |
| `seLinuxOptions.type` | the process type for each Pod on the cluster — usually `container_t` | the platform picks the type; only the operator can supply one for a workload | every Pod, by default; supply one only when you own the allow chain |
| `seLinuxOptions.level` | the category list for each Pod on the cluster — the scheduler picks each | each Pod's level is unique — each Pod's files are a stranger to every other Pod | every Pod; accept the default unless you need a cross-Pod share |

## What you can do now

- **Read** a running container's label on any RHEL host with `ps -eZ | grep container` and
  recognise the `s0:c…` level as the per-run key.
- **Decide** whether `:z` or `:Z` wins for a bind mount by checking whether the host path
  is also used by a host service — and `:Z` is wrong for shared storage.
- **Record** each use of `--security-opt label=disable`, `--security-opt label=type:...`
  and `--privileged` as a row in the inventory with the reason, not a footnote.
- **Audit** a Kubernetes Pod's `seLinuxOptions` and confirm that every Pod on every node
  carries a unique level — that is the isolation that names the platform's default.
- **Review** the container policy you are shipping against: it is the host module, plus a
  custom type for the container image, plus a decision about `container_t` or not.

:::: try On a RHEL host with Podman
Nothing changes state; you only set the vocabulary.

```bash title="Inspect a running container's label"
# ps -eZ | grep container
system_u:system_r:container_t:s0:c230,c456   1 root   /usr/bin/conmon ...
system_u:system_r:container_runtime_t:s0:c230,c456 8812 root   podman ...
```

```bash title="Compare :z versus :Z on a bind mount"
# ls -Z /tmp/shared          # before mount: your host's label
# podman run --volume /tmp/shared:/data:Z alpine ls -Z /data
# ls -Z /tmp/shared          # after :Z mount: you see the new label
```

The `:Z` line shows the file's label rewritten *only* for this container.
The same sequence with `:z` would show it rewritten for every container that shares the level.
::::

1. **Run** the `ps -eZ` command above on your lab host — it is one of the five verify steps
   in `lab.md`, and the label you see there is the same picture this chapter is about.
2. **Pick** one bind mount in your current project that uses `:z` and confirm that no host
   service also uses the path — if one does, that mount is the row that earns a review.
3. **Tell** the person adding a `--privileged` line to the run command what is going away,
   so the next read can tell you why it stayed.
